import CryptoKit
import Foundation
import MachO
import os
import System

private let logger = Logger(subsystem: "fashion", category: "cdhash")

enum CDHashError: MalformedInput, Equatable {
    case invalidCodeSignatureRange(offset: UInt32, size: UInt32, fileSize: Int)
    case truncatedCodeSignatureSuperblob(signatureSize: Int)
    case invalidCodeSignatureMagic(magic: UInt32)
    case invalidCodeSignatureSuperblobLength(length: UInt32, signatureSize: Int)
    case codeSignatureTooLarge(length: UInt32, limit: Int)
    case invalidCodeSignatureIndexTable(count: UInt32, length: UInt32)
    case invalidCodeSignatureBlobOffset(offset: UInt32, signatureSize: Int)
    case invalidCodeSignatureBlobRange(offset: UInt32, size: UInt32, signatureSize: Int)
    case codeDirectoryTooLarge(length: Int)
    case duplicateCodeDirectory(hashType: String)
}

extension CDHashError: LocalizedError {
    var errorDescription: String? {
        switch self {
        case let .invalidCodeSignatureRange(offset, size, fileSize):
            "Invalid Mach-O: code signature range at offset \(offset.hex) with size \(size.hex) is outside the \(fileSize.hex)-byte slice"
        case let .truncatedCodeSignatureSuperblob(signatureSize):
            "Invalid Mach-O: code signature is only \(String(signatureSize, pluralizing: "byte")); an embedded signature header requires 12"
        case let .invalidCodeSignatureMagic(magic):
            "Invalid Mach-O: code signature has invalid magic \(String(format: "0x%08x", magic))"
        case let .invalidCodeSignatureSuperblobLength(length, signatureSize):
            "Invalid Mach-O: code signature declares a \(length)-byte superblob inside a \(signatureSize)-byte signature"
        case let .codeSignatureTooLarge(length, limit):
            "Mach-O too large: its code signature declares a \(length)-byte superblob, more than \(limit)"
        case let .invalidCodeSignatureIndexTable(count, length):
            "Invalid Mach-O: code signature index count \(count) does not fit in the \(length)-byte superblob"
        case let .invalidCodeSignatureBlobOffset(offset, signatureSize):
            "Invalid Mach-O: code signature blob offset \(offset.hex) is outside the \(signatureSize.hex)-byte superblob"
        case let .invalidCodeSignatureBlobRange(offset, size, signatureSize):
            "Invalid Mach-O: code signature blob at offset \(offset.hex) with size \(size.hex) is outside the \(signatureSize.hex)-byte superblob"
        case let .codeDirectoryTooLarge(length):
            "Mach-O too large: its \(length)-byte ad-hoc CodeDirectory would overflow the 32-bit length field"
        case let .duplicateCodeDirectory(hashType):
            "Invalid Mach-O: two \(hashType) code directories, which Security refuses as an invalid signature"
        }
    }
}

/**
 Compute CDHash (Code Directory Hash) for each slice of a Mach-O binary.

 A signed slice yields its embedded cdhash(es).

 An unsigned slice yields a synthesized ad-hoc cdhash: the identity `syspolicyd` computes for unsigned code,
 byte-for-byte equal to `codesign --detached -s - --identifier ADHOC`.

 The per-slice computation lives on `MachO` below; this enum opens the binary and attaches architecture names.
 */
enum CDHash {
    struct SliceResult {
        let hash: String
        let arch: String?
        /// Hash type name, only set when a slice carries several code directories.
        let type: String?
        /// True when the slice is unsigned and the hash was synthesized.
        let adhoc: Bool
        /// True when the slice's signature does not hold as Security's static validation holds it: a code directory
        /// it cannot load, so the hash is synthesized; code that no longer hashes to this directory; or, judged by
        /// the best directory for every one of them, a sealed blob missing or changed, a code limit that is not
        /// the signature's offset, a CMS signature missing or not verifying (`MachO.securityTakes`).
        let invalid: Bool
    }

    /**
     Compute CDHash for each Mach-O slice in a file.

     Thin binaries return a single result with nil arch.
     Fat binaries return one result per slice.

     With `exact`, an unsigned slice is trimmed to its logical extent before synthesis,
     so appended trailing garbage does not change its ad-hoc cdhash.

     Each embedded code directory is checked against the code it signs, which reads the slice once, no further than the
     first slot that fails.
     */
    static func hash(_ file: File, path: String, exact: Bool = false) throws -> [SliceResult] {
        switch try Universal.open(file) {
        case let .fat(table):
            try table.flatMap { arch -> [SliceResult] in
                let name = arch.name
                // A slice that is not a thin Mach-O, typically the `ar` archive of a universal static library, has no code directory.
                guard let image = try MachO(file, offset: arch.offset, length: arch.length) else {
                    self.logSkip(path: path, arch: name, reason: "slice is not a Mach-O file")
                    return []
                }
                return try self.results(for: image, arch: name, path: path, exact: exact)
            }
        case let .thin(image):
            try self.results(for: image, arch: nil, path: path, exact: exact)
        case .notMachO:
            []
        }
    }

    // MARK: - Private

    /**
     One SliceResult per code directory. The hash type is only set when a slice carries several directories.
     */
    private static func results(for slice: MachO, arch: String?, path: String, exact: Bool) throws -> [SliceResult] {
        let hashed = try slice.codeDirectoryHashes(exact: exact)
        let directories = hashed.hashes
        if let skipReason = hashed.skipReason {
            self.logSkip(path: path, arch: arch, reason: skipReason)
        }
        let ambiguous = directories.count > 1

        return directories.map { cd in
            SliceResult(hash: cd.hash, arch: arch, type: ambiguous ? cd.type : nil, adhoc: cd.adhoc, invalid: cd.invalid)
        }
    }

    private static func logSkip(path: String, arch: String?, reason: String) {
        logger.info("No cdhash for \(path, privacy: .public)\(arch.map { " (\($0))" } ?? "", privacy: .public): \(reason, privacy: .public)")
    }
}

// MARK: - Per-slice code directory logic

extension MachO {
    /**
     A single code directory digest of a slice.
     */
    struct CodeDirectoryHash {
        let hash: String
        /// The hash type's name (see `HashType`): `sha256` for a synthesized ad-hoc directory.
        let type: String
        let adhoc: Bool
        /// See `CDHash.SliceResult.invalid`.
        let invalid: Bool
    }

    /**
     The slice's cdhashes, or the reason it has none (`skipReason` is set exactly when `hashes` is empty).

     A slice whose filetype `codesign` takes for a generic file rather than code (`MachORep::candidate`) has none,
     signed or not: `codesign -d` calls such a file "not signed at all" whatever its `LC_CODE_SIGNATURE` holds.

     A signed slice yields every code directory Security loads from its signature, strongest first per `HashType.rank`: the
     head is the kernel-enforced cdhash. Each of them is checked against the code (`validateExecutables`).

     An unsigned slice yields its synthesized ad-hoc cdhash, the SHA-256 one `syspolicyd` looks up. So does a signed
     slice whose code directories Security rejects, marked invalid: `codesign` calls it "not signed at all" and signs it
     up to where its signature starts, the code limit of `MachORep::signingLimit`. A signature Security cannot read at
     all is an error, as `codesign` cannot sign over it.

     A slice of a universal file is judged on its own, as if extracted: `codesign` instead decides a whole 32-bit
     universal file from its first slice, and treats a 64-bit one (`lipo -fat64`) as a generic file outright.
     */
    func codeDirectoryHashes(exact: Bool) throws -> CodeDirectoryHashes {
        guard Self.codeFiletypes.contains(self.filetype) else {
            return CodeDirectoryHashes(hashes: [], skipReason: "\(self.filetypeName) is not code to codesign")
        }

        let signature = try self.findCodeSignature()
        if let signature {
            let superblob = try self.signingData(signature)
            let loaded = try Self.loadCodeDirectories(superblob)
            let directories = loaded.sorted { $0.hashType.rank > $1.hashType.rank }
            let taken = Self.securityTakes(directories, primary: loaded.first, in: superblob, signature: signature)
            let hashes = try zip(directories, self.validateExecutables(directories)).map { cd, verdict in
                CodeDirectoryHash(hash: cd.hashType.digest(cd.data).hexString, type: cd.hashType.name, adhoc: false, invalid: !verdict.valid || !taken)
            }
            if !hashes.isEmpty {
                return CodeDirectoryHashes(hashes: hashes, skipReason: nil)
            }
        }

        return try CodeDirectoryHashes(hashes: self.adhocCDHashes(codeLimit: signature?.offset ?? (exact ? self.logicalEnd() : self.length), invalid: signature != nil), skipReason: nil)
    }

    /// The cdhashes of a slice, and why there are none, when there are none: a file type codesign does not sign.
    struct CodeDirectoryHashes {
        let hashes: [CodeDirectoryHash]
        let skipReason: String?
    }

    // MARK: - Embedded signature

    /**
     The most bytes a superblob may declare (64 MiB), a limit of this tool's, as `MachO.maxLoadCommandsSize` is:
     Security reads what the length says, the kernel maps what `LC_CODE_SIGNATURE` says, and the largest signatures
     the toolchain writes are a few megabytes, two directories of a 4 GiB `x86_64` slice adding up to 52 MiB, where a
     crafted length over a sparse file would be read whole.
     */
    static let maxSignatureSize = 64 << 20

    /**
     The superblob `LC_CODE_SIGNATURE` points at, read like `MachORep::signingData`: `BlobCore::readBlob` requires its
     magic and, unless the command's size is zero, a length within that size; then `EmbeddedSignatureBlob::specific`
     requires every blob it indexes to lie inside it. fashion also requires the length to fit the slice, where
     `codesign -d` reads on into the next slice of a universal file. Throws otherwise. `MachOVerifier` reads it too.

     The superblob, big-endian throughout, where `LC_CODE_SIGNATURE`'s `dataoff` points in `__LINKEDIT`:

     ```text
      +0x00 +-----------------------------------------------+
            | SuperBlob (12): magic 0xfade0cc0 | length |   |  `count` index entries follow
            |                 count                         |
      +0x0c +-----------------------------------------------+
            | index: count × { type (4) | offset (4) }      |  the slot and where its blob lies in the superblob
            +-----------------------------------------------+
            | slot 0: CodeDirectory 0xfade0c02              |  see `EmbeddedCodeDirectory`
            | slot 2: Requirements 0xfade0c01 (a set)       |  each sealed by its special slot in the directory
            | slot 5: Entitlements 0xfade7171 (XML plist)   |
            | slot 7: DER entitlements 0xfade7172           |
            | slots 0x1000…: alternate code directories     |  one per hash type, SHA-256 beside SHA-1
            | slot 0x10000: BlobWrapper 0xfade0b01, the CMS |  signed over the directory at slot 0, detached;
            |   signature                                   |  the 8-byte header alone when ad hoc
            +-----------------------------------------------+
     ```
     */
    func signingData(_ signature: Span) throws -> Data {
        let (offset, size) = (signature.offset, signature.size)
        guard offset <= self.length - 8 else {
            throw CDHashError.invalidCodeSignatureRange(offset: UInt32(offset), size: UInt32(size), fileSize: self.length)
        }

        // One read serves the header and, for most signatures, the whole superblob.
        let probe = try self.dataAt(offset, count: min(self.length - offset, 16384))
        let (magic, length) = (probe.bigEndianUInt32(at: 0), probe.bigEndianUInt32(at: 4))
        guard magic == Self.csmagicEmbeddedSignature else {
            throw CDHashError.invalidCodeSignatureMagic(magic: magic)
        }
        guard length >= 12 else {
            throw CDHashError.truncatedCodeSignatureSuperblob(signatureSize: Int(length))
        }
        guard
            size == 0 || Int(length) <= size,
            Int(length) <= self.length - offset
        else {
            throw CDHashError.invalidCodeSignatureSuperblobLength(length: length, signatureSize: size)
        }
        guard Int(length) <= Self.maxSignatureSize else {
            throw CDHashError.codeSignatureTooLarge(length: length, limit: Self.maxSignatureSize)
        }

        let superblob = Int(length) <= probe.count ? probe.prefix(Int(length)) : try self.dataAt(offset, count: Int(length))
        try Self.checkIndex(of: superblob)
        return superblob
    }

    /**
     `EmbeddedSignatureBlob::specific`'s check of a superblob's index, `superblob` being its magic and length's worth
     of bytes: the index fits, and every blob it points at lies inside, header included. Throws otherwise. The fuzzer's
     `signer` harness makes the same check of its input.
     */
    static func checkIndex(of superblob: Data) throws {
        let length = UInt32(superblob.count)
        let count = superblob.bigEndianUInt32(at: 8)
        let indexEnd = 12 + 8 * Int(count)
        guard indexEnd <= superblob.count else {
            throw CDHashError.invalidCodeSignatureIndexTable(count: count, length: length)
        }

        for entry in 0 ..< Int(count) {
            let blobOffset = superblob.bigEndianUInt32(at: 12 + 8 * entry + 4)
            guard blobOffset != 0 else {
                continue
            }
            guard
                Int(blobOffset) >= indexEnd,
                Int(blobOffset) <= superblob.count - 8
            else {
                throw CDHashError.invalidCodeSignatureBlobOffset(offset: blobOffset, signatureSize: superblob.count)
            }

            let blobLength = superblob.bigEndianUInt32(at: Int(blobOffset) + 4)
            guard
                blobLength >= 8,
                Int(blobLength) <= superblob.count - Int(blobOffset)
            else {
                throw CDHashError.invalidCodeSignatureBlobRange(offset: blobOffset, size: blobLength, signatureSize: superblob.count)
            }
        }
    }

    /**
     Whether Security's static validation takes the signature, beyond its code slots
     (`SecStaticCode::staticValidateCore`). Security judges a signature by one directory, the best: the first of
     `directories`. It never reads an alternate's own seals or limit.

     The signature slot. The blob there must lie under a wrapper, whatever the directory's flags
     (`EmbeddedSignatureBlob::component`): another magic is an invalid signature. When the directory is not flagged
     ad hoc, the CMS blob under the wrapper must verify over `primary` and bind every directory
     (`verifySignature`). When it is, the blob is not read. Whose chain the signer's is, trustd's work, is
     verify's business, not hash mode's.

     The code limit. Strict validation, codesign's and Gatekeeper's default, wants it at the signature's offset
     exactly (`SingleDiskRep::strictValidate`, "code limit must cover (exactly) the entire file").

     The special slots. Security visits the slots the directory has, up to slot 11
     (`validateNonResourceComponents`). A sealed slot, one whose hash is not all zeros, wants its blob there and
     hashing to it (`component`). An unsealed slot's blob is not read.

     ```
     slot   what it seals                       hashed over                   judged here
     -----  ----------------------------------  ----------------------------  -----------
     1      the Info.plist                      a file of the bundle          no
     2      the requirements                    the whole blob                yes
     3      the resource directory              a file of the bundle          no
     4      the top directory                   the bytes under its wrapper   yes
     5      the entitlements                    the whole blob                yes
     6      what the file's kind keeps there    the bytes under its wrapper   yes
     7      the DER entitlements                the whole blob                yes
     8-11   the launch and library constraints  the whole blob                yes
     ```

     A blob hashed under its wrapper must have one: without it, the signature is invalid. Slots 1 and 3 are left
     out because they need more than the slice: for an executable in a bundle, slot 1 seals the bundle's
     Info.plist. The list of slots a top directory holds is left out too: Security compares it once slot 4 itself
     holds.
     */
    private static func securityTakes(_ directories: [EmbeddedCodeDirectory], primary: EmbeddedCodeDirectory?, in superblob: Data, signature: Span) -> Bool {
        guard let best = directories.first, let primary else {
            return true
        }

        let wrapped = self.component(self.csslotSignature, of: superblob)
        if let wrapped, wrapped.bigEndianUInt32(at: 0) != self.csmagicBlobWrapper {
            return false
        }
        if best.flags & self.csAdhoc == 0 {
            guard
                let wrapped, wrapped.count > 8,
                (try? Signer(cms: Data(wrapped.dropFirst(8)), over: primary.data, binding: directories.map { Signer.Binding(hashType: $0.hashType, cdhash: $0.hashType.digest($0.data)) }, best: best.hashType, evaluatingChain: false)) != nil
            else {
                return false
            }
        }

        guard best.codeLimit == UInt64(signature.offset) else {
            return false
        }

        // Security fetches the top directory's blob whatever slots the directory has, and wants it wrapped.
        if case .unwrapped = self.sealable(self.csslotTopDirectory, in: superblob) {
            return false
        }

        // The slots the directory has: none for the linker's own ad hoc signature.
        return (1 ... self.csslotMax).prefix(best.nSpecialSlots).allSatisfy { slot in
            guard !self.csslotsLeftOut.contains(slot), let hash = best.specialSlot(Int(slot)) else {
                return true
            }
            switch self.sealable(slot, in: superblob) {
            case .unwrapped:
                return false
            case .none:
                return !hash.contains { $0 != 0 }
            case let .bytes(sealed):
                // Unsealed: nothing for Security to check.
                return !hash.contains { $0 != 0 } || best.hashType.digest(sealed).prefix(best.hashType.slotSize) == hash
            }
        }
    }

    /// What a special slot seals of the blob the superblob holds for it.
    private enum Sealable {
        /// No blob there.
        case none
        /// The bytes the slot's hash is taken over.
        case bytes(Data)
        /// A blob that should lie under a wrapper and does not, which Security refuses the signature for.
        case unwrapped
    }

    /// The bytes special slot `slot` seals in `superblob`, like `EmbeddedSignatureBlob::component`: the whole blob
    /// for a slot whose component is a blob of its own (`cdComponentIsBlob`), what lies under its wrapper for any
    /// other.
    private static func sealable(_ slot: UInt32, in superblob: Data) -> Sealable {
        guard let blob = self.component(slot, of: superblob) else {
            return .none
        }
        if self.csslotsOfBlobs.contains(slot) {
            return .bytes(blob)
        }
        return blob.bigEndianUInt32(at: 0) == self.csmagicBlobWrapper ? .bytes(Data(blob.dropFirst(8))) : .unwrapped
    }

    /**
     The code directories Security loads (`SecStaticCode::loadCodeDirectories`): the primary slot's, then the
     alternates' from 0x1000 up to the first one missing. Empty, so that the slice counts as unsigned, when the primary
     is missing or when any of them fails the checks of `EmbeddedCodeDirectory`. Throws for two of one hash type, which
     Security refuses as an invalid signature (`errSecCSSignatureInvalid`), where codesign says "invalid or
     unsupported format for signature".
     */
    static func loadCodeDirectories(_ superblob: Data) throws -> [EmbeddedCodeDirectory] {
        var directories: [EmbeddedCodeDirectory] = []
        for slot in [self.csslotCodeDirectory] + Array(self.csslotAlternateBase ..< self.csslotAlternateLimit) {
            guard let blob = self.component(slot, of: superblob) else {
                break
            }
            guard let directory = EmbeddedCodeDirectory(blob) else {
                return []
            }
            guard !directories.contains(where: { $0.hashType == directory.hashType }) else {
                throw CDHashError.duplicateCodeDirectory(hashType: directory.hashType.name)
            }
            directories.append(directory)
        }

        return directories
    }

    /**
     The blob a superblob holds in `slot`, like `SuperBlob::find`: the first index entry of that type, nil when there is
     none or its offset is zero. `signingData` has checked that the blob lies inside the superblob.
     */
    static func component(_ slot: UInt32, of superblob: Data) -> Data? {
        for entry in 0 ..< Int(superblob.bigEndianUInt32(at: 8)) where superblob.bigEndianUInt32(at: 12 + 8 * entry) == slot {
            let offset = Int(superblob.bigEndianUInt32(at: 12 + 8 * entry + 4))
            return offset == 0 ? nil : superblob.bytes(in: offset ..< offset + Int(superblob.bigEndianUInt32(at: offset + 4)))
        }
        return nil
    }

    /**
     Whether the code still hashes to each directory's code slots, like `SecStaticCode::validateExecutable`: the pages
     are cut by one directory's code limit and page size, the one of the lowest hash type, first in the map Security
     keeps them in, and every directory's slot at each page's index must be that page's hash, a directory with fewer
     slots failing at the first it lacks; the other directories' own limits and page sizes do not enter into it.
     False when a byte of code changed since signing, which `codesign --verify` reports as "code or signature have
     been modified", or when the slice ends before the code limit. The slice streams once for all the directories,
     each page through each directory's hasher as it arrives, however large the pages, and no further than the last
     slot still to check. A scattered directory's slots are checked in order like any other's: Security reads no
     scatter vector here.
     */
    func validateExecutables(_ directories: [EmbeddedCodeDirectory]) throws -> [Verdict] {
        guard let geometry = Self.geometry(of: directories) else {
            return []
        }
        var validators = directories.map { SlotValidator($0, geometry: geometry, length: self.length) }
        let limit = validators.filter(\.checking).map(\.limit).max() ?? 0
        do {
            try self.stream(0 ..< limit) { chunk in
                for index in validators.indices {
                    validators[index].update(chunk)
                }
                guard validators.contains(where: \.checking) else {
                    throw SlotValidator.Done()
                }
            }
        } catch is SlotValidator.Done {}
        return validators.map { Verdict(valid: $0.valid, failedSlot: $0.failedSlot) }
    }

    /// Whether a code directory's slots hash the code they seal, and the first slot that does not, if any.
    struct Verdict {
        let valid: Bool
        let failedSlot: Int?
    }

    /// The directory whose code limit and page size Security cuts every directory's pages by: the one of the lowest
    /// hash type, the first in the map `SecStaticCode` keeps them in (`validateExecutableSlots`).
    static func geometry(of directories: [EmbeddedCodeDirectory]) -> EmbeddedCodeDirectory? {
        directories.min { $0.hashType.rawValue < $1.hashType.rawValue }
    }

    // MARK: - Ad-hoc synthesis

    /**
     The ad-hoc cdhash of an unsigned slice whose code ends at `codeLimit`: the digest of the directory
     `codesign --detached -s - --identifier ADHOC` builds, byte for byte, the one `syspolicyd` looks up a ticket for.
     One directory per hash type of `hashTypes`, as `Signer::signMachO` builds them: SHA-256 alone, as `codesign -s -`
     and `syspolicyd` sign; the tests ask for SHA-1, truncated SHA-256 and SHA-384 beside it, every digest Security
     signs with: it refuses SHA-512, which it only reads.
     Throws where Security fails to sign: for a version or segment command it cannot read, or a directory too large.
     `invalid` when it stands in for a signature Security rejects.
     */
    func adhocCDHashes(codeLimit: Int, invalid: Bool, hashTypes: [HashType] = [.sha256]) throws -> [CodeDirectoryHash] {
        // Security's Signer::populate: fill a CodeDirectory::Builder with what MachORep reports.
        let execSeg = try self.execSeg()
        let builder = try CodeDirectoryBuilder(
            codeLimit: codeLimit,
            pageSizeLog: self.pageSizeLog(),
            execSegBase: execSeg.base,
            execSegLimit: execSeg.limit,
            execSegFlags: self.filetype == UInt32(MH_EXECUTE) ? 1 : 0, // CS_EXECSEG_MAIN_BINARY
            hashTypes: hashTypes,
            specialSlots: [1: self.infoPlistDigests(hashTypes), 2: CodeDirectoryBuilder.digests(of: Self.emptyRequirementsBlob, hashTypes)].compactMapValues { $0 }, // cdInfoSlot, cdRequirementsSlot
        )

        return try builder.build(code: self).map { built in
            CodeDirectoryHash(hash: built.hashType.digest(built.directory).hexString, type: built.hashType.name, adhoc: true, invalid: invalid)
        }
    }

    /**
     Stream the first `limit` bytes of the image through `body` a page at a time, the last page shorter: what each code
     slot hashes. A page cut by the end of a chunk waits for the rest of it.
     */
    fileprivate func forEachPage(upTo limit: Int, pageSize: Int, _ body: (UnsafeRawBufferPointer) -> Void) throws {
        var partial = Data()
        try self.stream(0 ..< limit) { chunk in
            var chunk = chunk
            if !partial.isEmpty {
                let fill = min(pageSize - partial.count, chunk.count)
                partial.append(contentsOf: chunk.prefix(fill))
                chunk = UnsafeRawBufferPointer(rebasing: chunk.dropFirst(fill))
                guard partial.count == pageSize else {
                    return
                }
                partial.withUnsafeBytes(body)
                partial.removeAll(keepingCapacity: true)
            }
            while chunk.count >= pageSize {
                body(UnsafeRawBufferPointer(rebasing: chunk.prefix(pageSize)))
                chunk = UnsafeRawBufferPointer(rebasing: chunk.dropFirst(pageSize))
            }
            partial.append(contentsOf: chunk)
        }
        // The last page, shorter than the others.
        if !partial.isEmpty {
            partial.withUnsafeBytes(body)
        }
    }

    /**
     log2 of the page size `codesign` signs with, like `MachORep::pageSize`: 16 KiB for the arm64 family, except
     4 KiB on tvOS, iOS before 16 and watchOS before 9 (the declared minimum OS, not the SDK); 4 KiB for every other
     architecture. The page the kernel maps the image on too, which `MachOVerifier` holds the segments to.
     */
    func pageSizeLog() throws -> UInt8 {
        guard [CPU_TYPE_ARM64, CPU_TYPE_ARM64_32].contains(self.cpuType) else {
            return 12
        }

        let version = try self.version()
        let minOS = version?.minOS ?? 0
        return switch version?.platform {
        case PLATFORM_TVOS: 12
        case PLATFORM_IOS: minOS < 0x0010_0000 ? 12 : 14
        case PLATFORM_WATCHOS: minOS < 0x0009_0000 ? 12 : 14
        default: 14
        }
    }

    /**
     The `__TEXT` file range `codesign` records as execSeg base and limit, like `MachORep::execSegBase` /
     `execSegLimit`: zero unless the slice declares a platform.

     The range is read as the file stores it, without byte-swapping, so a big-endian slice (ppc, ppc64) gets it
     byte-reversed: a 0x1000-byte ppc `__TEXT` is recorded as 0x100000. The ad-hoc identity carries that quirk too.
     */
    private func execSeg() throws -> ExecSeg {
        guard
            try (self.version()?.platform ?? 0) != 0,
            let text = try self.findSegment("__TEXT")
        else {
            return ExecSeg(base: 0, limit: 0)
        }

        // Security reads the 64-bit fields of a 64-bit image's segment command whatever the command's kind: of a
        // 56-byte LC_SEGMENT, the bytes its protections and section count hold, which `findSegment` has required.
        if self.is64 {
            return text.data.withUnsafeBytes { ExecSeg(base: $0.loadUnaligned(fromByteOffset: 40, as: UInt64.self), limit: $0.loadUnaligned(fromByteOffset: 48, as: UInt64.self)) }
        }

        return text.payload(as: segment_command.self).map { ExecSeg(base: UInt64($0.fileoff), limit: UInt64($0.filesize)) } ?? ExecSeg(base: 0, limit: 0)
    }

    /// The executable segment as a code directory records it, `__TEXT`'s file offset and size, read as the file
    /// stores them (`execSeg()`).
    private struct ExecSeg {
        let base: UInt64
        let limit: UInt64
    }

    /**
     The Info.plist embedded in `__TEXT,__info_plist`, like `MachORep::infoPlist`, digested under each of
     `hashTypes` as it streams by, whatever it holds, or nil. As in `MachOBase::findSection`, a segment
     command too short for the section table it declares holds no section. `MachORep::infoPlist` catches a failed
     `MachO::dataAt`, so a section `codesign` cannot read is no Info.plist either: one past the slice's end, or one
     larger than the 2 GiB a single read(2) takes (`nbyte > INT_MAX` is EINVAL). On a big-endian slice (ppc, ppc64)
     `codesign` bounds the section table with the unswapped section count, so it never finds the section.
     */
    private func infoPlistDigests(_ hashTypes: [HashType]) throws -> [HashType: Data]? {
        guard
            !self.swap,
            let text = try self.findSegment("__TEXT")
        else {
            return nil
        }

        // A segment command of the other ABI, shorter than the image's structure, declares no section table this
        // reads; Security reads a count past it, from the bytes of the next command.
        let (headerSize, sectionSize) = self.is64
            ? (MemoryLayout<segment_command_64>.size, MemoryLayout<section_64>.size)
            : (MemoryLayout<segment_command>.size, MemoryLayout<section>.size)
        guard text.data.count >= headerSize else {
            return nil
        }
        let count = try self.is64 ? text.load(segment_command_64.self).nsects : text.load(segment_command.self).nsects
        guard headerSize + Int(count) * sectionSize <= text.data.count else {
            return nil
        }

        for index in 0 ..< Int(count) {
            let at = headerSize + index * sectionSize
            guard Self.field(text.data.dropFirst(at).prefix(16), is: "__info_plist") else {
                continue
            }

            let (offset, size): (UInt64, UInt64) = text.data.withUnsafeBytes { raw in
                if self.is64 {
                    let entry = raw.loadUnaligned(fromByteOffset: at, as: section_64.self)
                    return (UInt64(entry.offset), entry.size)
                }
                let entry = raw.loadUnaligned(fromByteOffset: at, as: section.self)
                return (UInt64(entry.offset), UInt64(entry.size))
            }
            guard
                offset <= UInt64(self.length),
                size <= UInt64(self.length) - offset,
                size <= UInt64(Int32.max)
            else {
                return nil
            }
            do {
                var hashers = hashTypes.map { ($0, $0.hasher()) }
                try self.stream(Int(offset) ..< Int(offset + size)) { chunk in
                    for index in hashers.indices {
                        hashers[index].1.update(bufferPointer: chunk)
                    }
                }
                return Dictionary(uniqueKeysWithValues: hashers.map { ($0, Data($1.finalize())) })
            } catch is Errno {
                // What codesign cannot read either; a file that changed size is still reported.
                return nil
            }
        }
        return nil
    }

    /**
     The empty requirements blob `codesign` embeds; special slot -2 is its digest under the directory's hash type.
     A constant, independent of the binary: magic, length 12, count 0.
     */
    private static let emptyRequirementsBlob: Data = {
        var blob = Data()
        blob.appendBigEndian(Self.csmagicRequirements)
        blob.appendBigEndian(UInt32(12))
        blob.appendBigEndian(UInt32(0))

        return blob
    }()

    // MARK: - Constants (xnu cs_blobs.h, big-endian on disk)

    private static let csmagicEmbeddedSignature: UInt32 = 0xfade_0cc0
    fileprivate static let csmagicCodeDirectory: UInt32 = 0xfade_0c02
    private static let csmagicRequirements: UInt32 = 0xfade_0c01

    private static let csslotCodeDirectory: UInt32 = 0
    private static let csslotAlternateBase: UInt32 = 0x1000
    private static let csslotAlternateLimit: UInt32 = 0x1005
    /// The special slots Security seals a blob under: the requirements, the entitlements, their DER form.
    static let csslotRequirements: UInt32 = 2
    static let csslotEntitlements: UInt32 = 5
    static let csslotDEREntitlements: UInt32 = 7
    /// The top directory's slot, and the last slot Security visits: the library constraint's (`cdSlotMax`).
    private static let csslotTopDirectory: UInt32 = 4
    private static let csslotMax: UInt32 = 11
    /// The slots sealed over the whole blob (`cdComponentIsBlob`): the requirements, the entitlements, their DER
    /// form and the four constraints. The others are sealed over the bytes under a wrapper.
    private static let csslotsOfBlobs: Set<UInt32> = [2, 5, 7, 8, 9, 10, 11]
    /// The slots hash mode does not judge: the Info.plist's and the resource directory's.
    private static let csslotsLeftOut: Set<UInt32> = [1, 3]
    /// The CMS signature's slot, and the magic of the wrapper it lies under.
    static let csslotSignature: UInt32 = 0x10000
    static let csmagicBlobWrapper: UInt32 = 0xfade_0b01
    /// `CS_ADHOC`: a directory signed by no one, which Security takes without a CMS blob.
    static let csAdhoc: UInt32 = 0x2

    /// Filetypes codesign signs as Mach-O code; it signs any other one as a generic file (`Format=generic`).
    static let codeFiletypes = [
        MH_EXECUTE,
        MH_PRELOAD,
        MH_DYLIB,
        MH_DYLINKER,
        MH_BUNDLE,
        MH_KEXT_BUNDLE,
    ].map(UInt32.init)
}

// MARK: -

struct EmbeddedCodeDirectory {
    let data: Data
    let hashType: HashType
    /// Where code slot 0 starts.
    let hashOffset: Int
    /// The bytes of code the code slots cover, from the start of the slice.
    let codeLimit: UInt64
    /**
     The bytes of code each code slot covers when Security checks the slots (`validateExecutable`), the last one
     fewer. The code limit itself when the directory is not paged.

     Security computes `1 << pageSize` on an `int`: the shift counts modulo 32 on the hardware it runs on, and the
     result is widened with its sign.

     ```
     exponent   1 << (exponent & 31)    pages of
     --------   ---------------------   ------------------------------------------
     12         0x1000                  4 KiB
     31, 63     0x80000000, negative    0xffffffff80000000 bytes: past any code limit
     32         1                       1 byte
     44         0x1000                  4 KiB
     ```
     */
    let pageSize: UInt64
    /// Whether the directory holds a scatter vector, which Security does not read: it checks the slots in order.
    let scattered: Bool
    /// The directory's flags: `CS_ADHOC` among them.
    let flags: UInt32
    let nSpecialSlots: Int
    let nCodeSlots: Int
    /// log2 of the page size, zero for a directory that is not paged.
    let pageSizeLog: UInt8
    /// The team identifier the signer wrote, nil when none or before version 0x20200 held one.
    let teamID: String?

    /**
     A code directory Security accepts, with the checks `SecStaticCode::loadCodeDirectories` makes: its header holds
     every field its version declares (`CodeDirectory::validateBlob`), that version is one Security reads, its hash type
     one it knows with slots of that hash's width, its identifier and team strings end inside it, its hash slots,
     pre-encryption slots and scatter vector lie inside it, and its code slots cover its code limit page by page. Nil
     otherwise. Unlike the kernel, Security does not check the magic.

     The directory, big-endian, its header growing with its version, then the strings and the hash slots it points at:

     ```text
      +0x00 +-------------------------------------------------+
            | magic 0xfade0c02 (4)     | length (4)           |
      +0x08 | version (4)              | flags (4)            |  CS_ADHOC 0x2, CS_ENFORCE_EXPIRATION 0x400 among them
      +0x10 | hashOffset (4)           | identOffset (4)      |
      +0x18 | nSpecialSlots (4)        | nCodeSlots (4)       |
      +0x20 | codeLimit (4)            | hashSize (1) |       |  hashType 1 SHA-1, 2 SHA-256, 3 SHA-256 truncated,
            |   hashType (1) | platform (1) | pageSize (1)    |  4 SHA-384, 5 SHA-512; pageSize as log2, 0 unpaged
      +0x28 | spare2 (4)               | scatterOffset (4)    |  scatterOffset from version 0x20100
      +0x30 | teamOffset (4)           | spare3 (4)           |  teamOffset from 0x20200, spare3 from 0x20300
      +0x38 | codeLimit64 (8)                                 |  from 0x20300, read when it is not 0
      +0x40 | execSegBase (8) | execSegLimit (8) |            |  from 0x20400
            |   execSegFlags (8)                              |
      +0x58 | runtime (4)              | preEncryptOffset (4) |  from 0x20500; the header ends at 0x60
            +-------------------------------------------------+
            | identifier, NUL-terminated, at identOffset      |
            | team identifier, at teamOffset                  |
            +-------------------------------------------------+
            | special slots: nSpecialSlots × hashSize,        |  slot -n at hashOffset - n × hashSize: -1 Info.plist,
            |   ending at hashOffset                          |  -2 requirements, -3 resources, -4 application,
            +-------------------------------------------------+  -5 entitlements, -6 rep-specific, -7 DER entitlements
            | code slots: nCodeSlots × hashSize, from         |  one per page of codeLimit, 2^pageSize bytes each,
            |   hashOffset                                    |  the last page partial
            +-------------------------------------------------+
            | scatter vector, at scatterOffset                |  { count | base | targetOffset (8) | spare (8) } × n,
            | pre-encryption slots, at preEncryptOffset       |  to an entry of count 0; nCodeSlots × hashSize
            +-------------------------------------------------+
     ```
     */
    init?(_ blob: Data) {
        let length = blob.count
        guard length >= 12 else {
            return nil
        }

        let version = blob.bigEndianUInt32(at: 8)
        guard
            CodeDirectoryBuilder.headerSize(version: version) <= length,
            0x20001 ... 0x2f000 ~= version
        else {
            return nil
        }

        let (hashSize, rawHashType, pageSizeLog) = blob.withUnsafeBytes { raw -> (Int, UInt8, UInt8) in (Int(raw[36]), raw[37], raw[39]) }
        guard
            let hashType = HashType(rawValue: rawHashType),
            hashType.slotSize == hashSize
        else {
            return nil
        }

        /// Whether the C string at `offset` ends inside the blob, a NUL before its end.
        func endsInside(_ offset: UInt32) -> Bool {
            Int(offset) < length && blob.bytes(in: Int(offset) ..< length).contains(0)
        }
        guard
            endsInside(blob.bigEndianUInt32(at: 20)), // identOffset
            version < 0x20200 || blob.bigEndianUInt32(at: 48) == 0 || endsInside(blob.bigEndianUInt32(at: 48)) // teamOffset
        else {
            return nil
        }

        // Special slots precede hashOffset, code slots follow it; pre-encryption hashes have a code slot each.
        let hashOffset = Int(blob.bigEndianUInt32(at: 16))
        let nSpecialSlots = Int(blob.bigEndianUInt32(at: 24))
        let nCodeSlots = Int(blob.bigEndianUInt32(at: 28))
        let preEncryptOffset = version >= 0x20500 ? Int(blob.bigEndianUInt32(at: 92)) : 0
        guard
            hashOffset - hashSize * nSpecialSlots >= 8,
            hashOffset + hashSize * nCodeSlots <= length,
            preEncryptOffset == 0 || (preEncryptOffset >= 8 && preEncryptOffset + hashSize * nCodeSlots <= length)
        else {
            return nil
        }

        // The scatter vector runs to an entry of zero pages, and its last page needs a hash slot. Security computes that
        // slot's position with a 32-bit product, sign-extended.
        let scatterOffset = version >= 0x20100 ? Int(blob.bigEndianUInt32(at: 44)) : 0
        if scatterOffset != 0 {
            var entry = scatterOffset
            var pages: UInt32 = 0
            while true {
                guard
                    entry >= 8,
                    entry + 24 <= length
                else {
                    return nil
                }
                let count = blob.bigEndianUInt32(at: entry)
                entry += 24
                if count == 0 {
                    break
                }
                pages &+= count
            }

            let lastSlot = Int(Int32(bitPattern: (pages &- 1) &* UInt32(hashSize)))
            for base in [hashOffset] + (preEncryptOffset != 0 ? [preEncryptOffset] : []) {
                guard
                    base + lastSlot >= 8,
                    base + lastSlot + hashSize <= length
                else {
                    return nil
                }
            }
        }

        // One code slot per page of the code limit, or a single slot when the directory is not paged. Here Security
        // shifts a 64-bit limit, which counts modulo 64 on the hardware it runs on. The shift that sizes the pages
        // it checks is of an `int`, and counts modulo 32 (see `pageSize`).
        let codeLimit64 = version >= 0x20300 ? blob.bigEndianUInt64(at: 56) : 0
        let codeLimit = codeLimit64 != 0 ? codeLimit64 : UInt64(blob.bigEndianUInt32(at: 32))
        let codeSlots: UInt64? = if pageSizeLog != 0 {
            codeLimit == 0 ? nil : ((codeLimit - 1) &>> UInt64(pageSizeLog)) + 1
        } else {
            codeLimit == 0 ? 0 : 1
        }
        guard codeSlots == UInt64(nCodeSlots) else {
            return nil
        }

        self.data = blob
        self.hashType = hashType
        self.hashOffset = hashOffset
        self.codeLimit = codeLimit
        self.pageSize = pageSizeLog != 0 ? UInt64(bitPattern: Int64(Int32(bitPattern: 1 << UInt32(pageSizeLog & 31)))) : codeLimit
        self.scattered = scatterOffset != 0
        self.flags = blob.bigEndianUInt32(at: 12)
        self.nSpecialSlots = nSpecialSlots
        self.nCodeSlots = nCodeSlots
        self.pageSizeLog = pageSizeLog
        let teamOffset = version >= 0x20200 ? Int(blob.bigEndianUInt32(at: 48)) : 0
        self.teamID = teamOffset == 0 ? nil : String(decoding: blob.bytes(in: teamOffset ..< length).prefix { $0 != 0 }, as: UTF8.self)
    }

    /// Special slot `-slot`'s hash, nil when the directory has fewer special slots than that.
    func specialSlot(_ slot: Int) -> Data? {
        guard slot >= 1, slot <= self.nSpecialSlots else {
            return nil
        }
        let size = self.hashType.slotSize
        return self.data.bytes(in: self.hashOffset - slot * size ..< self.hashOffset - (slot - 1) * size)
    }

    /**
     Whether `digest`, of a page, is code slot `slot`'s, like `CodeDirectory::validateSlot`: a truncated hash type
     compares its slot's width of it.
     */
    func validateSlot(_ digest: Data, _ slot: Int) -> Bool {
        let size = self.hashType.slotSize
        let offset = self.hashOffset + slot * size
        return digest.prefix(size) == self.data.bytes(in: offset ..< offset + size)
    }
}

/**
 One code directory's slots checked as the code streams by: each page hashed as its bytes arrive, the last one shorter,
 against its slot, until one fails or the code limit is reached, the pages cut as the `geometry` directory lays them,
 which Security takes for every directory. A directory with fewer slots than pages fails at the first it lacks.
 So does a directory whose exponent is 32 or more, when the pages cut are smaller than its code: its slots are
 counted by the exponent as written, its pages cut by the exponent modulo 32 (`EmbeddedCodeDirectory.pageSize`).
 A geometry the slice cannot hold fails every directory outright. A scatter vector is not read, as Security reads
 none here: the slots are checked in order.
 */
private struct SlotValidator {
    /// Thrown through the stream once no slot is left to check.
    struct Done: Error {}

    private let directory: EmbeddedCodeDirectory
    /// The bytes of code to check: the code limit, or none.
    let limit: Int
    private let pageSize: Int
    private var hasher: any HashFunction
    private var slot = 0
    /// Bytes of code fed so far, and of the current page.
    private var offset = 0
    private var filled = 0
    private(set) var valid: Bool
    /// The first code slot the code did not hash to, when one did not.
    private(set) var failedSlot: Int?

    init(_ directory: EmbeddedCodeDirectory, geometry: EmbeddedCodeDirectory, length: Int) {
        let valid = geometry.codeLimit <= UInt64(length)
        self.directory = directory
        self.hasher = directory.hashType.hasher()
        self.valid = valid
        self.limit = valid ? Int(geometry.codeLimit) : 0
        self.pageSize = valid ? Int(min(geometry.pageSize, geometry.codeLimit)) : 0
    }

    /// Whether a slot is left to check.
    var checking: Bool {
        self.valid && self.offset < self.limit
    }

    /// Feed the code from `offset` on.
    mutating func update(_ chunk: UnsafeRawBufferPointer) {
        var chunk = chunk
        while self.checking, !chunk.isEmpty {
            let page = min(self.pageSize, self.limit - (self.offset - self.filled))
            let count = min(page - self.filled, chunk.count)
            self.hasher.update(bufferPointer: UnsafeRawBufferPointer(rebasing: chunk.prefix(count)))
            chunk = UnsafeRawBufferPointer(rebasing: chunk.dropFirst(count))
            self.offset += count
            self.filled += count
            if self.filled == page {
                self.valid = self.slot < self.directory.nCodeSlots && self.directory.validateSlot(Data(self.hasher.finalize()), self.slot)
                if !self.valid {
                    self.failedSlot = self.slot
                }
                self.hasher = self.directory.hashType.hasher()
                self.slot += 1
                self.filled = 0
            }
        }
    }
}

/**
 The ad-hoc CodeDirectory `codesign` builds, like Security's `CodeDirectory::Builder`: the fields decide the
 version, and the version decides how much of the header is written.
 */
private struct CodeDirectoryBuilder {
    let codeLimit: Int
    let pageSizeLog: UInt8
    let execSegBase: UInt64
    let execSegLimit: UInt64
    let execSegFlags: UInt64
    /// The directories built, one per hash type as `Signer::signMachO` builds them.
    let hashTypes: [HashType]
    /// Special slot digests by slot number and hash type, written into slot -n.
    let specialSlots: [Int: [HashType: Data]]

    /// `blob` digested under each of `hashTypes`, what a special slot holds of it.
    static func digests(of blob: Data, _ hashTypes: [HashType]) -> [HashType: Data] {
        Dictionary(uniqueKeysWithValues: hashTypes.map { ($0, $0.digest(blob)) })
    }

    /// `Builder::build`'s choice: the oldest version that holds every field in use.
    var version: UInt32 {
        if self.execSegLimit != 0 {
            return 0x20400 // execSeg
        }
        if self.codeLimit > UInt32.max {
            return 0x20300 // codeLimit64
        }
        return 0x20100
    }

    /// `Builder::size`'s fixed header size, which `CodeDirectory::validateBlob` requires of an embedded directory too:
    /// each version appends fields to the previous one.
    static func headerSize(version: UInt32) -> Int {
        switch version {
        case 0x20500...: 0x60 // runtime, preEncryptOffset
        case 0x20400...: 0x58 // execSegBase, execSegLimit, execSegFlags
        case 0x20300...: 0x40 // spare3, codeLimit64
        case 0x20200...: 0x34 // teamOffset
        case 0x20100...: 0x30 // scatterOffset
        default: 0x2c // through spare2
        }
    }

    /**
     The directory of each of `hashTypes`, like `Builder::build`: the header the fields call for, the identifier, the
     special slots, then a hash slot per page of code, read from the image once. A directory too large is refused
     before any code is read.
     */
    func build(code image: MachO) throws -> [Built] {
        let hashTypes = self.hashTypes
        var directories = try hashTypes.map { try self.directory(hashType: $0) }
        try image.forEachPage(upTo: self.codeLimit, pageSize: 1 << Int(self.pageSizeLog)) { page in
            for index in hashTypes.indices {
                directories[index].append(hashTypes[index].digest(page))
            }
        }

        return zip(hashTypes, directories).map { Built(hashType: $0, directory: $1) }
    }

    /// A code directory built, under its hash type.
    struct Built {
        let hashType: HashType
        let directory: Data
    }

    /**
     The directory of `hashType` up to its code slots, with room for them.
     */
    private func directory(hashType: HashType) throws -> Data {
        let pageSize = 1 << Int(self.pageSizeLog)
        let hashSize = hashType.slotSize
        let nSpecialSlots = self.specialSlots.keys.max() ?? 0
        let nCodeSlots = (self.codeLimit + pageSize - 1) / pageSize
        let identifier = Data("ADHOC".utf8) + Data([0])
        let identOffset = Self.headerSize(version: self.version)
        let hashOffset = identOffset + identifier.count + nSpecialSlots * hashSize
        let length = hashOffset + nCodeSlots * hashSize

        // Builder::build only refuses more than 2^32 code slots and truncates a longer length into its 32-bit field:
        // refuse any directory that does not fit rather than build a truncated one.
        guard let length32 = UInt32(exactly: length) else {
            throw CDHashError.codeDirectoryTooLarge(length: length)
        }

        // Every field up to execSegFlags; the version keeps the prefix its header holds.
        var header = Data()
        header.appendBigEndian(MachO.csmagicCodeDirectory) // magic
        header.appendBigEndian(length32) // length
        header.appendBigEndian(self.version) // version
        header.appendBigEndian(UInt32(2)) // flags: CS_ADHOC
        header.appendBigEndian(UInt32(hashOffset)) // hashOffset
        header.appendBigEndian(UInt32(identOffset)) // identOffset
        header.appendBigEndian(UInt32(nSpecialSlots)) // nSpecialSlots
        header.appendBigEndian(UInt32(nCodeSlots)) // nCodeSlots
        header.appendBigEndian(UInt32(clamping: self.codeLimit)) // codeLimit, 0xffffffff past 4 GiB
        header.append(contentsOf: [UInt8(hashSize), hashType.rawValue, 0, self.pageSizeLog]) // hashSize, hashType, platform, pageSize
        header.appendBigEndian(UInt32(0)) // spare2
        header.appendBigEndian(UInt32(0)) // scatterOffset
        header.appendBigEndian(UInt32(0)) // teamOffset
        header.appendBigEndian(UInt32(0)) // spare3
        header.appendBigEndian(UInt64(self.codeLimit > UInt32.max ? self.codeLimit : 0)) // codeLimit64
        header.appendBigEndian(self.execSegBase) // execSegBase
        header.appendBigEndian(self.execSegLimit) // execSegLimit
        header.appendBigEndian(self.execSegFlags) // execSegFlags

        var cd = header.prefix(identOffset)
        cd.reserveCapacity(length)
        cd.append(identifier)
        for slot in stride(from: nSpecialSlots, through: 1, by: -1) { // slots -nSpecialSlots ... -1
            cd.append(self.specialSlots[slot]?[hashType] ?? Data(count: hashSize))
        }
        return cd
    }
}

/**
 A code directory's hash type, numbered as `cs_blobs.h` numbers them (`CS_HASHTYPE_*`) and as Security's
 `CodeDirectory::hashFor` knows them: the directory's slots are hashes of that type, and its cdhash is the directory
 digested under it.
 */
enum HashType: UInt8 {
    case sha1 = 1
    case sha256 = 2
    case sha256Truncated = 3
    case sha384 = 4
    case sha512 = 5

    /// The width of one hash slot: a truncated SHA-256 keeps 20 bytes.
    var slotSize: Int {
        switch self {
        case .sha1: Insecure.SHA1.byteCount
        case .sha256: SHA256.byteCount
        case .sha256Truncated: 20
        case .sha384: SHA384.byteCount
        case .sha512: SHA512.byteCount
        }
    }

    /// How a cdhash line names it.
    var name: String {
        switch self {
        case .sha1: "sha1"
        case .sha256: "sha256"
        case .sha256Truncated: "sha256t"
        case .sha384: "sha384"
        case .sha512: "sha512"
        }
    }

    /// Order among code directories, higher first, as Security chooses (`hashPriorities`, which
    /// `SecStaticCode::codeDirectory` and codesign's CDHash follow) and xnu among the types it knows
    /// (`bsd/kern/ubc_subr.c`): SHA-512 first, which xnu does not know and refuses the signature for.
    var rank: Int {
        switch self {
        case .sha512: 5
        case .sha384: 4
        case .sha256: 3
        case .sha256Truncated: 2
        case .sha1: 1
        }
    }

    /// The whole digest of `data`: a slot or a cdhash. A truncated SHA-256 directory's cdhash is cut to 20 bytes as its
    /// slots are: `CodeDirectory::hashFor` makes every digest of that type 20 bytes long, codesign's CDHash included.
    func digest(_ data: some DataProtocol) -> Data {
        switch self {
        case .sha1: Data(Insecure.SHA1.hash(data: data))
        case .sha256: Data(SHA256.hash(data: data))
        case .sha256Truncated: Data(SHA256.hash(data: data).prefix(20))
        case .sha384: Data(SHA384.hash(data: data))
        case .sha512: Data(SHA512.hash(data: data))
        }
    }

    /// A hasher for a page fed as it arrives, whose digest `validateSlot` compares.
    func hasher() -> any HashFunction {
        switch self {
        case .sha1: Insecure.SHA1()
        case .sha256, .sha256Truncated: SHA256()
        case .sha384: SHA384()
        case .sha512: SHA512()
        }
    }
}

private extension Data {
    mutating func appendBigEndian(_ value: some FixedWidthInteger) {
        Swift.withUnsafeBytes(of: value.bigEndian) { append(contentsOf: $0) }
    }

    /// The big-endian integer at `offset`, counted from the first byte.
    func bigEndianUInt32(at offset: Int) -> UInt32 {
        self.withUnsafeBytes { UInt32(bigEndian: $0.loadUnaligned(fromByteOffset: offset, as: UInt32.self)) }
    }

    /// The big-endian integer at `offset`, counted from the first byte.
    func bigEndianUInt64(at offset: Int) -> UInt64 {
        self.withUnsafeBytes { UInt64(bigEndian: $0.loadUnaligned(fromByteOffset: offset, as: UInt64.self)) }
    }
}
