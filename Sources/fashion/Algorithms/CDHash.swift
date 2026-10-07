import CryptoKit
import Foundation
import MachO
import os
import System

private let logger = Logger(subsystem: "fashion", category: "cdhash")

enum CDHashError: Error, Equatable {
    case invalidCodeSignatureRange(offset: UInt32, size: UInt32, fileSize: Int)
    case truncatedCodeSignatureSuperblob(signatureSize: Int)
    case invalidCodeSignatureMagic(magic: UInt32)
    case invalidCodeSignatureSuperblobLength(length: UInt32, signatureSize: Int)
    case invalidCodeSignatureIndexTable(count: UInt32, length: UInt32)
    case invalidCodeSignatureBlobOffset(offset: UInt32, signatureSize: Int)
    case invalidCodeSignatureBlobRange(offset: UInt32, size: UInt32, signatureSize: Int)
    case codeDirectoryTooLarge(length: Int)
}

extension CDHashError: LocalizedError {
    var errorDescription: String? {
        switch self {
        case let .invalidCodeSignatureRange(offset, size, fileSize):
            "Invalid Mach-O: code signature range at offset \(offset) with size \(size) is outside the \(fileSize)-byte slice"
        case let .truncatedCodeSignatureSuperblob(signatureSize):
            "Invalid Mach-O: code signature is only \(String(signatureSize, pluralizing: "byte")); an embedded signature header requires 12"
        case let .invalidCodeSignatureMagic(magic):
            "Invalid Mach-O: code signature has invalid magic \(String(format: "0x%08x", magic))"
        case let .invalidCodeSignatureSuperblobLength(length, signatureSize):
            "Invalid Mach-O: code signature declares a \(length)-byte superblob inside a \(signatureSize)-byte signature"
        case let .invalidCodeSignatureIndexTable(count, length):
            "Invalid Mach-O: code signature index count \(count) does not fit in the \(length)-byte superblob"
        case let .invalidCodeSignatureBlobOffset(offset, signatureSize):
            "Invalid Mach-O: code signature blob offset \(offset) is outside the \(signatureSize)-byte superblob"
        case let .invalidCodeSignatureBlobRange(offset, size, signatureSize):
            "Invalid Mach-O: code signature blob at offset \(offset) with size \(size) is outside the \(signatureSize)-byte superblob"
        case let .codeDirectoryTooLarge(length):
            "Mach-O too large: its \(length)-byte ad-hoc CodeDirectory would overflow the 32-bit length field"
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
    }

    /**
     Compute CDHash for each Mach-O slice in a file.

     Thin binaries return a single result with nil arch.
     Fat binaries return one result per slice.

     With `exact`, an unsigned slice is trimmed to its logical extent before synthesis,
     so appended trailing garbage does not change its ad-hoc cdhash.
     */
    static func hash(_ file: File, path: String, exact: Bool = false) throws -> [SliceResult] {
        switch try Universal.open(file) {
        case let .fat(archs):
            try archs.flatMap { arch -> [SliceResult] in
                let name = arch.name
                // A slice that is not a thin Mach-O, typically the `ar` archive of a universal static library, has no code directory.
                guard let image = try MachO(file, offset: arch.range.lowerBound, length: arch.range.count) else {
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
        let (directories, skipReason) = try slice.codeDirectoryHashes(exact: exact)
        if let skipReason {
            self.logSkip(path: path, arch: arch, reason: skipReason)
        }
        let ambiguous = directories.count > 1

        return directories.map { cd in
            SliceResult(hash: cd.hash, arch: arch, type: ambiguous ? cd.type : nil, adhoc: cd.adhoc)
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
        /// The hash type's name (see `HashType`): `sha1` or `sha256` for a synthesized ad-hoc directory.
        let type: String
        let adhoc: Bool
    }

    /**
     The slice's cdhashes, or the reason it has none (`skipReason` is set exactly when `hashes` is empty).

     A slice whose filetype `codesign` takes for a generic file rather than code (`MachORep::candidate`) has none,
     signed or not: `codesign -d` calls such a file "not signed at all" whatever its `LC_CODE_SIGNATURE` holds.

     A signed slice yields every code directory Security loads from its signature, strongest first per `HashType.rank`: the
     head is the kernel-enforced cdhash.

     An unsigned slice yields its synthesized ad-hoc cdhashes (SHA-256 then SHA-1). So does a signed slice whose code
     directories Security rejects: `codesign` calls it "not signed at all" and signs it up to where its signature starts,
     the code limit of `MachORep::signingLimit`. A signature Security cannot read at all is an error, as `codesign` cannot
     sign over it.

     A slice of a universal file is judged on its own, as if extracted: `codesign` instead decides a whole 32-bit
     universal file from its first slice, and treats a 64-bit one (`lipo -fat64`) as a generic file outright.
     */
    func codeDirectoryHashes(exact: Bool) throws -> (hashes: [CodeDirectoryHash], skipReason: String?) {
        guard Self.codeFiletypes.contains(self.filetype) else {
            return ([], "\(self.filetypeName) is not code to codesign")
        }

        let signature = try self.findCodeSignature()
        if let signature {
            let hashes = try Self.loadCodeDirectories(self.signingData(signature))
                .sorted { $0.hashType.rank > $1.hashType.rank }
                .map { cd in
                    CodeDirectoryHash(hash: cd.hashType.digest(cd.data).hexString, type: cd.hashType.name, adhoc: false)
                }
            if !hashes.isEmpty {
                return (hashes, nil)
            }
        }

        return try (self.adhocCDHashes(codeLimit: signature?.offset ?? (exact ? self.logicalEnd() : self.length)), nil)
    }

    // MARK: - Embedded signature

    /**
     The superblob `LC_CODE_SIGNATURE` points at, read like `MachORep::signingData`: `BlobCore::readBlob` requires its
     magic and, unless the command's size is zero, a length within that size; then `EmbeddedSignatureBlob::specific`
     requires every blob it indexes to lie inside it. fashion also requires the length to fit the slice, where
     `codesign -d` reads on into the next slice of a universal file. Throws otherwise.
     */
    private func signingData(_ signature: (offset: Int, size: Int)) throws -> Data {
        let (offset, size) = signature
        guard offset <= self.length - 8 else {
            throw CDHashError.invalidCodeSignatureRange(offset: UInt32(offset), size: UInt32(size), fileSize: self.length)
        }

        let header = try self.dataAt(offset, count: 8)
        let (magic, length) = (header.bigEndianUInt32(at: 0), header.bigEndianUInt32(at: 4))
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

        let superblob = try self.dataAt(offset, count: Int(length))
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

        return superblob
    }

    /**
     The code directories Security loads (`SecStaticCode::loadCodeDirectories`): the primary slot's, then the
     alternates' from 0x1000 up to the first one missing. Empty, so that the slice counts as unsigned, when the primary
     is missing, when any of them fails the checks of `EmbeddedCodeDirectory`, or when two share a hash type.
     */
    private static func loadCodeDirectories(_ superblob: Data) -> [EmbeddedCodeDirectory] {
        var directories: [EmbeddedCodeDirectory] = []
        for slot in [self.csslotCodeDirectory] + Array(self.csslotAlternateBase ..< self.csslotAlternateLimit) {
            guard let blob = self.component(slot, of: superblob) else {
                break
            }
            guard
                let directory = EmbeddedCodeDirectory(blob),
                !directories.contains(where: { $0.hashType == directory.hashType })
            else {
                return []
            }
            directories.append(directory)
        }

        return directories
    }

    /**
     The blob a superblob holds in `slot`, like `SuperBlob::find`: the first index entry of that type, nil when there is
     none or its offset is zero. `signingData` has checked that the blob lies inside the superblob.
     */
    private static func component(_ slot: UInt32, of superblob: Data) -> Data? {
        for entry in 0 ..< Int(superblob.bigEndianUInt32(at: 8)) where superblob.bigEndianUInt32(at: 12 + 8 * entry) == slot {
            let offset = Int(superblob.bigEndianUInt32(at: 12 + 8 * entry + 4))
            return offset == 0 ? nil : superblob.bytes(in: offset ..< offset + Int(superblob.bigEndianUInt32(at: offset + 4)))
        }
        return nil
    }

    // MARK: - Ad-hoc synthesis

    /**
     Synthesize the ad-hoc cdhashes of an unsigned slice: for each hash algorithm codesign uses, the digest
     of the CodeDirectory that `codesign --detached -s - --identifier ADHOC --digest-algorithm=sha1,sha256`
     builds, byte for byte. Each cdhash is that directory digested under its own hash type.

     Returns the SHA-256 cdhash first (the kernel-enforced identity, matching `CandidateCDHashFull sha256`)
     then the SHA-1 cdhash (`CandidateCDHashFull sha1`).

     While we print the full hash, we can match the truncated 20-byte cdhash too. Code covers `codeLimit` bytes:
     the whole slice, its logical extent under `exact`, or what precedes a signature Security rejects.

     Throws where Security fails to sign: for a version or segment command it cannot read, or a directory too large.
     */
    private func adhocCDHashes(codeLimit: Int) throws -> [CodeDirectoryHash] {
        // Security's Signer::populate: fill a CodeDirectory::Builder with what MachORep reports.
        let execSeg = try self.execSeg()
        let builder = try CodeDirectoryBuilder(
            codeLimit: codeLimit,
            pageSizeLog: self.pageSizeLog(),
            execSegBase: execSeg.base,
            execSegLimit: execSeg.limit,
            execSegFlags: self.filetype == UInt32(MH_EXECUTE) ? 1 : 0, // CS_EXECSEG_MAIN_BINARY
            specialSlots: [1: self.infoPlist(), 2: Self.emptyRequirementsBlob].compactMapValues { $0 }, // cdInfoSlot, cdRequirementsSlot
        )

        return try builder.build(code: self).map { hashType, cd in
            CodeDirectoryHash(hash: hashType.digest(cd).hexString, type: hashType.name, adhoc: true)
        }
    }

    /**
     log2 of the page size `codesign` signs with, like `MachORep::pageSize`: 16 KiB for the arm64 family, except
     4 KiB on tvOS, iOS before 16 and watchOS before 9 (the declared minimum OS, not the SDK); 4 KiB for every other
     architecture.
     */
    private func pageSizeLog() throws -> UInt8 {
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
    private func execSeg() throws -> (base: UInt64, limit: UInt64) {
        guard
            try (self.version()?.platform ?? 0) != 0,
            let text = try self.findSegment("__TEXT")
        else {
            return (0, 0)
        }

        if self.is64 {
            return text.payload(as: segment_command_64.self).map { ($0.fileoff, $0.filesize) } ?? (0, 0)
        }

        return text.payload(as: segment_command.self).map { (UInt64($0.fileoff), UInt64($0.filesize)) } ?? (0, 0)
    }

    /**
     The Info.plist embedded in `__TEXT,__info_plist`, like `MachORep::infoPlist`: the section's bytes, whatever they
     hold, or nil. As in `MachOBase::findSection`, a segment command too short for the section table it declares holds
     no section. `MachORep::infoPlist` catches a failed `MachO::dataAt`, so a section `codesign` cannot read is no
     Info.plist either: one past the slice's end, or one larger than the 2 GiB a single read(2) takes. On a big-endian
     slice (ppc, ppc64) `codesign` bounds the section table with the unswapped section count, so it never finds the
     section.
     */
    private func infoPlist() throws -> Data? {
        guard
            !self.swap,
            let text = try self.findSegment("__TEXT")
        else {
            return nil
        }

        let (headerSize, sectionSize, count) = try self.is64
            ? (MemoryLayout<segment_command_64>.size, MemoryLayout<section_64>.size, text.load(segment_command_64.self).nsects)
            : (MemoryLayout<segment_command>.size, MemoryLayout<section>.size, text.load(segment_command.self).nsects)
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
                size <= UInt64(self.length) - offset
            else {
                return nil
            }
            do {
                return try self.dataAt(Int(offset), count: Int(size))
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

    // Filetypes codesign signs as Mach-O code; it signs any other one as a generic file (`Format=generic`).
    private static let codeFiletypes = [
        MH_EXECUTE,
        MH_PRELOAD,
        MH_DYLIB,
        MH_DYLINKER,
        MH_BUNDLE,
        MH_KEXT_BUNDLE,
    ].map(UInt32.init)
}

// MARK: -

private struct EmbeddedCodeDirectory {
    let data: Data
    let hashType: HashType

    /**
     A code directory Security accepts, with the checks `SecStaticCode::loadCodeDirectories` makes: its header holds
     every field its version declares (`CodeDirectory::validateBlob`), that version is one Security reads, its hash type
     one it knows with slots of that hash's width, its identifier and team strings end inside it, its hash slots,
     pre-encryption slots and scatter vector lie inside it, and its code slots cover its code limit page by page. Nil
     otherwise. Unlike the kernel, Security does not check the magic.
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

        // One code slot per page of the code limit, or a single slot when the directory is not paged. A shift counts
        // modulo 64, as on the hardware Security runs on.
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
    /// Special slot contents by slot number, hashed into slot -n.
    let specialSlots: [Int: Data]

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
     The directory of each hash type `codesign --digest-algorithm=sha1,sha256` builds, SHA-256 first, like
     `Builder::build`: the header the fields call for, the identifier, the special slots, then a hash slot per page of
     code, read from the image once for both types. A directory too large is refused before any code is read.
     */
    func build(code image: MachO) throws -> [(hashType: HashType, directory: Data)] {
        let hashTypes: [HashType] = [.sha256, .sha1]
        var directories = try hashTypes.map { try self.directory(hashType: $0) }
        func hashPage(_ page: UnsafeRawBufferPointer) {
            for index in hashTypes.indices {
                directories[index].append(hashTypes[index].digest(page))
            }
        }

        // Pages are hashed as the code streams through; one cut by the end of a chunk waits for the rest of it.
        let pageSize = 1 << Int(self.pageSizeLog)
        var partial = Data()
        try image.stream(0 ..< self.codeLimit) { chunk in
            var chunk = chunk
            if !partial.isEmpty {
                let fill = min(pageSize - partial.count, chunk.count)
                partial.append(contentsOf: chunk.prefix(fill))
                chunk = UnsafeRawBufferPointer(rebasing: chunk.dropFirst(fill))
                guard partial.count == pageSize else {
                    return
                }
                partial.withUnsafeBytes(hashPage)
                partial.removeAll(keepingCapacity: true)
            }
            while chunk.count >= pageSize {
                hashPage(UnsafeRawBufferPointer(rebasing: chunk.prefix(pageSize)))
                chunk = UnsafeRawBufferPointer(rebasing: chunk.dropFirst(pageSize))
            }
            partial.append(contentsOf: chunk)
        }
        // The last page, shorter than the others.
        if !partial.isEmpty {
            partial.withUnsafeBytes(hashPage)
        }

        return Array(zip(hashTypes, directories))
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
            cd.append(self.specialSlots[slot].map { hashType.digest($0) } ?? Data(count: hashSize))
        }
        return cd
    }
}

/**
 A code directory's hash type, numbered as `cs_blobs.h` numbers them (`CS_HASHTYPE_*`) and as Security's
 `CodeDirectory::hashFor` knows them: the directory's slots are hashes of that type, and its cdhash is the directory
 digested under it.
 */
private enum HashType: UInt8 {
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

    /// Order among code directories, higher first, as xnu chooses (`bsd/kern/ubc_subr.c`). SHA-512, which Security loads
    /// but xnu does not know, comes last.
    var rank: Int {
        switch self {
        case .sha512: 0
        case .sha1: 1
        case .sha256Truncated: 2
        case .sha256: 3
        case .sha384: 4
        }
    }

    /// The whole digest of `data`: a slot or a cdhash. Truncation applies to the slots inside a directory, not to its
    /// cdhash, which is plain SHA-256.
    func digest(_ data: some DataProtocol) -> Data {
        switch self {
        case .sha1: Data(Insecure.SHA1.hash(data: data))
        case .sha256, .sha256Truncated: Data(SHA256.hash(data: data))
        case .sha384: Data(SHA384.hash(data: data))
        case .sha512: Data(SHA512.hash(data: data))
        }
    }
}

private extension Data {
    mutating func appendBigEndian(_ value: UInt32) {
        Swift.withUnsafeBytes(of: value.bigEndian) { append(contentsOf: $0) }
    }

    mutating func appendBigEndian(_ value: UInt64) {
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
