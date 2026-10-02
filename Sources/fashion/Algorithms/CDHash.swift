import CryptoKit
import Foundation
import MachO
import os

private let logger = Logger(subsystem: "fashion", category: "cdhash")

/**
 Compute CDHash (Code Directory Hash) for each slice of a Mach-O binary.

 A signed slice yields its embedded cdhash(es).

 An unsigned slice yields a synthesized ad-hoc cdhash: the identity `syspolicyd` computes for unsigned code,
 byte-for-byte equal to `codesign --detached -s - --identifier ADHOC`.

 The per-slice computation lives on `MachOSlice` below; this enum opens the binary and attaches architecture names.
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
    static func hash(path: String, exact: Bool = false) throws -> [SliceResult] {
        let data = try FileReader.map(path: path)

        switch try MachOParser.open(data: data) {
        case let .fat(archs):
            return try archs.flatMap { arch -> [SliceResult] in
                let name = MachOParser.archName(cpuType: arch.cpuType, cpuSubtype: arch.cpuSubtype)
                // A slice that is not a thin Mach-O, typically the `ar` archive of a universal static library, has no code directory.
                guard let slice = try MachOSlice(MachOParser.sliceData(fileData: data, arch: arch)) else {
                    self.logSkip(path: path, arch: name, reason: "slice is not a Mach-O file")
                    return []
                }
                return try self.results(for: slice, arch: name, path: path, exact: exact)
            }
        case let .thin(slice):
            return try self.results(for: slice, arch: nil, path: path, exact: exact)
        case .notMachO:
            return []
        }
    }

    /**
     Compute CDHash from raw Mach-O data (single thin slice).

     Returns the strongest embedded cdhash, or the ad-hoc cdhash when unsigned. Nil for non-Mach-O input,
     and for a slice with neither (see `MachOSlice.codeDirectoryHashes(exact:)`).
     */
    static func hash(data: Data, exact: Bool = false) throws -> String? {
        try MachOSlice(data)?.codeDirectoryHashes(exact: exact).hashes.first?.hash
    }

    // MARK: - Private

    /**
     One SliceResult per code directory. The hash type is only set when a slice carries several directories.
     */
    private static func results(for slice: MachOSlice, arch: String?, path: String, exact: Bool) throws -> [SliceResult] {
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

extension MachOSlice {
    /**
     A single code directory digest of a slice.
     */
    struct CodeDirectoryHash {
        let hash: String
        /// The hash algorithm: `sha1` / `sha256` / `sha256t` / `sha384` for an embedded directory,
        /// or `sha1` / `sha256` for a synthesized ad-hoc directory.
        let type: String
        let adhoc: Bool
    }

    /**
     The slice's cdhashes, or the reason it has none (`skipReason` is set exactly when `hashes` is empty).

     A signed slice yields every embedded code directory, strongest first per hashRank: the head is the
     kernel-enforced cdhash.

     An unsigned slice yields its synthesized ad-hoc cdhashes (SHA-256 then SHA-1), unless its filetype is one
     `codesign` signs as a generic file rather than as code.

     A slice of a universal file is judged on its own, as if extracted: `codesign` instead decides a whole 32-bit
     universal file from its first slice, and treats a 64-bit one (`lipo -fat64`) as a generic file outright.
     */
    func codeDirectoryHashes(exact: Bool) throws -> (hashes: [CodeDirectoryHash], skipReason: String?) {
        // Only a slice with no signature at all falls back to the ad-hoc identity: a signed slice with an
        // unreadable signature yields nothing, as the ad-hoc cdhash only describes unsigned code.
        if let sigRange = try self.codeSignatureRange() {
            let hashes = try self.embeddedCodeDirectories(in: sigRange)
            return (hashes, hashes.isEmpty ? "signature has no code directory with a known hash type" : nil)
        }

        guard Self.codeFiletypes.contains(self.filetype) else {
            return ([], "\(self.filetypeName) is not code to codesign")
        }

        return (self.adhocCDHashes(codeLimit: exact ? self.logicalEnd() : self.data.count), nil)
    }

    // MARK: - Embedded signature

    private func embeddedCodeDirectories(in sigRange: Range<Int>) throws -> [CodeDirectoryHash] {
        let signature = Data(self.data[sigRange])

        return try Self.parseCodeDirectories(signature: signature)
            .sorted { Self.hashRank($0.hashType) > Self.hashRank($1.hashType) }
            .compactMap { cd in
                guard let digest = Self.digest(codeDirectory: cd.data, hashType: cd.hashType) else {
                    return nil
                }
                return CodeDirectoryHash(hash: digest, type: Self.typeName(cd.hashType), adhoc: false)
            }
    }

    /**
     Every code directory in an embedded signature blob (primary slot plus alternates).
     */
    private static func parseCodeDirectories(signature: Data) throws -> [EmbeddedCodeDirectory] {
        guard signature.count >= 12 else {
            throw ParserError.truncatedCodeSignatureSuperblob(signatureSize: signature.count)
        }

        let (magic, length, count) = signature.withUnsafeBytes { ptr -> (UInt32, UInt32, UInt32) in
            (
                UInt32(bigEndian: ptr.loadUnaligned(as: UInt32.self)),
                UInt32(bigEndian: ptr.loadUnaligned(fromByteOffset: 4, as: UInt32.self)),
                UInt32(bigEndian: ptr.loadUnaligned(fromByteOffset: 8, as: UInt32.self)),
            )
        }

        guard magic == self.csmagicEmbeddedSignature else {
            throw ParserError.invalidCodeSignatureMagic(magic: magic)
        }

        let superblobLength = Int(length)
        guard
            superblobLength >= 12,
            superblobLength <= signature.count
        else {
            throw ParserError.invalidCodeSignatureSuperblobLength(length: length, signatureSize: signature.count)
        }

        let indexBase = 12
        guard Int(count) <= (superblobLength - indexBase) / 8 else {
            throw ParserError.invalidCodeSignatureIndexTable(count: count, length: length)
        }

        // LC_CODE_SIGNATURE may include padding after the superblob. Every index and nested blob is
        // relative to, and bounded by, the superblob's own declared length.
        let superblob = Data(signature.prefix(superblobLength))
        var results: [EmbeddedCodeDirectory] = []

        for entryIndex in 0 ..< Int(count) {
            let entryOffset = indexBase + entryIndex * 8

            let (slotType, blobOffset) = superblob.withUnsafeBytes { ptr -> (UInt32, UInt32) in
                (
                    UInt32(bigEndian: ptr.loadUnaligned(fromByteOffset: entryOffset, as: UInt32.self)),
                    UInt32(bigEndian: ptr.loadUnaligned(fromByteOffset: entryOffset + 4, as: UInt32.self)),
                )
            }

            guard slotType == self.csslotCodeDirectory || (slotType >= self.csslotAlternateBase && slotType < self.csslotAlternateLimit) else {
                continue
            }

            let off = Int(blobOffset)
            guard off <= superblob.count - 12 else {
                throw ParserError.invalidCodeDirectoryOffset(offset: blobOffset, signatureSize: superblob.count)
            }

            let (blobMagic, blobLength) = superblob.withUnsafeBytes { ptr -> (UInt32, UInt32) in
                (
                    UInt32(bigEndian: ptr.loadUnaligned(fromByteOffset: off, as: UInt32.self)),
                    UInt32(bigEndian: ptr.loadUnaligned(fromByteOffset: off + 4, as: UInt32.self)),
                )
            }

            guard blobMagic == self.csmagicCodeDirectory else {
                throw ParserError.invalidCodeDirectoryMagic(offset: blobOffset, magic: blobMagic)
            }

            guard blobLength >= 38 else {
                throw ParserError.truncatedCodeDirectory(offset: blobOffset, length: blobLength)
            }
            let blobEnd = off + Int(blobLength)
            guard blobEnd <= superblob.count else {
                throw ParserError.invalidCodeDirectoryRange(offset: blobOffset, size: blobLength, signatureSize: superblob.count)
            }

            // hashType is at offset 37 in the CodeDirectory structure; require it to lie within the blob's
            // own declared length, not merely within the signature, so a short blob cannot borrow a byte
            // from the next one.
            let hashType = superblob.withUnsafeBytes { ptr -> UInt8 in
                ptr.loadUnaligned(fromByteOffset: off + 37, as: UInt8.self)
            }

            results.append(EmbeddedCodeDirectory(data: Data(superblob[off ..< blobEnd]), hashType: hashType))
        }

        return results
    }

    private static func digest(codeDirectory blob: Data, hashType: UInt8) -> String? {
        switch hashType {
        case self.csHashTypeSHA1:
            Insecure.SHA1.hash(data: blob).hexString
        case self.csHashTypeSHA256, self.csHashTypeSHA256Truncated:
            // Truncation applies to the hash slots inside the CD; the CD digest itself is plain SHA-256.
            SHA256.hash(data: blob).hexString
        case self.csHashTypeSHA384:
            SHA384.hash(data: blob).hexString
        default:
            // Unknown hash types rank 0 and are filtered before selection.
            nil
        }
    }

    private static func typeName(_ hashType: UInt8) -> String {
        switch hashType {
        case self.csHashTypeSHA1: "sha1"
        case self.csHashTypeSHA256: "sha256"
        case self.csHashTypeSHA256Truncated: "sha256t"
        case self.csHashTypeSHA384: "sha384"
        default: "unknown"
        }
    }

    /**
     Selection order among code directories, mirroring xnu (`bsd/kern/ubc_subr.c`): higher rank wins, 0 => don't use at all.
     */
    private static func hashRank(_ hashType: UInt8) -> Int {
        [self.csHashTypeSHA1, self.csHashTypeSHA256Truncated, self.csHashTypeSHA256, self.csHashTypeSHA384]
            .firstIndex(of: hashType).map { $0 + 1 } ?? 0
    }

    // MARK: - Ad-hoc synthesis

    /**
     Synthesize the ad-hoc cdhashes of an unsigned slice: for each hash algorithm codesign uses, the digest
     of the CodeDirectory that `codesign --detached -s - --identifier ADHOC --digest-algorithm=sha1,sha256`
     builds, byte for byte. Each cdhash is that directory digested under its own hash type.

     Returns the SHA-256 cdhash first (the kernel-enforced identity, matching `CandidateCDHashFull sha256`)
     then the SHA-1 cdhash (`CandidateCDHashFull sha1`).

     While we print the full hash, we can match the truncated 20-byte cdhash too. Code covers `codeLimit` bytes:
     the whole slice, or its logical extent under `exact`.
     */
    private func adhocCDHashes(codeLimit: Int) -> [CodeDirectoryHash] {
        // Security's Signer::populate: fill a CodeDirectory::Builder with what MachORep reports.
        let execSeg = self.execSeg()
        let builder = CodeDirectoryBuilder(
            codeLimit: codeLimit,
            pageSizeLog: self.pageSizeLog(),
            execSegBase: execSeg.base,
            execSegLimit: execSeg.limit,
            execSegFlags: self.filetype == UInt32(MH_EXECUTE) ? 1 : 0, // CS_EXECSEG_MAIN_BINARY
            specialSlots: [1: self.infoPlist(), 2: Self.emptyRequirementsBlob].compactMapValues { $0 }, // cdInfoSlot, cdRequirementsSlot
        )

        return [AdhocHashType.sha256, .sha1].map { hashType in
            let cd = builder.build(hashType: hashType, code: self.data)
            return CodeDirectoryHash(hash: hashType.hexDigest(cd), type: hashType.name, adhoc: true)
        }
    }

    /**
     log2 of the page size `codesign` signs with, like `MachORep::pageSize`: 16 KiB for the arm64 family, except
     4 KiB on tvOS, iOS before 16 and watchOS before 9 (the declared minimum OS, not the SDK); 4 KiB for every other
     architecture.
     */
    private func pageSizeLog() -> UInt8 {
        guard [CPU_TYPE_ARM64, CPU_TYPE_ARM64_32].contains(self.cpuType) else {
            return 12
        }

        let version = self.version()
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
    private func execSeg() -> (base: UInt64, limit: UInt64) {
        guard
            (self.version()?.platform ?? 0) != 0,
            let text = self.findSegment("__TEXT")
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
     hold, or nil. On a big-endian slice (ppc, ppc64) `codesign` bounds the section table with the unswapped section
     count, so it never finds the section.
     */
    private func infoPlist() -> Data? {
        guard
            !self.swap,
            let text = self.findSegment("__TEXT")
        else {
            return nil
        }

        let (headerSize, sectionSize, count) = self.is64
            ? (MemoryLayout<segment_command_64>.size, MemoryLayout<section_64>.size, text.payload(as: segment_command_64.self)?.nsects ?? 0)
            : (MemoryLayout<segment_command>.size, MemoryLayout<section>.size, text.payload(as: segment_command.self)?.nsects ?? 0)

        for index in 0 ..< min(Int(count), (text.data.count - headerSize) / sectionSize) {
            let at = headerSize + index * sectionSize
            guard Self.name(of: text.data.dropFirst(at).prefix(16)) == "__info_plist" else {
                continue
            }

            let (offset, size): (UInt64, UInt64) = text.data.withUnsafeBytes { raw in
                if self.is64 {
                    let section = raw.loadUnaligned(fromByteOffset: at, as: section_64.self)
                    return (UInt64(section.offset), section.size)
                }
                let section = raw.loadUnaligned(fromByteOffset: at, as: MachO.section.self)
                return (UInt64(section.offset), UInt64(section.size))
            }
            guard
                offset <= UInt64(self.data.count),
                size <= UInt64(self.data.count) - offset
            else {
                return nil
            }
            return self.data.subdata(in: Int(offset) ..< Int(offset + size))
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

    private static let csHashTypeSHA1: UInt8 = 1
    private static let csHashTypeSHA256: UInt8 = 2
    private static let csHashTypeSHA256Truncated: UInt8 = 3
    private static let csHashTypeSHA384: UInt8 = 4

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
    let hashType: UInt8
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

    /// `Builder::size`'s fixed header size: each version appends fields to the previous one.
    static func headerSize(version: UInt32) -> Int {
        switch version {
        case 0x20400...: 0x58 // execSegBase, execSegLimit, execSegFlags
        case 0x20300...: 0x40 // teamOffset (0x20200), spare3, codeLimit64
        default: 0x30 // through scatterOffset
        }
    }

    func build(hashType: AdhocHashType, code: Data) -> Data {
        let pageSize = 1 << Int(self.pageSizeLog)
        let hashSize = hashType.digestSize
        let nSpecialSlots = self.specialSlots.keys.max() ?? 0
        let nCodeSlots = (self.codeLimit + pageSize - 1) / pageSize
        let identifier = Data("ADHOC".utf8) + Data([0])
        let identOffset = Self.headerSize(version: self.version)
        let hashOffset = identOffset + identifier.count + nSpecialSlots * hashSize
        let length = hashOffset + nCodeSlots * hashSize

        // Every field up to execSegFlags; the version keeps the prefix its header holds.
        var header = Data()
        header.appendBigEndian(MachOSlice.csmagicCodeDirectory) // magic
        header.appendBigEndian(UInt32(length)) // length
        header.appendBigEndian(self.version) // version
        header.appendBigEndian(UInt32(2)) // flags: CS_ADHOC
        header.appendBigEndian(UInt32(hashOffset)) // hashOffset
        header.appendBigEndian(UInt32(identOffset)) // identOffset
        header.appendBigEndian(UInt32(nSpecialSlots)) // nSpecialSlots
        header.appendBigEndian(UInt32(nCodeSlots)) // nCodeSlots
        header.appendBigEndian(UInt32(clamping: self.codeLimit)) // codeLimit, 0xffffffff past 4 GiB
        header.append(contentsOf: [UInt8(hashSize), hashType.csHashType, 0, self.pageSizeLog]) // hashSize, hashType, platform, pageSize
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

        var offset = 0
        while offset < self.codeLimit {
            cd.append(hashType.digest(code.subdata(in: offset ..< min(offset + pageSize, self.codeLimit))))
            offset += pageSize
        }
        return cd
    }
}

/**
 A hash algorithm used to synthesize an ad-hoc CodeDirectory.

 `codesign` builds one directory per algorithm; each carries hash slots of that algorithm's width and yields its own
 cdhash, digested under the same algorithm.
 */
private enum AdhocHashType {
    case sha256
    case sha1

    /**
     The `cs_blobs.h` hashType byte stored in the CodeDirectory (`CS_HASHTYPE_SHA1` / `CS_HASHTYPE_SHA256`).
     */
    var csHashType: UInt8 {
        switch self {
        case .sha1: 1
        case .sha256: 2
        }
    }

    /**
     Width of one hash slot, in bytes.
     */
    var digestSize: Int {
        switch self {
        case .sha1: Insecure.SHA1.byteCount
        case .sha256: SHA256.byteCount
        }
    }

    /**
     Output label identifying the algorithm on the synthesized line.
     */
    var name: String {
        switch self {
        case .sha1: "sha1"
        case .sha256: "sha256"
        }
    }

    /**
     Raw digest of `data` — a special or code hash slot inside the CodeDirectory.
     */
    func digest(_ data: Data) -> Data {
        switch self {
        case .sha1: Data(Insecure.SHA1.hash(data: data))
        case .sha256: Data(SHA256.hash(data: data))
        }
    }

    /**
     Hex-encoded digest of `data` — the cdhash of the assembled CodeDirectory.
     */
    func hexDigest(_ data: Data) -> String {
        switch self {
        case .sha1: Insecure.SHA1.hash(data: data).hexString
        case .sha256: SHA256.hash(data: data).hexString
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
}
