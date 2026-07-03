import CryptoKit
import Foundation
import MachO

/**
 Compute CDHash (Code Directory Hash) for each slice of a Mach-O binary.

 A signed slice yields its embedded cdhash(es). An unsigned slice yields a synthesized ad-hoc cdhash:
 the identity `syspolicyd` computes for unsigned code and notarization revocation,
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
    static func hash(path: String, exact: Bool = false) -> [SliceResult] {
        guard let data = try? FileReader.map(path: path) else {
            return []
        }

        switch MachOParser.open(data: data) {
        case let .fat(archs):
            return archs.flatMap { arch -> [SliceResult] in
                guard let slice = MachOSlice(MachOParser.sliceData(fileData: data, arch: arch)) else {
                    return []
                }
                let name = MachOParser.archName(cpuType: arch.cpuType, cpuSubtype: arch.cpuSubtype)
                return self.results(for: slice, arch: name, exact: exact)
            }
        case .thin:
            guard let slice = MachOSlice(data) else {
                return []
            }
            return self.results(for: slice, arch: nil, exact: exact)
        case .notMachO:
            return []
        }
    }

    /**
     Compute CDHash from raw Mach-O data (single thin slice).
     Returns the strongest embedded cdhash, or the ad-hoc cdhash when unsigned. Nil for non-Mach-O input.
     */
    static func hash(data: Data, exact: Bool = false) -> String? {
        MachOSlice(data)?.codeDirectoryHashes(exact: exact).first?.hash
    }

    // MARK: - Private

    /**
     One SliceResult per code directory. The hash type is only set when a slice carries several directories.
     */
    private static func results(for slice: MachOSlice, arch: String?, exact: Bool) -> [SliceResult] {
        let directories = slice.codeDirectoryHashes(exact: exact)
        let ambiguous = directories.count > 1

        return directories.map { cd in
            SliceResult(hash: cd.hash, arch: arch, type: ambiguous ? cd.type : nil, adhoc: cd.adhoc)
        }
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
     Digest every code directory of a signed slice, strongest first per hashRank — the head is the kernel-enforced cdhash.
     An unsigned slice returns its synthesized ad-hoc cdhashes instead (SHA-256 then SHA-1).
     */
    func codeDirectoryHashes(exact: Bool) -> [CodeDirectoryHash] {
        // Only a slice with no signature at all falls back to the ad-hoc identity: a signed slice with an
        // unreadable signature yields nothing, as the ad-hoc cdhash only describes unsigned code.
        if let sigRange = self.codeSignatureRange() {
            return self.embeddedCodeDirectories(in: sigRange)
        }

        return self.adhocCDHashes(exact: exact)
    }

    // MARK: - Embedded signature

    private func embeddedCodeDirectories(in sigRange: Range<Int>) -> [CodeDirectoryHash] {
        let signature = Data(self.data[sigRange])

        return Self.parseCodeDirectories(signature: signature)
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
    private static func parseCodeDirectories(signature: Data) -> [EmbeddedCodeDirectory] {
        guard signature.count >= 12 else {
            return []
        }

        let (magic, _, count) = signature.withUnsafeBytes { ptr -> (UInt32, UInt32, UInt32) in
            (
                UInt32(bigEndian: ptr.loadUnaligned(as: UInt32.self)),
                UInt32(bigEndian: ptr.loadUnaligned(fromByteOffset: 4, as: UInt32.self)),
                UInt32(bigEndian: ptr.loadUnaligned(fromByteOffset: 8, as: UInt32.self)),
            )
        }

        guard magic == self.csmagicEmbeddedSignature else {
            return []
        }

        var results: [EmbeddedCodeDirectory] = []
        let indexBase = 12

        for i in 0 ..< Int(count) {
            let entryOffset = indexBase + i * 8
            guard entryOffset + 8 <= signature.count else {
                break
            }

            let (slotType, blobOffset) = signature.withUnsafeBytes { ptr -> (UInt32, UInt32) in
                (
                    UInt32(bigEndian: ptr.loadUnaligned(fromByteOffset: entryOffset, as: UInt32.self)),
                    UInt32(bigEndian: ptr.loadUnaligned(fromByteOffset: entryOffset + 4, as: UInt32.self)),
                )
            }

            guard slotType == self.csslotCodeDirectory || (slotType >= self.csslotAlternateBase && slotType < self.csslotAlternateLimit) else {
                continue
            }

            let off = Int(blobOffset)
            guard off + 12 <= signature.count else {
                continue
            }

            let (blobMagic, blobLength) = signature.withUnsafeBytes { ptr -> (UInt32, UInt32) in
                (
                    UInt32(bigEndian: ptr.loadUnaligned(fromByteOffset: off, as: UInt32.self)),
                    UInt32(bigEndian: ptr.loadUnaligned(fromByteOffset: off + 4, as: UInt32.self)),
                )
            }

            guard blobMagic == self.csmagicCodeDirectory else {
                continue
            }

            let blobEnd = off + Int(blobLength)
            guard blobEnd <= signature.count else {
                continue
            }

            // hashType is at offset 37 in the CodeDirectory structure; require it to lie within the blob's
            // own declared length, not merely within the signature, so a short blob cannot borrow a byte
            // from the next one.
            guard off + 38 <= blobEnd else {
                continue
            }

            let hashType = signature.withUnsafeBytes { ptr -> UInt8 in
                ptr.loadUnaligned(fromByteOffset: off + 37, as: UInt8.self)
            }

            results.append(EmbeddedCodeDirectory(data: Data(signature[off ..< blobEnd]), hashType: hashType))
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
     then the SHA-1 cdhash (`CandidateCDHashFull sha1`). While we print the full hash, we can match the
     truncated 20-byte cdhash too. Code covers the whole slice, or its logical extent when `exact` is set.
     */
    private func adhocCDHashes(exact: Bool) -> [CodeDirectoryHash] {
        let codeLimit = exact ? self.logicalEnd() : self.data.count

        // The synthesized CodeDirectory carries the 32-bit codeLimit field; a slice >= 4 GiB would need codeLimit64.
        guard codeLimit > 0, codeLimit <= UInt32.max else {
            return []
        }

        // Code-signing page size follows the target architecture: 16 KiB on arm64, 4 KiB elsewhere.
        let pageSizeLog: UInt8 = self.cpuType == CPU_TYPE_ARM64 ? 14 : 12

        return [AdhocHashType.sha256, .sha1].map { hashType in
            let cd = self.synthesizeCodeDirectory(codeLimit: codeLimit, pageSizeLog: pageSizeLog, hashType: hashType)
            return CodeDirectoryHash(hash: hashType.hexDigest(cd), type: hashType.name, adhoc: true)
        }
    }

    private func synthesizeCodeDirectory(codeLimit: Int, pageSizeLog: UInt8, hashType: AdhocHashType) -> Data {
        let pageSize = 1 << Int(pageSizeLog)
        let hashSize = hashType.digestSize
        let nSpecialSlots = 2
        let nCodeSlots = (codeLimit + pageSize - 1) / pageSize

        let identifier = Data("ADHOC".utf8) + Data([0])
        let headerSize = 0x58 // CodeDirectory v0x20400 fixed header (through execSegFlags)
        let identOffset = headerSize
        let hashOffset = identOffset + identifier.count + nSpecialSlots * hashSize
        let length = hashOffset + nCodeSlots * hashSize

        let exec = self.execSegment()

        var cd = Data(capacity: length)
        cd.appendBigEndian(Self.csmagicCodeDirectory) // magic
        cd.appendBigEndian(UInt32(length)) // length
        cd.appendBigEndian(Self.cdVersion) // version
        cd.appendBigEndian(Self.csAdhocFlag) // flags
        cd.appendBigEndian(UInt32(hashOffset)) // hashOffset
        cd.appendBigEndian(UInt32(identOffset)) // identOffset
        cd.appendBigEndian(UInt32(nSpecialSlots)) // nSpecialSlots
        cd.appendBigEndian(UInt32(nCodeSlots)) // nCodeSlots
        cd.appendBigEndian(UInt32(codeLimit)) // codeLimit
        cd.append(contentsOf: [UInt8(hashSize), hashType.csHashType, 0, pageSizeLog]) // hashSize, hashType, platform, pageSize
        cd.appendBigEndian(UInt32(0)) // spare2
        cd.appendBigEndian(UInt32(0)) // scatterOffset
        cd.appendBigEndian(UInt32(0)) // teamOffset
        cd.appendBigEndian(UInt32(0)) // spare3
        cd.appendBigEndian(UInt64(0)) // codeLimit64
        cd.appendBigEndian(exec.base) // execSegBase
        cd.appendBigEndian(exec.limit) // execSegLimit
        cd.appendBigEndian(exec.flags) // execSegFlags
        cd.append(identifier)

        cd.append(hashType.digest(Self.emptyRequirementsBlob)) // special slot -2: requirements
        cd.append(Data(repeating: 0, count: hashSize)) // special slot -1: Info.plist (absent)

        var offset = 0
        while offset < codeLimit {
            let end = min(offset + pageSize, codeLimit)
            cd.append(hashType.digest(self.data.subdata(in: offset ..< end)))
            offset += pageSize
        }

        return cd
    }

    /**
     The empty requirements blob codesign embeds; special slot -2 is its digest under the directory's hash type.
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
    private static let csmagicCodeDirectory: UInt32 = 0xfade_0c02
    private static let csmagicRequirements: UInt32 = 0xfade_0c01

    private static let csslotCodeDirectory: UInt32 = 0
    private static let csslotAlternateBase: UInt32 = 0x1000
    private static let csslotAlternateLimit: UInt32 = 0x1005

    private static let csHashTypeSHA1: UInt8 = 1
    private static let csHashTypeSHA256: UInt8 = 2
    private static let csHashTypeSHA256Truncated: UInt8 = 3
    private static let csHashTypeSHA384: UInt8 = 4

    // CodeDirectory version codesign emits for a bare ad-hoc binary (includes the execSeg fields), and the CS_ADHOC flag.
    private static let cdVersion: UInt32 = 0x0002_0400
    private static let csAdhocFlag: UInt32 = 0x0000_0002
}

// MARK: -

private struct EmbeddedCodeDirectory {
    let data: Data
    let hashType: UInt8
}

/**
 A hash algorithm used to synthesize an ad-hoc CodeDirectory. codesign builds one directory per algorithm;
 each carries hash slots of that algorithm's width and yields its own cdhash, digested under the same algorithm.
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
