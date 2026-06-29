import CryptoKit
import Foundation
import MachO

/** Compute CDHash (Code Directory Hash) from Mach-O code signatures. */
enum CDHash {
    struct SliceResult {
        let hash: String
        let arch: String?
        let type: String?
    }

    /**
     Compute CDHash for each Mach-O slice in a file.
     Thin binaries return a single result with nil arch.
     Fat binaries return one result per signed slice.
     */
    static func hash(path: String) -> [SliceResult] {
        guard let data = try? FileReader.map(path: path) else {
            return []
        }

        switch MachOParser.open(data: data) {
        case let .fat(archs):
            var results: [SliceResult] = []
            for arch in archs {
                let slice = MachOParser.sliceData(fileData: data, arch: arch)
                let name = MachOParser.archName(cpuType: arch.cpuType, cpuSubtype: arch.cpuSubtype)
                results.append(contentsOf: self.sliceResults(machOData: slice, arch: name))
            }
            return results
        case .thin:
            return self.sliceResults(machOData: data, arch: nil)
        case .notMachO:
            return []
        }
    }

    /**
     Compute CDHash from raw Mach-O data (single thin slice).
     */
    static func hash(data: Data) -> String? {
        self.computeCDHash(machOData: data)
    }

    // MARK: - Private

    // Code signing magic (big-endian on disk)
    private static let csmagicEmbeddedSignature: UInt32 = 0xfade_0cc0
    private static let csmagicCodeDirectory: UInt32 = 0xfade_0c02

    // CodeDirectory slot types
    private static let csslotCodeDirectory: UInt32 = 0
    private static let csslotAlternateBase: UInt32 = 0x1000
    private static let csslotAlternateLimit: UInt32 = 0x1005

    // Hash type constants from xnu cs_blobs.h (CS_HASHTYPE_*)
    private static let csHashTypeSHA1: UInt8 = 1
    private static let csHashTypeSHA256: UInt8 = 2
    private static let csHashTypeSHA256Truncated: UInt8 = 3
    private static let csHashTypeSHA384: UInt8 = 4

    // Selection order among code directories, mirroring xnu (bsd/kern/ubc_subr.c).
    // Index is the rank — higher is better, 0 => don't use at all.
    private static let hashPriorities: [UInt8] = [
        csHashTypeSHA1,
        csHashTypeSHA256Truncated,
        csHashTypeSHA256,
        csHashTypeSHA384,
    ]

    private static func hashRank(_ hashType: UInt8) -> Int {
        self.hashPriorities.firstIndex(of: hashType).map { $0 + 1 } ?? 0
    }

    private struct CodeDirectoryInfo {
        let data: Data
        let hashType: UInt8
    }

    /**
     One SliceResult per code directory. The hash type is only set when a slice carries several directories.
     */
    private static func sliceResults(machOData: Data, arch: String?) -> [SliceResult] {
        let candidates = self.computeCDHashes(machOData: machOData)
        let ambiguous = candidates.count > 1
        return candidates.map {
            SliceResult(hash: $0.hash, arch: arch, type: ambiguous ? $0.type : nil)
        }
    }

    private static func computeCDHash(machOData: Data) -> String? {
        self.computeCDHashes(machOData: machOData).first?.hash
    }

    /**
     Digest every code directory of a slice, strongest first per hashPriorities — the head is the kernel-enforced cdhash.
     */
    private static func computeCDHashes(machOData: Data) -> [(hash: String, type: String)] {
        guard let sigRange = self.findCodeSignature(machOData: machOData) else {
            return []
        }

        let sigData = Data(machOData[sigRange])
        return self.findCodeDirectories(signatureData: sigData)
            .sorted { self.hashRank($0.hashType) > self.hashRank($1.hashType) }
            .compactMap { cd -> (hash: String, type: String)? in
                guard let digest = self.digestCodeDirectory(blob: cd.data, hashType: cd.hashType) else {
                    return nil
                }
                return (digest, self.typeName(cd.hashType))
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

    private static func findCodeSignature(machOData: Data) -> Range<Int>? {
        let commands = MachOParser.loadCommands(data: machOData)

        for cmd in commands where cmd.cmd == UInt32(LC_CODE_SIGNATURE) {
            guard cmd.data.count >= 16 else {
                continue
            }

            let (dataOff, dataSize) = cmd.data.withUnsafeBytes { ptr -> (UInt32, UInt32) in
                (
                    ptr.loadUnaligned(fromByteOffset: 8, as: UInt32.self),
                    ptr.loadUnaligned(fromByteOffset: 12, as: UInt32.self),
                )
            }

            let start = Int(dataOff)
            let end = start + Int(dataSize)
            guard
                start > 0,
                end > start, end <= machOData.count
            else {
                continue
            }

            return start ..< end
        }

        return nil
    }

    private static func findCodeDirectories(signatureData: Data) -> [CodeDirectoryInfo] {
        guard signatureData.count >= 12 else {
            return []
        }

        let (magic, _, count) = signatureData.withUnsafeBytes { ptr -> (UInt32, UInt32, UInt32) in
            (
                UInt32(bigEndian: ptr.loadUnaligned(as: UInt32.self)),
                UInt32(bigEndian: ptr.loadUnaligned(fromByteOffset: 4, as: UInt32.self)),
                UInt32(bigEndian: ptr.loadUnaligned(fromByteOffset: 8, as: UInt32.self)),
            )
        }

        guard magic == self.csmagicEmbeddedSignature else {
            return []
        }

        var results: [CodeDirectoryInfo] = []
        let indexBase = 12

        for i in 0 ..< Int(count) {
            let entryOffset = indexBase + i * 8
            guard entryOffset + 8 <= signatureData.count else {
                break
            }

            let (slotType, blobOffset) = signatureData.withUnsafeBytes { ptr -> (UInt32, UInt32) in
                (
                    UInt32(bigEndian: ptr.loadUnaligned(fromByteOffset: entryOffset, as: UInt32.self)),
                    UInt32(bigEndian: ptr.loadUnaligned(fromByteOffset: entryOffset + 4, as: UInt32.self)),
                )
            }

            guard slotType == self.csslotCodeDirectory || (slotType >= self.csslotAlternateBase && slotType < self.csslotAlternateLimit) else {
                continue
            }

            let off = Int(blobOffset)
            guard off + 12 <= signatureData.count else {
                continue
            }

            let (blobMagic, blobLength) = signatureData.withUnsafeBytes { ptr -> (UInt32, UInt32) in
                (
                    UInt32(bigEndian: ptr.loadUnaligned(fromByteOffset: off, as: UInt32.self)),
                    UInt32(bigEndian: ptr.loadUnaligned(fromByteOffset: off + 4, as: UInt32.self)),
                )
            }

            guard blobMagic == self.csmagicCodeDirectory else {
                continue
            }
            let blobEnd = off + Int(blobLength)
            guard blobEnd <= signatureData.count else {
                continue
            }

            // hashType is at offset 37 in CodeDirectory structure
            guard off + 38 <= signatureData.count else {
                continue
            }
            let hashType = signatureData.withUnsafeBytes { ptr -> UInt8 in
                ptr.load(fromByteOffset: off + 37, as: UInt8.self)
            }

            let blobData = Data(signatureData[off ..< blobEnd])
            results.append(CodeDirectoryInfo(data: blobData, hashType: hashType))
        }

        return results
    }

    private static func digestCodeDirectory(blob: Data, hashType: UInt8) -> String? {
        switch hashType {
        case self.csHashTypeSHA1:
            Insecure.SHA1.hash(data: blob).hexString
        case self.csHashTypeSHA256, self.csHashTypeSHA256Truncated:
            // Truncation applies to the hash slots inside the CD; the CD digest itself is plain SHA-256
            SHA256.hash(data: blob).hexString
        case self.csHashTypeSHA384:
            SHA384.hash(data: blob).hexString
        default:
            // Unknown hash types rank 0 and are filtered before selection
            nil
        }
    }
}
