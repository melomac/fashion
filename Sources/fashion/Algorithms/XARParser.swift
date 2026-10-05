import Foundation
import os
import zlib

/**
 Naive XAR archive parser for TOC extraction and hashing.
 */
enum XARParser {
    private static let logger = Logger(subsystem: "fashion", category: "xar")
    private static let XAR_MAGIC: UInt32 = 0x7861_7221 // "xar!"

    /// Upper bound on a decompressed TOC (128 MiB), to bound memory against a decompression bomb.
    static let maxUncompressedTocSize = 128 << 20

    struct XARHeader {
        let headerSize: UInt16
        let version: UInt16
        let compressedTocLength: UInt64
        let uncompressedTocLength: UInt64
        let checksumAlgorithm: UInt32
    }

    enum XARError: Error, Equatable, LocalizedError {
        case invalidMagic
        case headerTooShort
        case tocOutsideFile(offset: UInt64, length: UInt64, fileSize: Int)
        case tocTooLarge(size: UInt64)
        case tocDoesNotDecompress(size: UInt64)

        var errorDescription: String? {
            switch self {
            case .invalidMagic:
                NSLocalizedString("Not a XAR archive", comment: "File without the XAR magic")
            case .headerTooShort:
                NSLocalizedString("XAR header too short", comment: "Truncated XAR header")
            case let .tocOutsideFile(offset, length, fileSize):
                String(format: NSLocalizedString("Invalid XAR: table of contents at offset %llu with length %llu is outside the %ld-byte file", comment: "XAR table of contents past the end of the file"), offset, length, fileSize)
            case let .tocTooLarge(size):
                String(format: NSLocalizedString("Invalid XAR: table of contents declares %llu bytes uncompressed, beyond the %ld-byte limit", comment: "XAR table of contents larger than the decompression limit"), size, XARParser.maxUncompressedTocSize)
            case let .tocDoesNotDecompress(size):
                String(format: NSLocalizedString("Invalid XAR: table of contents does not decompress to its declared %llu bytes", comment: "XAR table of contents that zlib cannot decompress to its declared size"), size)
            }
        }
    }

    /**
     Parse XAR header from data.
     */
    static func parseHeader(data: Data) throws -> XARHeader {
        guard data.count >= 28 else {
            throw XARError.headerTooShort
        }

        let magic = data.withUnsafeBytes { ptr in
            UInt32(bigEndian: ptr.loadUnaligned(as: UInt32.self))
        }
        guard magic == self.XAR_MAGIC else {
            throw XARError.invalidMagic
        }

        let header = data.withUnsafeBytes { ptr in
            XARHeader(
                headerSize: UInt16(bigEndian: ptr.loadUnaligned(fromByteOffset: 4, as: UInt16.self)),
                version: UInt16(bigEndian: ptr.loadUnaligned(fromByteOffset: 6, as: UInt16.self)),
                compressedTocLength: UInt64(bigEndian: ptr.loadUnaligned(fromByteOffset: 8, as: UInt64.self)),
                uncompressedTocLength: UInt64(bigEndian: ptr.loadUnaligned(fromByteOffset: 16, as: UInt64.self)),
                checksumAlgorithm: UInt32(bigEndian: ptr.loadUnaligned(fromByteOffset: 24, as: UInt32.self)),
            )
        }

        // The XAR spec fixes the header at 28 bytes; a smaller value would place the TOC inside the header.
        guard header.headerSize >= 28 else {
            throw XARError.headerTooShort
        }

        return header
    }

    /**
     Extract and optionally decompress the TOC, then hash it.

     Nil for a file that is not a XAR archive, which its first four bytes tell before the file is mapped (mapping reads a
     whole file on a volume Foundation deems unsafe, such as a mounted disk image). Throws for one that is, but whose
     header or table of contents is malformed, rather than report nothing for it.
     */
    static func hashToc(path: String, algorithm: Algorithm, decompress: Bool) throws -> String? {
        guard try FileReader.head(path: path, count: 4) == Array("xar!".utf8) else {
            return nil
        }

        let data = try FileReader.map(path: path)
        let header = try self.parseHeader(data: data)

        // Every length below is attacker-controlled; validate in wide (UInt64) arithmetic and only
        // convert to Int once a value is known to be in range, so a crafted header cannot trap.
        let tocStart = UInt64(header.headerSize)
        let compressedLength = header.compressedTocLength
        guard
            compressedLength <= UInt64(data.count),
            tocStart <= UInt64(data.count) - compressedLength
        else {
            throw XARError.tocOutsideFile(offset: tocStart, length: compressedLength, fileSize: data.count)
        }

        // A view of the mapped file, hashed in place.
        let start = Int(tocStart)
        let compressed = data[start ..< start + Int(compressedLength)]

        let tocData: Data
        if decompress {
            // Defend against a decompression bomb: reject a declared uncompressed size beyond a generous
            // ceiling before allocating the output buffer. Real XAR tables of contents are a few MB at most.
            guard header.uncompressedTocLength <= UInt64(self.maxUncompressedTocSize) else {
                throw XARError.tocTooLarge(size: header.uncompressedTocLength)
            }
            let size = Int(header.uncompressedTocLength)
            guard
                let decompressed = decompressZlib(compressed, size: size),
                decompressed.count == size
            else {
                throw XARError.tocDoesNotDecompress(size: header.uncompressedTocLength)
            }
            tocData = decompressed

            if let xml = String(data: tocData, encoding: .utf8) {
                self.logger.debug("XAR TOC:\n\(xml, privacy: .public)")
            }
        } else {
            tocData = compressed
        }

        // Hash the TOC data
        switch algorithm {
        case .md5, .sha1, .sha256, .sha384, .sha512:
            return try CryptoDigest.hash(data: tocData, algorithm: algorithm)
        case .git:
            return try GitBlobDigest.hashData(tocData, useSHA256: false)
        case .git256:
            return try GitBlobDigest.hashData(tocData, useSHA256: true)
        case .ssdeep:
            return SSDeepBridge.hash(data: tocData)
        case .tlsh:
            return TLSHBridge.hash(data: tocData)
        case .cdhash:
            return nil
        }
    }

    // MARK: - Zlib Decompression

    private static func decompressZlib(_ data: Data, size: Int) -> Data? {
        var destLen = uLong(size)
        var dest = Data(count: size)

        let result = data.withUnsafeBytes { src in
            dest.withUnsafeMutableBytes { dst in
                guard
                    let srcBase = src.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    let dstBase = dst.baseAddress?.assumingMemoryBound(to: UInt8.self)
                else {
                    return Z_BUF_ERROR
                }
                return uncompress(dstBase, &destLen, srcBase, uLong(data.count))
            }
        }

        guard result == Z_OK else {
            return nil
        }

        return dest.prefix(Int(destLen))
    }
}
