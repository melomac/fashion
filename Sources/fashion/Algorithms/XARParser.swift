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

    enum XARError: Error, LocalizedError {
        case invalidMagic
        case headerTooShort
        case readError

        var errorDescription: String? {
            switch self {
            case .invalidMagic: NSLocalizedString("Not a XAR archive", comment: "")
            case .headerTooShort: NSLocalizedString("XAR header too short", comment: "")
            case .readError: NSLocalizedString("Failed to read XAR data", comment: "")
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
     */
    static func hashToc(path: String, algorithm: Algorithm, decompress: Bool) throws -> String? {
        let data = try FileReader.map(path: path)

        let header: XARHeader
        do {
            header = try self.parseHeader(data: data)
        } catch is XARError {
            return nil
        }

        // Every length below is attacker-controlled; validate in wide (UInt64) arithmetic and only
        // convert to Int once a value is known to be in range, so a crafted header cannot trap.
        let tocStart = UInt64(header.headerSize)
        let compressedLength = header.compressedTocLength
        guard
            compressedLength <= UInt64(data.count),
            tocStart <= UInt64(data.count) - compressedLength
        else {
            return nil
        }

        let start = Int(tocStart)
        let compressed = data[start ..< start + Int(compressedLength)]

        let tocData: Data
        let expectedSize: Int
        if decompress {
            // Defend against a decompression bomb: reject a declared uncompressed size beyond a generous
            // ceiling before allocating the output buffer. Real XAR tables of contents are a few MB at most.
            guard header.uncompressedTocLength <= UInt64(self.maxUncompressedTocSize) else {
                return nil
            }
            let size = Int(header.uncompressedTocLength)
            guard let decompressed = decompressZlib(compressed, size: size) else {
                return nil
            }
            tocData = decompressed
            expectedSize = size

            if let xml = String(data: tocData, encoding: .utf8) {
                self.logger.debug("XAR TOC:\n\(xml, privacy: .public)")
            }
        } else {
            tocData = Data(compressed)
            expectedSize = Int(compressedLength)
        }

        guard tocData.count == expectedSize else {
            return nil
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
