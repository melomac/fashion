import Compression
import Foundation
import os

/**
 Naive XAR archive parser for TOC extraction and hashing.
 */
enum XARParser {
    private static let logger = Logger(subsystem: "fashion", category: "xar")
    private static let XAR_MAGIC: UInt32 = 0x7861_7221 // "xar!"

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
            UInt32(bigEndian: ptr.load(as: UInt32.self))
        }
        guard magic == self.XAR_MAGIC else {
            throw XARError.invalidMagic
        }

        return data.withUnsafeBytes { ptr in
            XARHeader(
                headerSize: UInt16(bigEndian: ptr.load(fromByteOffset: 4, as: UInt16.self)),
                version: UInt16(bigEndian: ptr.load(fromByteOffset: 6, as: UInt16.self)),
                compressedTocLength: UInt64(bigEndian: ptr.load(fromByteOffset: 8, as: UInt64.self)),
                uncompressedTocLength: UInt64(bigEndian: ptr.load(fromByteOffset: 16, as: UInt64.self)),
                checksumAlgorithm: UInt32(bigEndian: ptr.load(fromByteOffset: 24, as: UInt32.self)),
            )
        }
    }

    /**
     Extract and optionally decompress the TOC, then hash it.
     */
    static func hashToc(path: String, algorithm: Algorithm, decompress: Bool) throws -> String? {
        let data = try Data(contentsOf: URL(fileURLWithPath: path), options: .mappedIfSafe)

        let header: XARHeader
        do {
            header = try self.parseHeader(data: data)
        } catch is XARError {
            return nil
        }

        let tocStart = Int(header.headerSize)
        let tocEnd = tocStart + Int(header.compressedTocLength)
        guard tocEnd <= data.count else {
            return nil
        }

        let compressedToc = data[tocStart ..< tocEnd]

        let tocData: Data
        if decompress {
            guard let decompressed = decompressZlib(compressedToc, uncompressedSize: Int(header.uncompressedTocLength)) else {
                return nil
            }
            tocData = decompressed

            if let xml = String(data: tocData, encoding: .utf8) {
                self.logger.debug("XAR TOC:\n\(xml, privacy: .public)")
            }
        } else {
            tocData = Data(compressedToc)
        }

        // Hash the TOC data
        switch algorithm {
        case .md5, .sha1, .sha224, .sha256, .sha384, .sha512:
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

    /**
     Apple's `COMPRESSION_ZLIB` is raw deflate (RFC 1951).
     XAR TOCs use zlib-wrapped deflate (RFC 1950): 2-byte header + deflate + 4-byte Adler-32.
     Strip the wrapper before decompressing.
     */
    private static func decompressZlib(_ data: Data, uncompressedSize: Int) -> Data? {
        guard data.count > 6 else {
            return nil
        }
        let deflateData = data.dropFirst(2).dropLast(4)

        let sourceSize = deflateData.count
        var dest = Data(count: uncompressedSize)

        let result = deflateData.withUnsafeBytes { srcPtr -> Int in
            dest.withUnsafeMutableBytes { destPtr -> Int in
                guard
                    let srcBase = srcPtr.baseAddress,
                    let destBase = destPtr.baseAddress?.assumingMemoryBound(to: UInt8.self)
                else {
                    return -1
                }

                return compression_decode_buffer(destBase, uncompressedSize, srcBase.assumingMemoryBound(to: UInt8.self), sourceSize, nil, COMPRESSION_ZLIB)
            }
        }

        guard result > 0 else {
            return nil
        }

        return dest.prefix(result)
    }
}
