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
                "Not a XAR archive"
            case .headerTooShort:
                "XAR header too short"
            case let .tocOutsideFile(offset, length, fileSize):
                "Invalid XAR: table of contents at offset \(offset) with length \(length) is outside the \(fileSize)-byte file"
            case let .tocTooLarge(size):
                "Invalid XAR: table of contents declares \(size) bytes uncompressed, beyond the \(XARParser.maxUncompressedTocSize)-byte limit"
            case let .tocDoesNotDecompress(size):
                "Invalid XAR: table of contents does not decompress to its declared \(size) bytes"
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
     Hash the table of contents, compressed as stored or inflated.

     Nil for a file that is not a XAR archive, which its first four bytes tell. Throws for one that is, but whose header
     or table of contents is malformed, rather than report nothing for it. The compressed table streams from the file;
     inflated, it streams through zlib, so memory holds no more than the declared uncompressed size, itself bounded.
     */
    static func hashToc(_ file: File, algorithm: ByteHash, decompress: Bool) throws -> String? {
        let head = try file.read(at: 0, count: min(file.size, 28))
        guard head.prefix(4) == Data("xar!".utf8) else {
            return nil
        }
        let header = try self.parseHeader(data: head)

        // Every length below is attacker-controlled; validate in wide (UInt64) arithmetic and only
        // convert to Int once a value is known to be in range, so a crafted header cannot trap.
        let tocStart = UInt64(header.headerSize)
        let compressedLength = header.compressedTocLength
        guard
            compressedLength <= UInt64(file.size),
            tocStart <= UInt64(file.size) - compressedLength
        else {
            throw XARError.tocOutsideFile(offset: tocStart, length: compressedLength, fileSize: file.size)
        }
        let toc = Int(tocStart) ..< Int(tocStart + compressedLength)

        guard decompress else {
            return try algorithm.digest(file, range: toc)
        }

        // Defend against a decompression bomb: reject a declared uncompressed size beyond a generous
        // ceiling before allocating the output buffer. Real XAR tables of contents are a few MB at most.
        guard header.uncompressedTocLength <= UInt64(self.maxUncompressedTocSize) else {
            throw XARError.tocTooLarge(size: header.uncompressedTocLength)
        }
        guard let tocData = try self.inflate(file, range: toc, size: Int(header.uncompressedTocLength)) else {
            throw XARError.tocDoesNotDecompress(size: header.uncompressedTocLength)
        }
        if let xml = String(data: tocData, encoding: .utf8) {
            self.logger.debug("XAR TOC:\n\(xml, privacy: .public)")
        }

        return try algorithm.digest(tocData)
    }

    // MARK: - Zlib Decompression

    /**
     The `size` bytes the zlib stream at `range` of the file inflates to, as zlib's `uncompress` would decompress the
     range from memory: nil unless the stream ends within the range, having filled exactly `size` bytes. Bytes after the
     end of the stream are ignored, and an empty input is refused. An empty output gets a 1-byte buffer, as in
     `uncompress`, which reports nothing of what lands there.
     */
    private static func inflate(_ file: File, range: Range<Int>, size: Int) throws -> Data? {
        guard !range.isEmpty else {
            return nil
        }

        var stream = z_stream()
        guard inflateInit_(&stream, ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size)) == Z_OK else {
            return nil
        }
        defer {
            inflateEnd(&stream)
        }

        var output = Data(count: max(size, 1))
        var status = Z_OK
        try output.withUnsafeMutableBytes { buffer in
            stream.next_out = buffer.baseAddress?.assumingMemoryBound(to: Bytef.self)
            stream.avail_out = uInt(buffer.count)
            // Once the stream ends or fails, the rest of the range is not part of it, and is not read.
            var offset = range.lowerBound
            while status == Z_OK, offset < range.upperBound {
                let chunk = try file.read(at: offset, count: min(File.chunkSize, range.upperBound - offset))
                offset += chunk.count
                chunk.withUnsafeBytes { bytes in
                    stream.next_in = UnsafeMutablePointer(mutating: bytes.baseAddress?.assumingMemoryBound(to: Bytef.self))
                    stream.avail_in = uInt(bytes.count)
                    repeat {
                        status = zlib.inflate(&stream, Z_NO_FLUSH)
                    } while status == Z_OK && stream.avail_in > 0
                }
            }
        }

        guard
            status == Z_STREAM_END,
            size == 0 || stream.total_out == size
        else {
            return nil
        }
        return output.prefix(size)
    }
}
