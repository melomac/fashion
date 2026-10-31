import Foundation
import os
import zlib

/**
 Naive XAR archive parser for TOC extraction and hashing.

 The archive begins with a 28-byte header, big-endian, then the table of contents, an XML document zlib-compressed
 whole, then the heap, where the TOC's own checksum comes first and the files' data after it, at the offsets the TOC
 gives from the heap's start:

 ```text
  0x0000 +-----------------------------------------------+
         | magic "xar!" (4)                              |
  0x0004 +-----------------------------------------------+
         | size (2)            | version (2)             |  size 28: where the TOC starts
  0x0008 +-----------------------------------------------+
         | toc_length_compressed (8)                     |  the TOC as stored
  0x0010 +-----------------------------------------------+
         | toc_length_uncompressed (8)                   |  the TOC inflated, which libxar does not check
  0x0018 +-----------------------------------------------+
         | cksum_alg (4)                                 |  0 none, 1 SHA-1, 2 MD5, 3 SHA-256, 4 SHA-512
  0x001c +-----------------------------------------------+
         | table of contents, zlib-compressed            |  toc_length_compressed bytes: what --xar-toc hashes,
         |                                               |  as stored or inflated with --decompress
         +-----------------------------------------------+  <- the heap starts here
         | the TOC's checksum, by cksum_alg              |  what `xar --dump-toc-cksum` prints
         | the files' data, at the TOC's offsets         |
         +-----------------------------------------------+
 ```
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
        case tocTooLarge(limit: Int)
        case tocDoesNotDecompress(size: UInt64)

        var errorDescription: String? {
            switch self {
            case .invalidMagic:
                "Not a XAR archive"
            case .headerTooShort:
                "XAR header too short"
            case let .tocOutsideFile(offset, length, fileSize):
                "Invalid XAR: table of contents at offset \(offset.hex) with length \(length.hex) is outside the \(fileSize.hex)-byte file"
            case let .tocTooLarge(limit):
                "Invalid XAR: table of contents inflates past the \(limit)-byte limit"
            case let .tocDoesNotDecompress(size):
                "Invalid XAR: table of contents does not inflate to its end, declared \(size) bytes"
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

     A digest per algorithm, with its hash; none for a file that is not a XAR archive, which its first four bytes tell.
     Throws for one that is, but whose header or table of contents is malformed, rather than report nothing for it. The
     compressed table streams from the file; inflated, it streams through zlib, so memory holds no more than the declared
     uncompressed size, itself bounded. `caveat` hears what TLSH leaves out of the table.
     */
    static func hashToc(_ file: File, algorithms: [ByteHash], decompress: Bool, caveat: (String) -> Void = { _ in }) throws -> [(hash: ByteHash, digest: String)] {
        let head = try file.read(at: 0, count: min(file.size, 28))
        guard head.prefix(4) == Data("xar!".utf8) else {
            return []
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
            return try ByteHash.digests(algorithms, file, range: toc, caveat: caveat)
        }

        // libxar inflates the table of contents as a stream and never reads the length the header declares for it.
        guard let tocData = try self.inflate(file, range: toc, limit: self.maxUncompressedTocSize) else {
            throw XARError.tocDoesNotDecompress(size: header.uncompressedTocLength)
        }
        if let xml = String(data: tocData, encoding: .utf8) {
            self.logger.debug("XAR TOC:\n\(xml, privacy: .public)")
        }

        return try ByteHash.digests(algorithms, tocData, caveat: caveat)
    }

    // MARK: - Zlib Decompression

    /**
     The bytes the zlib stream at `range` of the file inflates to, as libxar inflates a table of contents: the stream
     run to its end, whatever length the header declares, the output grown as it comes; nil unless the stream ends
     within the range, and `limit` bytes of output throw `tocTooLarge`. Bytes after the end of the stream are ignored.
     */
    private static func inflate(_ file: File, range: Range<Int>, limit: Int) throws -> Data? {
        var stream = z_stream()
        guard inflateInit_(&stream, ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size)) == Z_OK else {
            return nil
        }
        defer {
            inflateEnd(&stream)
        }

        var output = Data()
        var status = Z_OK
        // Once the stream ends or fails, the rest of the range is not part of it, and is not read.
        var offset = range.lowerBound
        while status == Z_OK, offset < range.upperBound {
            let chunk = try file.read(at: offset, count: min(File.chunkSize, range.upperBound - offset))
            offset += chunk.count
            try chunk.withUnsafeBytes { bytes in
                stream.next_in = UnsafeMutablePointer(mutating: bytes.baseAddress?.assumingMemoryBound(to: Bytef.self))
                stream.avail_in = uInt(bytes.count)
                repeat {
                    // Room for what comes, a chunk at a time, up to the limit.
                    let produced = Int(stream.total_out)
                    if produced == output.count {
                        guard produced < limit else {
                            throw XARError.tocTooLarge(limit: limit)
                        }
                        output.count = min(produced + File.chunkSize, limit)
                    }
                    status = output.withUnsafeMutableBytes { buffer in
                        stream.next_out = buffer.baseAddress!.advanced(by: produced).assumingMemoryBound(to: Bytef.self)
                        stream.avail_out = uInt(buffer.count - produced)
                        return zlib.inflate(&stream, Z_NO_FLUSH)
                    }
                } while status == Z_OK && (stream.avail_in > 0 || stream.avail_out == 0)
            }
        }

        guard status == Z_STREAM_END else {
            return nil
        }
        return output.prefix(Int(stream.total_out))
    }
}
