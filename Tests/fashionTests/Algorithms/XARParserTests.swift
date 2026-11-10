@testable import fashion
import XCTest
import zlib

final class XARParserTests: XCTestCase {
    func testParseHeaderValid() throws {
        var data = Data()
        // Magic: "xar!" = 0x78617221
        data.append(contentsOf: [0x78, 0x61, 0x72, 0x21])
        // Header size: 28
        data.append(contentsOf: [0x00, 0x1c])
        // Version: 1
        data.append(contentsOf: [0x00, 0x01])
        // Compressed TOC length: 100
        data.append(contentsOf: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64])
        // Uncompressed TOC length: 200
        data.append(contentsOf: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc8])
        // Checksum algorithm: SHA-1 (1)
        data.append(contentsOf: [0x00, 0x00, 0x00, 0x01])

        let header = try XARParser.parseHeader(data: data)
        XCTAssertEqual(header.headerSize, 28)
        XCTAssertEqual(header.version, 1)
        XCTAssertEqual(header.compressedTocLength, 100)
        XCTAssertEqual(header.uncompressedTocLength, 200)
        XCTAssertEqual(header.checksumAlgorithm, 1)
    }

    func testParseHeaderInvalidMagic() throws {
        let data = Data(repeating: 0, count: 28)
        XCTAssertThrowsError(try XARParser.parseHeader(data: data))
    }

    func testParseHeaderTooShort() throws {
        let data = Data(count: 10)
        XCTAssertThrowsError(try XARParser.parseHeader(data: data))
    }

    // MARK: - Error descriptions

    func testErrorDescriptions() {
        XCTAssertNotNil(XARParser.XARError.invalidMagic.errorDescription)
        XCTAssertNotNil(XARParser.XARError.headerTooShort.errorDescription)
        XCTAssertEqual(
            XARParser.XARError.tocOutsideFile(offset: 28, length: 1000, fileSize: 28).errorDescription,
            "Invalid XAR: table of contents at offset 0x1c with length 0x3e8 is outside the 0x1c-byte file",
        )
        XCTAssertEqual(
            XARParser.XARError.tocTooLarge(limit: 1 << 30).errorDescription,
            "Invalid XAR: table of contents inflates past the 1073741824-byte limit",
        )
        XCTAssertEqual(
            XARParser.XARError.tocDoesNotDecompress(size: 2000).errorDescription,
            "Invalid XAR: table of contents does not inflate to its end, declared 2000 bytes",
        )
    }

    // MARK: - hashToc

    func testHashTocNotXARReturnsNil() throws {
        let file = try File(data: Data("not a xar file, needs enough bytes to be meaningful padding here".utf8))

        XCTAssertNil(try XARParser.hashToc(file, algorithm: .sha256, decompress: false))
    }

    /**
     The magic makes it a XAR archive: a header cut short is an error, not a file to skip.
     */
    func testHashTocShortArchiveThrows() throws {
        let file = try File(data: Data("xar!\u{0}\u{1c}".utf8))

        XCTAssertThrowsError(try XARParser.hashToc(file, algorithm: .sha256, decompress: false)) { error in
            XCTAssertEqual(error as? XARParser.XARError, .headerTooShort)
        }
    }

    /**
     Valid header but TOC extends past end of data
     */
    func testHashTocCompressedTocTruncatedThrows() throws {
        var data = Data()
        data.append(contentsOf: [0x78, 0x61, 0x72, 0x21]) // magic
        data.append(contentsOf: [0x00, 0x1c]) // header size: 28
        data.append(contentsOf: [0x00, 0x01]) // version
        data.append(contentsOf: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xe8]) // compressed TOC: 1000
        data.append(contentsOf: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0xd0]) // uncompressed TOC: 2000
        data.append(contentsOf: [0x00, 0x00, 0x00, 0x01]) // checksum

        XCTAssertThrowsError(try XARParser.hashToc(File(data: data), algorithm: .sha256, decompress: false)) { error in
            XCTAssertEqual(error as? XARParser.XARError, .tocOutsideFile(offset: 28, length: 1000, fileSize: 28))
        }
    }

    /**
     The table is hashed as stored, whatever uncompressed size the header declares.
     */
    func testHashTocUncompressedMode() throws {
        let toc = Data("fake-toc-data".utf8)
        let file = try File(data: xarArchive(toc: toc, size: 0))

        let result = try XARParser.hashToc(file, algorithm: .sha256, decompress: false)
        XCTAssertNotNil(result)
        XCTAssertEqual(result, try ByteHash.sha256.digest(toc))
    }

    func testParseHeaderRejectsUndersizedHeaderSize() throws {
        var data = Data()
        data.append(contentsOf: [0x78, 0x61, 0x72, 0x21]) // magic
        data.append(contentsOf: [0x00, 0x08]) // header size: 8 (< 28)
        data.append(contentsOf: [0x00, 0x01]) // version
        data.append(Data(count: 20))

        XCTAssertThrowsError(try XARParser.parseHeader(data: data))
    }

    /**
     compressedTocLength = UInt64.max would trap on Int(...) before the range check; must throw instead.
     */
    func testHashTocHugeCompressedLengthThrows() throws {
        var data = Data()
        data.append(contentsOf: [0x78, 0x61, 0x72, 0x21]) // magic
        data.append(contentsOf: [0x00, 0x1c]) // header size: 28
        data.append(contentsOf: [0x00, 0x01]) // version
        data.append(contentsOf: [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]) // compressed TOC: UInt64.max
        data.append(contentsOf: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]) // uncompressed TOC
        data.append(contentsOf: [0x00, 0x00, 0x00, 0x01]) // checksum

        XCTAssertThrowsError(try XARParser.hashToc(File(data: data), algorithm: .sha256, decompress: false)) { error in
            XCTAssertEqual(error as? XARParser.XARError, .tocOutsideFile(offset: 28, length: .max, fileSize: 28))
        }
    }

    /**
     A table of contents that inflates past the limit, a byte more of zeros, is refused as it inflates, whatever the
     header declares of it, 22 bytes here.
     */
    func testHashTocDecompressionBombThrows() throws {
        let file = try File(data: xarArchive(toc: deflate(Data(count: XARParser.maxUncompressedTocSize + 1)), size: 22))

        XCTAssertThrowsError(try XARParser.hashToc(file, algorithm: .sha256, decompress: true)) { error in
            XCTAssertEqual(error as? XARParser.XARError, .tocTooLarge(limit: XARParser.maxUncompressedTocSize))
        }
        // The compressed TOC itself is still hashed without --decompress.
        XCTAssertNotNil(try XARParser.hashToc(file, algorithm: .sha256, decompress: false))
    }

    func testHashTocMissingFileThrows() {
        XCTAssertThrowsError(try XARParser.hashToc(File(path: "/tmp/fashion-nonexistent-\(UUID())"), algorithm: .sha256, decompress: false))
    }

    func testHashTocDecompressMode() throws {
        let toc = Data("<xar><toc></toc></xar>".utf8)
        let file = try File(data: xarArchive(toc: deflate(toc), size: toc.count))

        let result = try XARParser.hashToc(file, algorithm: .sha256, decompress: true)
        XCTAssertNotNil(result)
        XCTAssertEqual(result, try ByteHash.sha256.digest(toc))

        // As zlib's uncompress does: the declared range may run past the end of the stream.
        let trailing = try File(data: xarArchive(toc: deflate(toc) + Data(repeating: 0xff, count: 100), size: toc.count))
        XCTAssertEqual(try XARParser.hashToc(trailing, algorithm: .sha256, decompress: true), try ByteHash.sha256.digest(toc))
    }

    /**
     libxar never reads the length the header declares for the table of contents, inflating it as a stream to its
     end, and `xar` lists an archive whatever the field says: so does this, off by one, by far, or zero.
     */
    func testHashTocIgnoresTheDeclaredLengthAsLibxarDoes() throws {
        let toc = Data("<xar><toc></toc></xar>".utf8)
        for size in [toc.count + 1, toc.count + 999, 0, Int(UInt32.max)] {
            let file = try File(data: xarArchive(toc: deflate(toc), size: size))
            XCTAssertEqual(try XARParser.hashToc(file, algorithm: .sha256, decompress: true), try ByteHash.sha256.digest(toc), "\(size)")
        }
    }

    // MARK: - Streaming inflate

    /**
     Stored blocks keep the table as large compressed as it is inflated, several reads long.
     */
    func testDecompressStreamsAcrossChunks() throws {
        let toc = Data((0 ..< File.chunkSize * 3 + 123).map { UInt8(truncatingIfNeeded: $0 &* 31 &+ $0 >> 9) })
        let file = try File(data: xarArchive(toc: deflate(toc, level: 0), size: toc.count))

        XCTAssertEqual(try XARParser.hashToc(file, algorithm: .sha256, decompress: true), try ByteHash.sha256.digest(toc))
    }

    /**
     A table whose first chunk of input inflates to a chunk of output exactly is read on. The input and the room
     for what it makes then run out together: the call made once there is room again has nothing to read and
     nothing to write, which zlib reports as no progress. That is no end of the stream, and the next chunk is read.

     The stream is made by hand: a run of spaces packed and flushed, then stored blocks sized to fill the first
     chunk of each side to the byte, then a last stored block.
     */
    func testDecompressGoesOnWhenInputAndRoomRunOutTogether() throws {
        let chunk = File.chunkSize
        /// `data` as stored blocks, none of them the stream's last, each of `size` bytes at most.
        func stored(_ data: Data, size: Int, final: Bool = false) -> Data {
            var blocks = Data()
            var rest = data[...]
            repeat {
                let block = rest.prefix(size)
                rest = rest.dropFirst(block.count)
                blocks.append(final && rest.isEmpty ? 1 : 0)
                blocks.append(contentsOf: [UInt8(block.count & 0xff), UInt8(block.count >> 8), UInt8(~block.count & 0xff), UInt8((~block.count >> 8) & 0xff)])
                blocks += block
            } while !rest.isEmpty
            return blocks
        }
        /// `data` packed as a raw deflate stream, flushed to a byte and not ended.
        func packed(_ data: Data) -> Data {
            var stream = z_stream()
            XCTAssertEqual(deflateInit2_(&stream, 9, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY, ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size)), Z_OK)
            defer {
                deflateEnd(&stream)
            }
            var output = Data(count: Int(deflateBound(&stream, uLong(data.count))) + 16)
            let count = output.count
            data.withUnsafeBytes { source in
                output.withUnsafeMutableBytes { destination in
                    stream.next_in = UnsafeMutablePointer(mutating: source.baseAddress!.assumingMemoryBound(to: Bytef.self))
                    stream.avail_in = uInt(data.count)
                    stream.next_out = destination.baseAddress!.assumingMemoryBound(to: Bytef.self)
                    stream.avail_out = uInt(count)
                    XCTAssertEqual(deflate(&stream, Z_SYNC_FLUSH), Z_OK)
                }
            }
            return output.prefix(Int(stream.total_out))
        }

        // The spaces pack to a few bytes: stored blocks of their length less what they packed to, five bytes of
        // header each, bring the input and the output to the chunk's end together.
        var spaces = 4096
        var head = packed(Data(repeating: 0x20, count: spaces))
        while (spaces - 2 - head.count) % 5 != 0 {
            spaces += 1
            head = packed(Data(repeating: 0x20, count: spaces))
        }
        let blocks = (spaces - 2 - head.count) / 5
        let filler = Data(repeating: UInt8(ascii: "x"), count: chunk - spaces)
        let fill = stored(filler, size: (filler.count + blocks - 1) / blocks)
        XCTAssertEqual(2 + head.count + fill.count, chunk, "the first chunk of input")
        let tail = Data(repeating: UInt8(ascii: "y"), count: 1000)
        let plain = Data(repeating: 0x20, count: spaces) + filler + tail
        var toc = Data([0x78, 0x01]) + head + fill + stored(tail, size: 0xffff, final: true)
        toc.appendUInt32BE(plain.withUnsafeBytes { UInt32(adler32(1, $0.baseAddress!.assumingMemoryBound(to: Bytef.self), uInt(plain.count))) })

        let file = try File(data: xarArchive(toc: toc, size: plain.count))
        XCTAssertEqual(try XARParser.hashToc(file, algorithm: .sha256, decompress: true), try ByteHash.sha256.digest(plain))
    }

    /**
     The declared range runs two chunks past the stream, which ends in the first: the rest is not read, so the
     table still decompresses once the file no longer holds it.
     */
    func testDecompressStopsReadingAtTheEndOfTheStream() throws {
        let toc = Data("<xar><toc></toc></xar>".utf8)
        let url = FileManager.default.temporaryDirectory / "fashion-xar-stream-end-\(UUID())"
        try xarArchive(toc: deflate(toc) + Data(count: File.chunkSize * 2), size: toc.count).write(to: url)
        defer {
            try? FileManager.default.removeItem(at: url)
        }
        let file = try File(path: url.path())
        XCTAssertEqual(truncate(url.path(), off_t(28 + File.chunkSize)), 0)

        XCTAssertEqual(try XARParser.hashToc(file, algorithm: .sha256, decompress: true), try ByteHash.sha256.digest(toc))
    }

    /**
     A table declared empty inflates to what it holds, as libxar reads it: nothing, a byte, two.
     */
    func testDecompressToWhatTheStreamHolds() throws {
        for content in [Data(), Data("x".utf8), Data("xy".utf8)] {
            let file = try File(data: xarArchive(toc: deflate(content), size: 0))
            XCTAssertEqual(try XARParser.hashToc(file, algorithm: .sha256, decompress: true), try ByteHash.sha256.digest(content))
        }
    }
}
