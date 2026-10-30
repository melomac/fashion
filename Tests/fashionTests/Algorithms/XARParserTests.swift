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
