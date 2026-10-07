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
            "Invalid XAR: table of contents at offset 28 with length 1000 is outside the 28-byte file",
        )
        XCTAssertEqual(
            XARParser.XARError.tocTooLarge(size: 1 << 30).errorDescription,
            "Invalid XAR: table of contents declares 1073741824 bytes uncompressed, beyond the 134217728-byte limit",
        )
        XCTAssertEqual(
            XARParser.XARError.tocDoesNotDecompress(size: 2000).errorDescription,
            "Invalid XAR: table of contents does not decompress to its declared 2000 bytes",
        )
    }

    // MARK: - hashToc

    /**
     A XAR archive holding `toc` as its table of contents, declared `size` bytes uncompressed, then `trailer`.
     */
    private func archive(toc: Data, size: Int, trailer: Data = Data()) -> Data {
        var data = Data("xar!".utf8)
        data.append(contentsOf: [0x00, 0x1c, 0x00, 0x01]) // header size 28, version 1
        data.appendUInt64BE(UInt64(toc.count))
        data.appendUInt64BE(UInt64(size))
        data.appendUInt32BE(1) // checksum algorithm
        return data + toc + trailer
    }

    private func deflate(_ data: Data, level: Int32 = Z_DEFAULT_COMPRESSION) -> Data {
        var length = compressBound(uLong(data.count))
        var compressed = Data(count: Int(length))
        let status = data.withUnsafeBytes { source in
            compressed.withUnsafeMutableBytes { destination in
                compress2(destination.baseAddress!.assumingMemoryBound(to: Bytef.self), &length, source.baseAddress?.assumingMemoryBound(to: Bytef.self), uLong(data.count), level)
            }
        }
        XCTAssertEqual(status, Z_OK)
        return compressed.prefix(Int(length))
    }

    func testHashTocNotXARReturnsNil() throws {
        let file = try File(data: Data("not a xar file, needs enough bytes to be meaningful padding here".utf8))

        XCTAssertNil(try XARParser.hashToc(file, algorithm: .sha256, decompress: false))
    }

    func testHashTocShortArchiveThrows() throws {
        // The magic makes it a XAR archive: a header cut short is an error, not a file to skip.
        let file = try File(data: Data("xar!\u{0}\u{1c}".utf8))

        XCTAssertThrowsError(try XARParser.hashToc(file, algorithm: .sha256, decompress: false)) { error in
            XCTAssertEqual(error as? XARParser.XARError, .headerTooShort)
        }
    }

    func testHashTocCompressedTocTruncatedThrows() throws {
        // Valid header but TOC extends past end of data
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

    func testHashTocUncompressedMode() throws {
        // The table is hashed as stored, whatever uncompressed size the header declares.
        let toc = Data("fake-toc-data".utf8)
        let file = try File(data: self.archive(toc: toc, size: 0))

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

    func testHashTocHugeCompressedLengthThrows() throws {
        // compressedTocLength = UInt64.max would trap on Int(...) before the range check; must throw instead.
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

    func testHashTocDecompressionBombThrows() throws {
        // A tiny compressed TOC claiming a huge uncompressed size must be rejected before allocation.
        let toc = Data("<xar><toc></toc></xar>".utf8)
        let file = try File(data: self.archive(toc: self.deflate(toc), size: XARParser.maxUncompressedTocSize + 1)) // one past the cap

        XCTAssertThrowsError(try XARParser.hashToc(file, algorithm: .sha256, decompress: true)) { error in
            XCTAssertEqual(error as? XARParser.XARError, .tocTooLarge(size: UInt64(XARParser.maxUncompressedTocSize + 1)))
        }
        // The compressed TOC itself is still hashed without --decompress.
        XCTAssertNotNil(try XARParser.hashToc(file, algorithm: .sha256, decompress: false))
    }

    func testHashTocMissingFileThrows() {
        XCTAssertThrowsError(try XARParser.hashToc(File(path: "/tmp/fashion-nonexistent-\(UUID())"), algorithm: .sha256, decompress: false))
    }

    func testHashTocDecompressMode() throws {
        let toc = Data("<xar><toc></toc></xar>".utf8)
        let file = try File(data: self.archive(toc: self.deflate(toc), size: toc.count))

        let result = try XARParser.hashToc(file, algorithm: .sha256, decompress: true)
        XCTAssertNotNil(result)
        XCTAssertEqual(result, try ByteHash.sha256.digest(toc))

        // As zlib's uncompress does: the declared range may run past the end of the stream.
        let trailing = try File(data: self.archive(toc: self.deflate(toc) + Data(repeating: 0xff, count: 100), size: toc.count))
        XCTAssertEqual(try XARParser.hashToc(trailing, algorithm: .sha256, decompress: true), try ByteHash.sha256.digest(toc))
    }

    func testHashTocDecompressSizeMismatchThrows() throws {
        // The header declares more than the table inflates to.
        let toc = Data("<xar><toc></toc></xar>".utf8)
        let file = try File(data: self.archive(toc: self.deflate(toc), size: toc.count + 999))

        XCTAssertThrowsError(try XARParser.hashToc(file, algorithm: .sha256, decompress: true), "decompressed size must match the header") { error in
            XCTAssertEqual(error as? XARParser.XARError, .tocDoesNotDecompress(size: UInt64(toc.count + 999)))
        }
    }

    // MARK: - Streaming inflate

    func testDecompressStreamsAcrossChunks() throws {
        // Stored blocks keep the table as large compressed as it is inflated, several reads long.
        let toc = Data((0 ..< File.chunkSize * 3 + 123).map { UInt8(truncatingIfNeeded: $0 &* 31 &+ $0 >> 9) })
        let file = try File(data: self.archive(toc: self.deflate(toc, level: 0), size: toc.count))

        XCTAssertEqual(try XARParser.hashToc(file, algorithm: .sha256, decompress: true), try ByteHash.sha256.digest(toc))
    }

    func testDecompressStopsReadingAtTheEndOfTheStream() throws {
        // The declared range runs two chunks past the stream, which ends in the first: the rest is not read, so the
        // table still decompresses once the file no longer holds it.
        let toc = Data("<xar><toc></toc></xar>".utf8)
        let url = FileManager.default.temporaryDirectory / "fashion-xar-stream-end-\(UUID())"
        try self.archive(toc: self.deflate(toc) + Data(count: File.chunkSize * 2), size: toc.count).write(to: url)
        defer {
            try? FileManager.default.removeItem(at: url)
        }
        let file = try File(path: url.path())
        XCTAssertEqual(truncate(url.path(), off_t(28 + File.chunkSize)), 0)

        XCTAssertEqual(try XARParser.hashToc(file, algorithm: .sha256, decompress: true), try ByteHash.sha256.digest(toc))
    }

    func testDecompressToNothingAsUncompressDoes() throws {
        // uncompress gives an empty output a 1-byte buffer and reports nothing of it: a stream of up to one byte
        // inflates to an empty table, a longer one does not decompress.
        for (content, decompresses) in [(Data(), true), (Data("x".utf8), true), (Data("xy".utf8), false)] {
            let file = try File(data: self.archive(toc: self.deflate(content), size: 0))
            if decompresses {
                XCTAssertEqual(try XARParser.hashToc(file, algorithm: .sha256, decompress: true), try ByteHash.sha256.digest(Data()))
            } else {
                XCTAssertThrowsError(try XARParser.hashToc(file, algorithm: .sha256, decompress: true)) { error in
                    XCTAssertEqual(error as? XARParser.XARError, .tocDoesNotDecompress(size: 0))
                }
            }
        }
    }
}
