@testable import fashion
import XCTest

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
        XCTAssertNotNil(XARParser.XARError.readError.errorDescription)
    }

    // MARK: - hashToc

    func testHashTocNotXARReturnsNil() throws {
        let url = FileManager.default.temporaryDirectory / "fashion-notxar-\(UUID())"
        try Data("not a xar file, needs enough bytes to be meaningful padding here".utf8).write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }

        let result = try XARParser.hashToc(path: url.path(), algorithm: .sha256, decompress: false)
        XCTAssertNil(result)
    }

    func testHashTocCompressedTocTruncated() throws {
        // Valid header but TOC extends past end of data
        var data = Data()
        data.append(contentsOf: [0x78, 0x61, 0x72, 0x21]) // magic
        data.append(contentsOf: [0x00, 0x1c]) // header size: 28
        data.append(contentsOf: [0x00, 0x01]) // version
        data.append(contentsOf: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xe8]) // compressed TOC: 1000
        data.append(contentsOf: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0xd0]) // uncompressed TOC: 2000
        data.append(contentsOf: [0x00, 0x00, 0x00, 0x01]) // checksum

        let url = FileManager.default.temporaryDirectory / "fashion-xar-trunc-\(UUID())"
        try data.write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }

        let result = try XARParser.hashToc(path: url.path(), algorithm: .sha256, decompress: false)
        XCTAssertNil(result)
    }

    func testHashTocUncompressedMode() throws {
        // Valid header with a small "TOC" that we hash without decompression
        let tocBytes = Data("fake-toc-data".utf8)
        var data = Data()
        data.append(contentsOf: [0x78, 0x61, 0x72, 0x21]) // magic
        data.append(contentsOf: [0x00, 0x1c]) // header size: 28
        data.append(contentsOf: [0x00, 0x01]) // version
        // Compressed TOC length = tocBytes.count
        var tocLen = UInt64(tocBytes.count).bigEndian
        data.append(Data(bytes: &tocLen, count: 8))
        // Uncompressed TOC length (irrelevant for uncompressed mode)
        data.append(contentsOf: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        data.append(contentsOf: [0x00, 0x00, 0x00, 0x01]) // checksum
        data.append(tocBytes)

        let url = FileManager.default.temporaryDirectory / "fashion-xar-valid-\(UUID())"
        try data.write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }

        let result = try XARParser.hashToc(path: url.path(), algorithm: .sha256, decompress: false)
        XCTAssertNotNil(result)
        // Should match one-shot hash of the TOC bytes
        XCTAssertEqual(result, try CryptoDigest.hash(data: tocBytes, algorithm: .sha256))
    }

    func testHashTocMissingFileThrows() {
        XCTAssertThrowsError(try XARParser.hashToc(path: "/tmp/fashion-nonexistent-\(UUID())", algorithm: .sha256, decompress: false))
    }
}
