@testable import fashion
import XCTest

final class GitBlobDigestTests: XCTestCase {
    func testGitBlobSHA1Empty() throws {
        let data = Data()
        let result = try GitBlobDigest.hashData(data, useSHA256: false)
        // git hash-object --stdin <<< "" produces hash of "blob 0\0"
        XCTAssertEqual(result, "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391")
    }

    func testGitBlobSHA1Hello() throws {
        let data = Data("hello".utf8)
        let result = try GitBlobDigest.hashData(data, useSHA256: false)
        // "blob 5\0hello"
        XCTAssertEqual(result, "b6fc4c620b67d95f953a5c1c1230aaab5db5a1b0")
    }

    func testGitBlobSHA256Empty() throws {
        let data = Data()
        let result = try GitBlobDigest.hashData(data, useSHA256: true)
        XCTAssertNotNil(result)
        XCTAssertEqual(result.count, 64) // 256-bit = 64 hex chars
    }

    // MARK: - File path

    private func tmpFile(_ content: Data) throws -> URL {
        let url = FileManager.default.temporaryDirectory / "fashion-gitblob-\(UUID())"
        try content.write(to: url)
        return url
    }

    func testGitBlobFileSHA1() throws {
        let data = Data("hello".utf8)
        let url = try tmpFile(data)
        defer { try? FileManager.default.removeItem(at: url) }

        let result = try GitBlobDigest.hash(path: url.path(), useSHA256: false)
        XCTAssertEqual(result, try GitBlobDigest.hashData(data, useSHA256: false))
    }

    func testGitBlobFileSHA256() throws {
        let data = Data("hello".utf8)
        let url = try tmpFile(data)
        defer { try? FileManager.default.removeItem(at: url) }

        let result = try GitBlobDigest.hash(path: url.path(), useSHA256: true)
        XCTAssertEqual(result, try GitBlobDigest.hashData(data, useSHA256: true))
    }

    func testGitBlobFileMissingThrows() {
        XCTAssertThrowsError(try GitBlobDigest.hash(path: "/tmp/fashion-nonexistent-\(UUID())", useSHA256: false))
    }
}
