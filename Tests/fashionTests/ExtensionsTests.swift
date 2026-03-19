@testable import fashion
import XCTest

// MARK: FileManager+Inode

final class FileManagerInodeTests: XCTestCase {
    func testInodeReturnsValueForExistingFile() throws {
        let tmp = FileManager.default.temporaryDirectory / "fashion-test-inode-\(UUID())"
        try Data("test".utf8).write(to: tmp)
        defer { try? FileManager.default.removeItem(at: tmp) }

        let inode = try XCTUnwrap(FileManager.default.inode(atPath: tmp.path()))
        XCTAssertGreaterThan(inode, 0)
    }

    func testInodeReturnsNilForMissingFile() {
        let result = FileManager.default.inode(atPath: "/tmp/fashion-nonexistent-\(UUID())")
        XCTAssertNil(result)
    }

    func testInodeIsStableAcrossReads() throws {
        let tmp = FileManager.default.temporaryDirectory / "fashion-test-inode-stable-\(UUID())"
        try Data("test".utf8).write(to: tmp)
        defer { try? FileManager.default.removeItem(at: tmp) }

        let first = FileManager.default.inode(atPath: tmp.path())
        let second = FileManager.default.inode(atPath: tmp.path())
        XCTAssertEqual(first, second)
    }

    func testDeviceInodeReturnsValueForExistingFile() throws {
        let tmp = FileManager.default.temporaryDirectory / "fashion-test-devinode-\(UUID())"
        try Data("test".utf8).write(to: tmp)
        defer { try? FileManager.default.removeItem(at: tmp) }

        let result = try XCTUnwrap(FileManager.default.deviceInode(atPath: tmp.path()))
        XCTAssertGreaterThan(result.device, 0)
        XCTAssertGreaterThan(result.inode, 0)
    }

    func testDeviceInodeReturnsNilForMissingFile() {
        let result = FileManager.default.deviceInode(atPath: "/tmp/fashion-nonexistent-\(UUID())")
        XCTAssertNil(result)
    }

    func testDifferentFilesHaveDifferentInodes() throws {
        let tmp1 = FileManager.default.temporaryDirectory / "fashion-test-inode-a-\(UUID())"
        let tmp2 = FileManager.default.temporaryDirectory / "fashion-test-inode-b-\(UUID())"
        try Data("a".utf8).write(to: tmp1)
        try Data("b".utf8).write(to: tmp2)
        defer {
            try? FileManager.default.removeItem(at: tmp1)
            try? FileManager.default.removeItem(at: tmp2)
        }

        let inode1 = try XCTUnwrap(FileManager.default.inode(atPath: tmp1.path()))
        let inode2 = try XCTUnwrap(FileManager.default.inode(atPath: tmp2.path()))
        XCTAssertNotEqual(inode1, inode2)
    }
}

// MARK: - Sequence+HexString

final class HexStringTests: XCTestCase {
    func testEmpty() {
        let bytes: [UInt8] = []
        XCTAssertEqual(bytes.hexString, "")
    }

    func testSingleByte() {
        XCTAssertEqual([UInt8(0x00)].hexString, "00")
        XCTAssertEqual([UInt8(0x0f)].hexString, "0f")
        XCTAssertEqual([UInt8(0xff)].hexString, "ff")
    }

    func testMultipleBytes() {
        let bytes: [UInt8] = [0xde, 0xad, 0xbe, 0xef]
        XCTAssertEqual(bytes.hexString, "deadbeef")
    }

    func testLeadingZeros() {
        let bytes: [UInt8] = [0x00, 0x01, 0x02, 0x03]
        XCTAssertEqual(bytes.hexString, "00010203")
    }
}

// MARK: - URL+Component

final class URLComponentTests: XCTestCase {
    func testUrlSlashComponent() {
        let components = ["our", "hard", "work", "by", "these", "words", "guarded"]
        let suffix = components.joined(separator: "/")

        let url = URL(fileURLWithPath: "/private/tmp", isDirectory: true) / suffix

        XCTAssertEqual(url.pathComponents.suffix(components.count), components)
    }

    func testUrlSlashComponents() {
        let components = ["our", "hard", "work", "by", "these", "words", "guarded"]
        let suffix = components.joined(separator: "/")

        let url = URL(fileURLWithPath: "/private/tmp", isDirectory: true) / "our" / "hard" / "work" / "by" / "these" / "words" / "guarded"

        XCTAssertTrue(url.path.hasSuffix(suffix))
    }

    func testHttpUrlWithQueryString() throws {
        let base = try XCTUnwrap(URL(string: "https://example.com/api"))
        let url = base / "search?q=test&limit=10"
        XCTAssertEqual(url.path, "/api/search")
        XCTAssertEqual(url.query, "q=test&limit=10")
    }

    func testHttpUrlWithLeadingSlashQuery() throws {
        let base = try XCTUnwrap(URL(string: "https://example.com"))
        let url = base / "/endpoint?key=value"
        XCTAssertEqual(url.path, "/endpoint")
        XCTAssertEqual(url.query, "key=value")
    }

    func testFileUrlIgnoresQueryParsing() {
        // File URLs should NOT split on '?' — the '?' is part of the path component
        let base = URL(fileURLWithPath: "/tmp")
        let url = base / "file?name"
        XCTAssertTrue(url.path.contains("file?name") || url.path.hasSuffix("file%3Fname"))
    }

    func testHttpUrlWithoutQuery() throws {
        let base = try XCTUnwrap(URL(string: "https://example.com"))
        let url = base / "path/to/resource"
        XCTAssertTrue(url.path.hasSuffix("path/to/resource"))
        XCTAssertNil(url.query)
    }
}
