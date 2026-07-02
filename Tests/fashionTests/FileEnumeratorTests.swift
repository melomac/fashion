@testable import fashion
import Foundation
import XCTest

final class FileEnumeratorTests: XCTestCase {
    func testCollectSortedSkipsFifo() throws {
        // A directly-named FIFO must be skipped, not opened (which would block forever).
        let url = FileManager.default.temporaryDirectory / "fashion-fifo-\(UUID())"
        defer {
            try? FileManager.default.removeItem(at: url)
        }
        guard mkfifo(url.path, 0o600) == 0 else {
            throw XCTSkip("mkfifo failed: errno \(errno)")
        }

        let paths = FileEnumerator.collectSorted(paths: [url.path], follow: false)
        XCTAssertFalse(paths.contains(url.path), "FIFO should be skipped")
    }

    func testCollectSortedIncludesRegularFile() throws {
        let url = FileManager.default.temporaryDirectory / "fashion-reg-\(UUID())"
        try Data("hello".utf8).write(to: url)
        defer {
            try? FileManager.default.removeItem(at: url)
        }

        let paths = FileEnumerator.collectSorted(paths: [url.path], follow: false)
        XCTAssertEqual(paths, [url.path])
    }

    func testCollectSortedMissingPathReturnsEmpty() {
        let paths = FileEnumerator.collectSorted(paths: ["/tmp/fashion-nonexistent-\(UUID())"], follow: false)
        XCTAssertTrue(paths.isEmpty)
    }

    func testStreamingWalkMatchesCollectSorted() async throws {
        // The pull-based streaming walk must enumerate the same files as the sorted collector.
        let dir = FileManager.default.temporaryDirectory / "fashion-walk-\(UUID())"
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer {
            try? FileManager.default.removeItem(at: dir)
        }
        for name in ["a.txt", "b.txt", "c.txt"] {
            try Data("x".utf8).write(to: dir / name)
        }
        try FileManager.default.createDirectory(at: dir / "sub", withIntermediateDirectories: true)
        try Data("y".utf8).write(to: dir / "sub" / "d.txt")

        let sorted = FileEnumerator.collectSorted(paths: [dir.path], follow: false)

        var streamed: [String] = []
        for await path in FileEnumerator.walk(paths: [dir.path], follow: false) {
            streamed.append(path)
        }

        XCTAssertEqual(sorted.count, 4)
        XCTAssertEqual(streamed.sorted(), sorted)
    }

    func testStreamingWalkReportsErrorsAndSkipsFifo() async throws {
        let dir = FileManager.default.temporaryDirectory / "fashion-walk-fifo-\(UUID())"
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer {
            try? FileManager.default.removeItem(at: dir)
        }
        try Data("x".utf8).write(to: dir / "real.txt")
        guard mkfifo((dir / "pipe").path, 0o600) == 0 else {
            throw XCTSkip("mkfifo failed: errno \(errno)")
        }

        var streamed: [String] = []
        for await path in FileEnumerator.walk(paths: [dir.path], follow: false) {
            streamed.append(path)
        }

        // The FIFO inside a walked directory is skipped by fts; only the regular file is emitted.
        XCTAssertEqual(streamed.map { ($0 as NSString).lastPathComponent }, ["real.txt"])
    }
}
