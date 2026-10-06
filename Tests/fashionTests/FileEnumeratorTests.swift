@testable import fashion
import Foundation
import XCTest

final class FileEnumeratorTests: XCTestCase {
    /**
     The files under `paths`, walked sorted.
     */
    private func sortedWalk(_ paths: [String]) -> [String] {
        Array(FileWalker(paths: paths, follow: false, sorted: true))
    }

    private func byteSorted(_ paths: [String]) -> [String] {
        paths.sorted { $0.utf8.lexicographicallyPrecedes($1.utf8) }
    }

    func testSortedWalkSkipsFifo() throws {
        // A directly-named FIFO must be skipped, not opened (which would block forever).
        let url = FileManager.default.temporaryDirectory / "fashion-fifo-\(UUID())"
        defer {
            try? FileManager.default.removeItem(at: url)
        }
        guard mkfifo(url.path, 0o600) == 0 else {
            throw XCTSkip("mkfifo failed: errno \(errno)")
        }

        let paths = self.sortedWalk([url.path])
        XCTAssertFalse(paths.contains(url.path), "FIFO should be skipped")
    }

    func testSortedWalkIncludesRegularFile() throws {
        let url = FileManager.default.temporaryDirectory / "fashion-reg-\(UUID())"
        try Data("hello".utf8).write(to: url)
        defer {
            try? FileManager.default.removeItem(at: url)
        }

        let paths = self.sortedWalk([url.path])
        XCTAssertEqual(paths, [url.path])
    }

    func testRootSymlinkToDirectoryIsWalked() throws {
        // A root named on the command line is followed even without -L, like `find -H`; inner symlinks are not.
        let dir = FileManager.default.temporaryDirectory / "fashion-rootlink-\(UUID())"
        try FileManager.default.createDirectory(at: dir / "sub", withIntermediateDirectories: true)
        try Data("hi".utf8).write(to: dir / "sub" / "f")
        try FileManager.default.createSymbolicLink(at: dir / "link", withDestinationURL: dir / "sub")
        defer {
            try? FileManager.default.removeItem(at: dir)
        }

        XCTAssertEqual(self.sortedWalk([(dir / "link").path]), [(dir / "link" / "f").path])
        XCTAssertEqual(self.sortedWalk([dir.path]), [(dir / "sub" / "f").path])
    }

    func testSortedWalkMissingPathReturnsEmpty() {
        let paths = self.sortedWalk(["/tmp/fashion-nonexistent-\(UUID())"])
        XCTAssertTrue(paths.isEmpty)
    }

    func testStreamingWalkMatchesSortedWalk() throws {
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

        let sorted = self.sortedWalk([dir.path])
        let streamed = Array(FileWalker(paths: [dir.path], follow: false))

        XCTAssertEqual(sorted.count, 4)
        XCTAssertEqual(self.byteSorted(streamed), sorted)
    }

    func testStreamingWalkReportsErrorsAndSkipsFifo() throws {
        let dir = FileManager.default.temporaryDirectory / "fashion-walk-fifo-\(UUID())"
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer {
            try? FileManager.default.removeItem(at: dir)
        }
        try Data("x".utf8).write(to: dir / "real.txt")
        guard mkfifo((dir / "pipe").path, 0o600) == 0 else {
            throw XCTSkip("mkfifo failed: errno \(errno)")
        }

        let streamed = Array(FileWalker(paths: [dir.path], follow: false))

        // The FIFO inside a walked directory is skipped by fts; only the regular file is emitted.
        XCTAssertEqual(streamed.map { ($0 as NSString).lastPathComponent }, ["real.txt"])
    }

    func testDirectoryRootTrailingSlashesDoNotDoubleUp() throws {
        // libc's fts appends "/" to the root as given, so `dir/` used to enumerate as `dir//file`.
        let dir = FileManager.default.temporaryDirectory / "fashion-slash-\(UUID())"
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try Data("x".utf8).write(to: dir / "f")
        defer {
            try? FileManager.default.removeItem(at: dir)
        }

        for root in [dir.path + "/", dir.path + "//"] {
            XCTAssertEqual(self.sortedWalk([root]), [(dir / "f").path])
        }
    }

    /**
     A tree whose names sort around "/": `a-b`, `a.txt` and `a b` sort before `a/x`, and `sub-1` before `sub/k`. In `n`,
     a decomposed `é` and a precomposed `éx`, which Swift's `<` cannot order consistently.
     */
    private func makeSortTree() throws -> URL {
        let dir = FileManager.default.temporaryDirectory / "fashion-sorted-\(UUID())"
        for sub in ["a/sub", "a!", "b", "n", "\u{E9}"] {
            try FileManager.default.createDirectory(at: dir / sub, withIntermediateDirectories: true)
        }
        for name in ["a/x", "a/sub/k", "a/sub-1", "a/sub.txt", "a!/z", "a-b", "a.txt", "a b", "Z", "b/y", "n/e\u{301}", "n/\u{E9}x", "\u{E9}/f", "e\u{301}x"] {
            try Data("x".utf8).write(to: dir / name)
        }
        return dir
    }

    func testSortedWalkMatchesSortingFullPathBytes() throws {
        let dir = try self.makeSortTree()
        defer {
            try? FileManager.default.removeItem(at: dir)
        }

        let walked = Array(FileWalker(paths: [dir.path], follow: false))
        XCTAssertEqual(walked.count, 14)
        XCTAssertEqual(self.sortedWalk([dir.path]), self.byteSorted(walked))
    }

    func testSortedWalkOrdersRoots() throws {
        let dir = try self.makeSortTree()
        defer {
            try? FileManager.default.removeItem(at: dir)
        }

        // Separate roots, in any order, list their files as sorting all of them would.
        let roots = [(dir / "b").path, (dir / "a-b").path, (dir / "a").path, (dir / "Z").path]
        let walked = roots.flatMap { Array(FileWalker(paths: [$0], follow: false)) }
        XCTAssertEqual(walked.count, 1 + 1 + 4 + 1)
        XCTAssertEqual(self.sortedWalk(roots), self.byteSorted(walked))

        // A root inside another is walked after it, not merged into it.
        XCTAssertEqual(self.sortedWalk([(dir / "a").path, dir.path]), self.sortedWalk([dir.path]) + self.sortedWalk([(dir / "a").path]))
        // Past `a`, both `a` and `a/sub` go on with "/": the rest of the path decides, in whichever order they are given.
        let nested = [(dir / "a").path, (dir / "a" / "sub").path]
        for roots in [nested, nested.reversed()] {
            XCTAssertEqual(self.sortedWalk(roots), self.sortedWalk([nested[0]]) + self.sortedWalk([nested[1]]))
        }
    }

    /**
     Run the built `fashion` on `arguments`: its exit status and the lines it wrote to stderr.
     */
    private func run(_ arguments: [String]) throws -> (status: Int32, errors: [String]) {
        let process = Process()
        process.executableURL = try fashionExecutable()
        process.arguments = arguments
        process.environment = fashionEnvironment
        process.standardOutput = FileHandle.nullDevice
        let stderr = Pipe()
        process.standardError = stderr
        try process.run()
        let output = stderr.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return (process.terminationStatus, String(decoding: output, as: UTF8.self).split(separator: "\n").map(String.init))
    }

    func testRootsReportTheirOwnErrors() throws {
        // Each root that cannot be walked is reported with what fts met there: a path in an unreadable directory is
        // not missing, a file named as a directory is not one, and a root symlink to nothing does not exist.
        try XCTSkipIf(getuid() == 0, "root reads an unreadable directory")
        let dir = FileManager.default.temporaryDirectory / "fashion-roots-\(UUID())"
        try FileManager.default.createDirectory(at: dir / "locked", withIntermediateDirectories: true)
        try Data("x".utf8).write(to: dir / "locked" / "f")
        try Data("x".utf8).write(to: dir / "file")
        try FileManager.default.createSymbolicLink(atPath: (dir / "dangling").path, withDestinationPath: "nowhere")
        XCTAssertEqual(chmod((dir / "locked").path, 0), 0)
        defer {
            chmod((dir / "locked").path, 0o755)
            try? FileManager.default.removeItem(at: dir)
        }

        let roots = [(dir / "locked" / "f").path, (dir / "file").path + "/", (dir / "dangling").path, (dir / "missing").path]
        XCTAssertTrue(self.sortedWalk(roots).isEmpty)

        let (status, errors) = try self.run(["--sort"] + roots)
        XCTAssertEqual(status, 2)
        XCTAssertEqual(errors, [
            "fashion: \(dir.path)/dangling: No such file or directory",
            "fashion: \(dir.path)/file/: Not a directory",
            "fashion: \(dir.path)/locked/f: Permission denied",
            "fashion: \(dir.path)/missing: No such file or directory",
        ])
    }
}
