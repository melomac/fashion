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

    func testSortedWalkSkipsFifo() throws {
        // A directly-named FIFO is not a file to hash: the walk skips it.
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
        XCTAssertEqual(naturallySorted(streamed), sorted)
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

    func testSortedWalkMatchesSortingFullPaths() throws {
        let dir = try self.makeSortTree()
        defer {
            try? FileManager.default.removeItem(at: dir)
        }

        let walked = Array(FileWalker(paths: [dir.path], follow: false))
        XCTAssertEqual(walked.count, 14)
        XCTAssertEqual(self.sortedWalk([dir.path]), naturallySorted(walked))
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
        XCTAssertEqual(self.sortedWalk(roots), naturallySorted(walked))

        // A root inside another is walked after it, not merged into it.
        XCTAssertEqual(self.sortedWalk([(dir / "a").path, dir.path]), self.sortedWalk([dir.path]) + self.sortedWalk([(dir / "a").path]))
        // Past `a`, both `a` and `a/sub` go on with "/": the rest of the path decides, in whichever order they are given.
        let nested = [(dir / "a").path, (dir / "a" / "sub").path]
        for roots in [nested, nested.reversed()] {
            XCTAssertEqual(self.sortedWalk(roots), self.sortedWalk([nested[0]]) + self.sortedWalk([nested[1]]))
        }
    }

    /**
     A tree whose names hold numbers, and its files in the order `--sort` lists them: numbers by value, past what 64 bits
     hold, and equal ones with more leading zeros first, even where the rest of the path would order them the other way
     (`r01/z` before `r1/b`).
     */
    private func makeNumberTree() throws -> (dir: URL, sorted: [String]) {
        let dir = FileManager.default.temporaryDirectory / "fashion-numbers-\(UUID())"
        let names = [
            "img", "img-1G", "img-2G", "img-10G", "img-12G", "img.dst/bin/img",
            "r01/z", "r1-x", "r1/b", "r10/a",
            "v007", "v07", "v7", "v9", "v18446744073709551615", "v18446744073709551616",
        ]
        for name in names {
            let url = dir / name
            try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            try Data("x".utf8).write(to: url)
        }
        return (dir, names.map { (dir / $0).path })
    }

    func testSortedWalkOrdersNumbersByValue() throws {
        let (dir, sorted) = try self.makeNumberTree()
        defer {
            try? FileManager.default.removeItem(at: dir)
        }

        XCTAssertEqual(self.sortedWalk([dir.path]), sorted)
        XCTAssertEqual(naturallySorted(Array(FileWalker(paths: [dir.path], follow: false))), sorted)

        // Roots order the same way, whichever way they are given.
        let roots = ["img-10G", "img.dst", "img-2G", "img", "img-1G", "img-12G"].map { (dir / $0).path }
        XCTAssertEqual(self.sortedWalk(roots), Array(sorted[..<6]))
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

        let (status, errors) = try runFashion(["--sort"] + roots)
        XCTAssertEqual(status, 2)
        XCTAssertEqual(errors, [
            "fashion: \(dir.path)/dangling: No such file or directory",
            "fashion: \(dir.path)/file/: Not a directory",
            "fashion: \(dir.path)/locked/f: Permission denied",
            "fashion: \(dir.path)/missing: No such file or directory",
        ])
    }

    func testRootTooLongToLookUpIsReportedAlone() throws {
        // fts reports a root the kernel cannot look up in order with the others, but refuses every root when one is
        // longer than its own buffer (about 64 KiB): the roots too long for the kernel are then reported first, and
        // the others are still walked.
        let file = FileManager.default.temporaryDirectory / "fashion-long-root-\(UUID())"
        try Data("x".utf8).write(to: file)
        defer {
            try? FileManager.default.removeItem(at: file)
        }
        let missing = FileManager.default.temporaryDirectory / "fashion-missing-\(UUID())"
        let tooLong = String(repeating: "x/", count: Int(PATH_MAX) / 2)
        let long = String(repeating: "x/", count: 40000)

        XCTAssertEqual(self.sortedWalk([file.path, long, tooLong]), [file.path])
        XCTAssertEqual(self.sortedWalk([long]), [])

        // Sorted, "/…" comes before "x/…": fts orders the roots it can walk.
        var (status, errors) = try runFashion(["--sort", tooLong, missing.path])
        XCTAssertEqual(status, 2)
        XCTAssertEqual(errors, ["fashion: \(missing.path): No such file or directory", "fashion: \(tooLong): File name too long"])

        (status, errors) = try runFashion(["--sort", file.path, long, tooLong])
        XCTAssertEqual(status, 2)
        XCTAssertEqual(errors, ["fashion: \(long): File name too long", "fashion: \(tooLong): File name too long"])
    }

    func testUnreadableFileIsReportedLikeAWalkError() throws {
        // Opening the file fails where the walk did not: the message is the same strerror text a walk error has.
        try XCTSkipIf(getuid() == 0, "root reads an unreadable file")
        let url = FileManager.default.temporaryDirectory / "fashion-unreadable-\(UUID())"
        try Data("x".utf8).write(to: url)
        XCTAssertEqual(chmod(url.path, 0), 0)
        defer {
            try? FileManager.default.removeItem(at: url)
        }

        let (status, errors) = try runFashion([url.path])
        XCTAssertEqual(status, 2)
        XCTAssertEqual(errors, ["fashion: \(url.path): Permission denied"])
    }
}
