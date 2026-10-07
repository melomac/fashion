@testable import fashion
import XCTest

final class CLITests: XCTestCase {
    /**
     The message the command line prints for `arguments`, or nil when they are valid.
     */
    private func error(_ arguments: [String]) -> String? {
        do {
            _ = try Fashion.parse(arguments)
            return nil
        } catch {
            return Fashion.message(for: error)
        }
    }

    func testNegativeCountsAreRefused() {
        // `--jobs -7` reads `-7` as an option; joined with "=", the value reaches validation.
        XCTAssertEqual(self.error(["--jobs=-7"]), "--jobs must be zero or greater.")
        XCTAssertEqual(self.error(["--score=-1"]), "--score must be zero or greater.")
    }

    func testArgumentsMustBeUTF8() throws {
        // CommandLine.arguments repairs bytes that are not UTF-8 to U+FFFD, another path that may name another file:
        // the run is refused before anything is hashed. A Japanese name is UTF-8 like any other.
        let dir = FileManager.default.temporaryDirectory / "fashion-argv-\(UUID())"
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer {
            try? FileManager.default.removeItem(at: dir)
        }
        let japanese = dir / "日本語"
        try Data("x".utf8).write(to: japanese)

        XCTAssertEqual(try runFashion([japanese.path]).status, 0)
        // sh makes the byte itself: a Swift string cannot hold it.
        let (status, errors) = try runFashion([japanese.path], sh: #"exec "$0" "$1" "$(printf '\377')""#)
        XCTAssertEqual(status, 64) // EX_USAGE
        XCTAssertEqual(errors.first, "Error: Argument 2 is not valid UTF-8.")
    }

    func testJobsResolveToTheProcessors() throws {
        let processors = ProcessInfo.processInfo.activeProcessorCount
        XCTAssertEqual(try Fashion.parse(["--jobs=0"]).resolvedJobs, processors)
        XCTAssertEqual(try Fashion.parse(["--jobs=1"]).resolvedJobs, 1)
        XCTAssertEqual(try Fashion.parse(["--jobs=\(processors + 1)"]).resolvedJobs, processors)
    }
}
