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

    func testJobsResolveToTheProcessors() throws {
        let processors = ProcessInfo.processInfo.activeProcessorCount
        XCTAssertEqual(try Fashion.parse(["--jobs=0"]).resolvedJobs, processors)
        XCTAssertEqual(try Fashion.parse(["--jobs=1"]).resolvedJobs, 1)
        XCTAssertEqual(try Fashion.parse(["--jobs=\(processors + 1)"]).resolvedJobs, processors)
    }
}
