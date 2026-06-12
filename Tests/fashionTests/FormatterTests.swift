@testable import fashion
import XCTest

final class FormatterTests: XCTestCase {
    func testFormatLine() {
        let line = OutputFormatter.formatLine(digest: "abc123", path: "/tmp/file.txt", algorithm: .sha256)
        XCTAssertEqual(line, "abc123  /tmp/file.txt")
    }

    func testFormatLineSSDeepPadding() {
        let digest = "3:abc"
        let path = "/tmp/file.txt"
        let line = OutputFormatter.formatLine(digest: digest, path: path, algorithm: .ssdeep)

        // formatLine pads ssdeep digests to 107 chars, then "  <path>"
        let expectedLength = OutputFormatter.ssdeepPadWidth + 2 + path.count
        XCTAssertEqual(line.count, expectedLength)
        XCTAssertTrue(line.hasSuffix("  \(path)"))

        // formatQuiet returns the raw digest without padding (machine-consumable)
        let quiet = OutputFormatter.formatQuiet(digest: digest, algorithm: .ssdeep)
        XCTAssertEqual(quiet, digest)
    }

    func testFormatLineCDHashPadding() {
        let digest = String(repeating: "a", count: 40) // SHA-1 candidate
        let path = "/tmp/file.txt"
        let line = OutputFormatter.formatLine(digest: digest, path: path, algorithm: .cdhash)

        // formatLine pads cdhash digests to SHA-256 length, then "  <path>"
        let expectedLength = OutputFormatter.cdhashPadWidth + 2 + path.count
        XCTAssertEqual(line.count, expectedLength)
        XCTAssertTrue(line.hasSuffix("  \(path)"))

        // Full SHA-256 digests are left untouched
        let full = String(repeating: "b", count: 64)
        XCTAssertEqual(OutputFormatter.formatLine(digest: full, path: path, algorithm: .cdhash), "\(full)  \(path)")

        // formatQuiet returns the raw digest without padding (machine-consumable)
        let quiet = OutputFormatter.formatQuiet(digest: digest, algorithm: .cdhash)
        XCTAssertEqual(quiet, digest)
    }

    func testFormatMatchLineSSDeep() {
        let line = OutputFormatter.formatMatchLine(digest: "3:abc", score: 95, path: "/tmp/file.txt", algorithm: .ssdeep)
        XCTAssertTrue(line.contains(" 95  "))
    }

    func testFormatMatchLineTLSH() {
        let line = OutputFormatter.formatMatchLine(digest: "T1ABC123", score: 12, path: "/tmp/file.txt", algorithm: .tlsh)
        XCTAssertTrue(line.contains("  12  "))
    }

    func testFormatQuiet() {
        let result = OutputFormatter.formatQuiet(digest: "abc123", algorithm: .sha256)
        XCTAssertEqual(result, "abc123")
    }

    func testFormatQuietMatch() {
        let result = OutputFormatter.formatQuietMatch(path: "/tmp/file.txt")
        XCTAssertEqual(result, "/tmp/file.txt")
    }

    func testFormatMatchLineExactAlgorithmNoScore() {
        // For non-fuzzy algorithms, score string should be empty
        let line = OutputFormatter.formatMatchLine(digest: "abc123", score: 0, path: "/tmp/file.txt", algorithm: .sha256)
        XCTAssertTrue(line.hasPrefix("abc123"))
        XCTAssertTrue(line.hasSuffix("/tmp/file.txt"))
    }
}
