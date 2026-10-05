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
    }

    func testFormatLineCDHashPadding() {
        let digest = String(repeating: "a", count: 40) // SHA-1 candidate
        let path = "/tmp/file.txt"
        let line = OutputFormatter.formatLine(digest: digest, path: path, algorithm: .cdhash)

        // formatLine pads cdhash digests to the common SHA-256 length, then "  <path>"
        let expectedLength = OutputFormatter.cdhashPadWidth + 2 + path.count
        XCTAssertEqual(line.count, expectedLength)
        XCTAssertTrue(line.hasSuffix("  \(path)"))

        // A full-width digest (at the pad width) is left untouched
        let full = String(repeating: "b", count: OutputFormatter.cdhashPadWidth)
        XCTAssertEqual(OutputFormatter.formatLine(digest: full, path: path, algorithm: .cdhash), "\(full)  \(path)")
    }

    func testFormatLineSSDeepScore() {
        let line = OutputFormatter.formatLine(digest: "3:abc", score: 95, path: "/tmp/file.txt", algorithm: .ssdeep)
        XCTAssertTrue(line.contains(" 95  "))
    }

    func testFormatLineTLSHScore() {
        let line = OutputFormatter.formatLine(digest: "T1ABC123", score: 12, path: "/tmp/file.txt", algorithm: .tlsh)
        XCTAssertTrue(line.contains("  12  "))
    }

    func testFormatPathOrdinaryPathNotEscaped() {
        XCTAssertEqual(OutputFormatter.formatPath("/tmp/file.txt"), "/tmp/file.txt")
    }

    func testFormatLineExactAlgorithmNoScore() {
        // For non-fuzzy algorithms, score string should be empty
        let line = OutputFormatter.formatLine(digest: "abc123", score: 0, path: "/tmp/file.txt", algorithm: .sha256)
        XCTAssertTrue(line.hasPrefix("abc123"))
        XCTAssertTrue(line.hasSuffix("/tmp/file.txt"))
    }

    // MARK: - Path escaping

    func testFormatLineEscapesNewlineInPath() {
        // A crafted filename with a newline must not forge a second output line.
        let line = OutputFormatter.formatLine(digest: "abc123", path: "/tmp/a\nb", algorithm: .sha256)
        XCTAssertFalse(line.contains("\n"), "Newline must be escaped, not emitted literally")
        XCTAssertEqual(line, "\\abc123  /tmp/a\\nb")
    }

    func testFormatLineEscapesCarriageReturnLineFeedInPath() {
        // "\r\n" is a single Character, which contains neither "\r" nor "\n": the line break must still be escaped.
        for line in [
            OutputFormatter.formatLine(digest: "abc123", path: "/tmp/a\r\nfake", algorithm: .sha256),
            OutputFormatter.formatPath("/tmp/a\r\nfake"),
        ] {
            XCTAssertFalse(line.utf8.contains { $0 == UInt8(ascii: "\n") || $0 == UInt8(ascii: "\r") }, "Line breaks must be escaped, not emitted literally")
        }
        XCTAssertEqual(OutputFormatter.formatLine(digest: "abc123", path: "/tmp/a\r\nfake", algorithm: .sha256), "\\abc123  /tmp/a\\r\\nfake")
        XCTAssertEqual(OutputFormatter.formatPath("/tmp/a\r\nfake"), "\\/tmp/a\\r\\nfake")
    }

    func testFormatLineEscapesBackslashInPath() {
        let line = OutputFormatter.formatLine(digest: "abc123", path: "/tmp/a\\b", algorithm: .sha256)
        XCTAssertEqual(line, "\\abc123  /tmp/a\\\\b")
    }

    func testFormatLineOrdinaryPathNotEscaped() {
        let line = OutputFormatter.formatLine(digest: "abc123", path: "/tmp/file.txt", algorithm: .sha256)
        XCTAssertEqual(line, "abc123  /tmp/file.txt")
    }

    func testFormatPathEscapesNewline() {
        let line = OutputFormatter.formatPath("/tmp/a\nb")
        XCTAssertFalse(line.contains("\n"))
        XCTAssertEqual(line, "\\/tmp/a\\nb")
    }

    func testFormatPathEscapesDiagnosticPath() {
        XCTAssertEqual(OutputFormatter.formatPath("/tmp/a\nb\\c"), "\\/tmp/a\\nb\\\\c")
    }

    func testFormatDiagnosticEscapesLineBreaks() {
        XCTAssertEqual(OutputFormatter.formatDiagnostic("first\nsecond\rthird"), "first\\nsecond\\rthird")
    }
}
