@testable import fashion
import XCTest

final class ConsoleTests: XCTestCase {
    /**
     ESC, BEL, BS, DEL and the C1 CSI of a crafted file name would move the cursor or rewrite earlier lines; a
     right-to-left override, a zero-width space, a byte order mark and a soft hyphen would show the name as another.
     Each is a "?", as `ls` shows them; a no-break space, a combining mark and a private-use character are shown.
     */
    func testPrintableReplacesControlCharacters() {
        XCTAssertEqual(Console.printable("abc  /tmp/x\u{1B}[1A\u{07}\u{08}\u{7F}\u{9B}2K"), "abc  /tmp/x?[1A????2K")
        XCTAssertEqual(Console.printable("a\u{202E}fdp.exe \u{200B}b\u{FEFF}c\u{AD}d \u{A0}e\u{301}\u{E000}"), "a?fdp.exe ?b?c?d \u{A0}e\u{301}\u{E000}")
    }

    func testTintedWrapsTheLine() {
        XCTAssertEqual(Console.tinted("abc  /tmp/x", .adhoc), "\u{1B}[2mabc  /tmp/x\u{1B}[0m")
        XCTAssertEqual(Console.tinted("abc  /tmp/x", .none), "abc  /tmp/x")
    }

    /**
     Full green when identical, then darker greens by quarters of the way to the threshold.
     */
    func testMatchTintFadesWithDistance() {
        let ramp = [0, 0.01, 0.25, 0.26, 0.5, 0.51, 0.75, 0.76, 1].map { Tint.match(distance: $0).sgr() }
        XCTAssertEqual(ramp, ["38;5;46", "38;5;40", "38;5;40", "38;5;34", "38;5;34", "38;5;28", "38;5;28", "38;5;22", "38;5;22"])
        // With 16 colors, the terminal's own green, dimmed as soon as a match is not full, and bright black for gray.
        XCTAssertEqual([0, 0.01, 1].map { Tint.match(distance: $0).sgr(colors256: false) }, ["32", "2;32", "2;32"])
        XCTAssertEqual(Tint.weak.sgr(colors256: false), "90")
        XCTAssertEqual(Tint.adhoc.sgr(colors256: false), "2")
    }

    func testPrintableKeepsOrdinaryText() {
        let line = "abc  /tmp/r\u{E9}sum\u{E9} \u{65E5}\u{672C} e\u{301}"
        XCTAssertEqual(Console.printable(line), line)
    }
}
