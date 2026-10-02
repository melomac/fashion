@testable import fashion
import XCTest

final class ConsoleTests: XCTestCase {
    func testPrintableReplacesControlCharacters() {
        // ESC, BEL, BS, DEL and the C1 CSI of a crafted file name would move the cursor or rewrite earlier lines.
        XCTAssertEqual(Console.printable("abc  /tmp/x\u{1B}[1A\u{07}\u{08}\u{7F}\u{9B}2K"), "abc  /tmp/x?[1A????2K")
    }

    func testPrintableKeepsOrdinaryText() {
        let line = "abc  /tmp/r\u{E9}sum\u{E9} \u{65E5}\u{672C} e\u{301}"
        XCTAssertEqual(Console.printable(line), line)
    }
}
