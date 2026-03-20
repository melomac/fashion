@testable import fashion
import XCTest

final class AlgorithmTests: XCTestCase {
    func testParseStandardAlgorithms() {
        XCTAssertEqual(Algorithm.parse("md5"), .md5)
        XCTAssertEqual(Algorithm.parse("sha1"), .sha1)
        XCTAssertEqual(Algorithm.parse("sha256"), .sha256)
        XCTAssertEqual(Algorithm.parse("sha384"), .sha384)
        XCTAssertEqual(Algorithm.parse("sha512"), .sha512)
        XCTAssertEqual(Algorithm.parse("git"), .git)
        XCTAssertEqual(Algorithm.parse("git256"), .git256)
        XCTAssertEqual(Algorithm.parse("ssdeep"), .ssdeep)
        XCTAssertEqual(Algorithm.parse("tlsh"), .tlsh)
    }

    func testParseAlias() {
        XCTAssertEqual(Algorithm.parse("sha2"), .sha256)
    }

    func testParseCaseInsensitive() {
        XCTAssertEqual(Algorithm.parse("SHA256"), .sha256)
        XCTAssertEqual(Algorithm.parse("MD5"), .md5)
        XCTAssertEqual(Algorithm.parse("SHA2"), .sha256)
    }

    func testParseInvalid() {
        XCTAssertNil(Algorithm.parse("bogus"))
        XCTAssertNil(Algorithm.parse(""))
    }

    func testIsFuzzy() {
        XCTAssertTrue(Algorithm.ssdeep.isFuzzy)
        XCTAssertTrue(Algorithm.tlsh.isFuzzy)
        XCTAssertFalse(Algorithm.sha256.isFuzzy)
        XCTAssertFalse(Algorithm.md5.isFuzzy)
        XCTAssertFalse(Algorithm.git.isFuzzy)
    }
}
