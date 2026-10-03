@testable import fashion
import XCTest

// MARK: Sequence+HexString

final class HexStringTests: XCTestCase {
    func testEmpty() {
        let bytes: [UInt8] = []
        XCTAssertEqual(bytes.hexString, "")
    }

    func testSingleByte() {
        XCTAssertEqual([UInt8(0x00)].hexString, "00")
        XCTAssertEqual([UInt8(0x0f)].hexString, "0f")
        XCTAssertEqual([UInt8(0xff)].hexString, "ff")
    }

    func testMultipleBytes() {
        let bytes: [UInt8] = [0xde, 0xad, 0xbe, 0xef]
        XCTAssertEqual(bytes.hexString, "deadbeef")
    }

    func testLeadingZeros() {
        let bytes: [UInt8] = [0x00, 0x01, 0x02, 0x03]
        XCTAssertEqual(bytes.hexString, "00010203")
    }
}

// MARK: String+Pluralizing

final class PluralizingTests: XCTestCase {
    func testRegularPlural() {
        XCTAssertEqual(String(0, pluralizing: "file"), "0 files")
        XCTAssertEqual(String(1, pluralizing: "file"), "1 file")
        XCTAssertEqual(String(2, pluralizing: "file"), "2 files")
    }

    func testIrregularPlural() {
        XCTAssertEqual(String(1, pluralizing: "hash", plural: "hashes"), "1 hash")
        XCTAssertEqual(String(2, pluralizing: "hash", plural: "hashes"), "2 hashes")
        XCTAssertEqual(String(12345, pluralizing: "entry", plural: "entries"), "12345 entries")
    }
}
