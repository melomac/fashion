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
