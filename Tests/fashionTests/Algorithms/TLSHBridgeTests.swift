@testable import fashion
import XCTest

final class TLSHBridgeTests: XCTestCase {
    let data = Data((0 ..< 256).map {
        UInt8($0 % 256)
    })

    func testHashDataTooSmall() {
        XCTAssertNil(
            TLSHBridge.hash(data: Data(repeating: 0x41, count: 10)),
        )
    }

    func testHashDataLargeEnough() throws {
        let hash = try XCTUnwrap(TLSHBridge.hash(data: self.data))

        XCTAssertNotNil(hash)
        XCTAssertFalse(hash.isEmpty)
    }

    func testHashFile() throws {
        let url = FileManager.default.temporaryDirectory / "fashion-tlsh-\(UUID())"
        try self.data.write(to: url)
        defer {
            try? FileManager.default.removeItem(at: url)
        }
        let hash = try TLSHBridge.hash(path: url.path())

        XCTAssertNotNil(hash)
        XCTAssertFalse(try XCTUnwrap(hash?.isEmpty))
    }

    func testDiffIdenticalHashes() throws {
        let hash = try XCTUnwrap(TLSHBridge.hash(data: self.data))
        XCTAssertFalse(hash.isEmpty)

        let distance = TLSHBridge.diff(hash, hash)
        XCTAssertEqual(distance, 0)
    }

    func testDiffInvalidHashes() {
        let distance = TLSHBridge.diff("invalid", "alsobad")

        XCTAssertEqual(distance, -1)
    }

    func testHashDeterministic() {
        let first = TLSHBridge.hash(data: self.data)

        for _ in 0 ..< 10 {
            XCTAssertEqual(TLSHBridge.hash(data: self.data), first, "TLSH produced different hash for identical input")
        }
    }

    func testDiffStripsT1Prefix() throws {
        let hash = try XCTUnwrap(TLSHBridge.hash(data: self.data))

        let prefixed = "T1" + hash.dropFirst(2)
        XCTAssertEqual(TLSHBridge.diff(hash, prefixed), 0)

        let truncated = String(hash.dropFirst(2))
        XCTAssertEqual(TLSHBridge.diff(hash, truncated), 0)
    }
}
