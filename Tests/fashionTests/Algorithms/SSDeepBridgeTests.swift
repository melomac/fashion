@testable import fashion
import XCTest

final class SSDeepBridgeTests: XCTestCase {
    func testHashData() throws {
        // ssdeep needs reasonable data to produce a hash
        let data = Data(repeating: 0x41, count: 4096)
        let result = SSDeepBridge.hash(data: data)

        XCTAssertNotNil(result)
        XCTAssertFalse(try XCTUnwrap(result?.isEmpty))
    }

    func testHashFile() throws {
        let data = Data(repeating: 0x42, count: 4096)
        let url = FileManager.default.temporaryDirectory / "fashion-ssdeep-\(UUID())"
        try data.write(to: url)
        defer {
            try? FileManager.default.removeItem(at: url)
        }

        let result = SSDeepBridge.hash(path: url.path())
        XCTAssertNotNil(result)
    }

    func testHashFileMissingReturnsNil() {
        let result = SSDeepBridge.hash(path: "/tmp/fashion-nonexistent-\(UUID())")

        XCTAssertNil(result)
    }

    func testCompareIdenticalSignatures() {
        let data = Data(repeating: 0x43, count: 4096)
        guard let sig = SSDeepBridge.hash(data: data) else {
            XCTFail("Failed to compute ssdeep hash")
            return
        }

        let score = SSDeepBridge.compare(sig, sig)
        XCTAssertEqual(score, 100)
    }

    func testCompareCompletelyDifferent() {
        let score = SSDeepBridge.compare("3:abc:def", "96:zzz:yyy")
        XCTAssertEqual(score, 0)
    }
}
