@testable import fashion
import System
import XCTest

final class SSDeepBridgeTests: XCTestCase {
    func testHashData() throws {
        // ssdeep needs reasonable data to produce a hash
        let data = Data(repeating: 0x41, count: 4096)
        let result = try ByteHash.ssdeep.digest(data)

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

        let result = try ByteHash.ssdeep.digest(File(path: url.path()))
        XCTAssertFalse(try XCTUnwrap(result).isEmpty)
    }

    func testHashDataMatchesHashFile() throws {
        // The streaming buffer path must produce the same digest as hashing the file directly.
        let data = Data((0 ..< 8192).map { UInt8($0 & 0xff) })
        let url = FileManager.default.temporaryDirectory / "fashion-ssdeep-eq-\(UUID())"
        try data.write(to: url)
        defer {
            try? FileManager.default.removeItem(at: url)
        }

        XCTAssertEqual(try ByteHash.ssdeep.digest(data), try ByteHash.ssdeep.digest(File(path: url.path())))
    }

    func testHashEmptyData() throws {
        // Empty input has no base address; the bridge must not crash and should return the degenerate signature.
        XCTAssertEqual(try ByteHash.ssdeep.digest(Data()), "3::")
    }

    func testHashFileMissingThrows() {
        XCTAssertThrowsError(try ByteHash.ssdeep.digest(File(path: "/tmp/fashion-nonexistent-\(UUID())"))) { error in
            XCTAssertEqual(error as? Errno, .noSuchFileOrDirectory)
        }
    }

    func testCompareIdenticalSignatures() throws {
        let data = Data(repeating: 0x43, count: 4096)
        guard let sig = try ByteHash.ssdeep.digest(data) else {
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
