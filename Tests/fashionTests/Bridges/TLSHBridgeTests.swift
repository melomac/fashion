@testable import fashion
import XCTest

final class TLSHBridgeTests: XCTestCase {
    let data = Data((0 ..< 256).map {
        UInt8($0 % 256)
    })

    func testHashDataTooSmall() throws {
        XCTAssertNil(
            try ByteHash.tlsh.digest(Data(repeating: 0x41, count: 10)),
        )
    }

    func testCaveats() throws {
        // libtlsh says nothing of a digest it does not make: fashion names why, after the TLSH tools' own errors.
        var caveats: [String] = []
        XCTAssertNil(try ByteHash.tlsh.digest(Data(repeating: 0x41, count: 10)) { caveats.append($0) })
        XCTAssertNil(try ByteHash.tlsh.digest(Data([0x41])) { caveats.append($0) })
        XCTAssertNil(try ByteHash.tlsh.digest(File(data: Data())) { caveats.append($0) })
        XCTAssertNil(try ByteHash.tlsh.digest(Data(repeating: 0, count: 4096)) { caveats.append($0) })
        XCTAssertNotNil(try ByteHash.tlsh.digest(self.data) { caveats.append($0) })
        XCTAssertNotNil(try ByteHash.sha256.digest(Data()) { caveats.append($0) })
        XCTAssertEqual(caveats, [
            "TLSH cannot hash: input too small (10 bytes, minimum 50)",
            "TLSH cannot hash: input too small (1 byte, minimum 50)",
            "TLSH cannot hash: input too small (0 bytes, minimum 50)",
            "TLSH cannot hash: not enough variation in input",
        ])
    }

    func testCaveatPastLengthLimit() throws {
        // Past its length limit TLSH hashes the first maximumDataSize bytes, too many to feed a test: the caveat is asked
        // for directly.
        let limit = Int(TLSHBridge.maximumDataSize)
        let digest = try XCTUnwrap(ByteHash.tlsh.digest(self.data))
        XCTAssertNil(TLSHBridge.caveat(length: limit, digest: digest))
        XCTAssertEqual(TLSHBridge.caveat(length: limit + 1, digest: digest), "TLSH hashed the first 4224281216 bytes only, it's a known issue: https://github.com/trendmicro/tlsh/issues/84")
        XCTAssertEqual(TLSHBridge.caveat(length: limit + 1, digest: nil), "TLSH cannot hash: not enough variation in the first 4224281216 bytes")
    }

    func testHashDataLargeEnough() throws {
        let hash = try XCTUnwrap(ByteHash.tlsh.digest(self.data))

        XCTAssertNotNil(hash)
        XCTAssertFalse(hash.isEmpty)
    }

    func testHashFile() throws {
        let hash = try ByteHash.tlsh.digest(File(data: self.data))

        XCTAssertNotNil(hash)
        XCTAssertFalse(try XCTUnwrap(hash?.isEmpty))
    }

    func testDiffIdenticalHashes() throws {
        let hash = try XCTUnwrap(ByteHash.tlsh.digest(self.data))
        XCTAssertFalse(hash.isEmpty)

        let distance = TLSHBridge.diff(hash, hash)
        XCTAssertEqual(distance, 0)
    }

    func testDiffWithoutLength() {
        // A 50,704-byte Mach-O, then the same file padded with zeros to 2,952,771 bytes: only the length and the checksum
        // differ, 42 length steps of 12 and 1. Without the length, as the tlsh tool's -xlen, the checksum is all that is
        // left.
        let exact = "T13D338D7A3B0DE1A6C29CC134A5EFCB829D63F9151D7863432B91C5792FC86942F21B4B"
        let padded = "T1B2D58D7A3B0DE1A6C29CC134A5EFCB829D63F9151D7863432B91C5792FC86942F21B4B"
        XCTAssertEqual(TLSHBridge.diff(exact, padded), 505)
        XCTAssertEqual(TLSHBridge.diff(exact, padded, length: false), 1)

        XCTAssertNil(Targets([exact]).match(padded, algorithm: .tlsh, threshold: 40))
        XCTAssertEqual(Targets([exact]).match(padded, algorithm: .tlsh, threshold: 40, xlen: true)?.score, 1)
    }

    func testDiffInvalidHashes() {
        let distance = TLSHBridge.diff("invalid", "alsobad")

        XCTAssertEqual(distance, -1)
    }

    func testDiffRequiresWholeDigests() throws {
        // libtlsh reads the 70 digits it needs and accepts whatever follows them: only whole digests may be compared.
        let hash = try XCTUnwrap(ByteHash.tlsh.digest(self.data))
        let digits = String(hash.dropFirst(2))
        XCTAssertEqual(TLSHBridge.diff(hash, digits), 0, "the T1 prefix is optional")
        XCTAssertEqual(TLSHBridge.diff(hash, "t1" + digits.lowercased()), 0, "digests compare regardless of case")

        for target in [hash + ":garbage", hash + "ZZZZ", hash + "0", "T2" + digits, String(hash.dropLast()), "T1" + digits.dropLast() + "G", " " + hash] {
            XCTAssertEqual(TLSHBridge.diff(hash, target), -1, target)
            // Neither is a TLSH target: shaped like none, it is left out before any digest is compared.
            XCTAssertNil(Targets.shape(of: target), target)
            XCTAssertNil(Targets([target], algorithm: .tlsh).match(hash, algorithm: .tlsh, threshold: 40), target)
        }
    }

    func testHashDeterministic() throws {
        let first = try ByteHash.tlsh.digest(self.data)

        for _ in 0 ..< 10 {
            XCTAssertEqual(try ByteHash.tlsh.digest(self.data), first, "TLSH produced different hash for identical input")
        }
    }

    func testDiffStripsT1Prefix() throws {
        let hash = try XCTUnwrap(ByteHash.tlsh.digest(self.data))

        let prefixed = "T1" + hash.dropFirst(2)
        XCTAssertEqual(TLSHBridge.diff(hash, prefixed), 0)

        let truncated = String(hash.dropFirst(2))
        XCTAssertEqual(TLSHBridge.diff(hash, truncated), 0)
    }
}
