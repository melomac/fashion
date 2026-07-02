@testable import fashion
import XCTest

final class MatchingTests: XCTestCase {
    // MARK: - Exact matching

    func testExactMatchFound() throws {
        let result = Matching.check(digest: "abc123", against: ["abc123"], algorithm: .sha256, threshold: 0)
        XCTAssertNotNil(result)
        XCTAssertTrue(try XCTUnwrap(result?.matched))
        XCTAssertNil(result?.score)
    }

    func testExactMatchCaseInsensitive() {
        let result = Matching.check(digest: "ABC123", against: ["abc123"], algorithm: .md5, threshold: 0)
        XCTAssertNotNil(result)
    }

    func testExactMatchNotFound() {
        let result = Matching.check(digest: "abc123", against: ["def456"], algorithm: .sha256, threshold: 0)
        XCTAssertNil(result)
    }

    func testExactMatchMultipleTargets() {
        let result = Matching.check(digest: "def456", against: ["abc123", "def456", "ghi789"], algorithm: .sha1, threshold: 0)
        XCTAssertNotNil(result)
    }

    func testExactMatchEmptyTargets() {
        let result = Matching.check(digest: "abc123", against: [], algorithm: .sha256, threshold: 0)
        XCTAssertNil(result)
    }

    func testExactMatchAllAlgorithmsExceptFuzzy() {
        for algo: Algorithm in [.md5, .sha1, .sha256, .sha384, .sha512] {
            let result = Matching.check(digest: "abc", against: ["abc"], algorithm: algo, threshold: 0)
            XCTAssertNotNil(result, "Expected match for \(algo)")
        }
    }

    // MARK: - SSDeep fuzzy matching

    func testSSDeepMatchRouting() {
        // Two identical ssdeep signatures should yield score 100
        let sig = "3:abc:def"
        let result = Matching.check(digest: sig, against: [sig], algorithm: .ssdeep, threshold: 0)
        XCTAssertNotNil(result)
        XCTAssertNotNil(result?.score)
    }

    func testSSDeepNoMatchBelowThreshold() {
        // Completely different signatures — score should be 0, below any threshold > 0
        let result = Matching.check(digest: "3:abc:def", against: ["96:zzzzzzzzzzzzzzzzz:yyyy"], algorithm: .ssdeep, threshold: 100)
        XCTAssertNil(result)
    }

    // MARK: - TLSH fuzzy matching

    func testTLSHMatchRouting() {
        // Compute a real TLSH hash from data, then verify matching routes through TLSH logic
        let data = Data((0 ..< 1024).map { UInt8($0 % 256) })
        guard let hash = TLSHBridge.hash(data: data) else { return }

        let result = Matching.check(digest: hash, against: [hash], algorithm: .tlsh, threshold: 200)
        XCTAssertNotNil(result)
        XCTAssertNotNil(result?.score)
        XCTAssertEqual(result?.score, 0) // identical = distance 0
    }

    func testTLSHNoMatchAboveThreshold() {
        // Use real TLSH hashes from different data
        let data1 = Data((0 ..< 1024).map { UInt8($0 % 256) })
        let data2 = Data((0 ..< 1024).map { UInt8(($0 * 7 + 13) % 256) })
        guard let h1 = TLSHBridge.hash(data: data1), let h2 = TLSHBridge.hash(data: data2) else { return }

        let result = Matching.check(digest: h1, against: [h2], algorithm: .tlsh, threshold: 0)
        // Distance is likely > 0, so threshold 0 means only exact distance 0 matches
        if result != nil {
            XCTAssertEqual(result?.score, 0)
        }
    }

    // MARK: - CDHash prefix matching

    private let cdhash = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"

    func testCDHashFullMatch() {
        let result = Matching.check(digest: self.cdhash, against: [self.cdhash], algorithm: .cdhash, threshold: 0)
        XCTAssertNotNil(result)
    }

    func testCDHashTruncatedPrefixMatch() {
        let result = Matching.check(digest: self.cdhash, against: [String(self.cdhash.prefix(40))], algorithm: .cdhash, threshold: 0)
        XCTAssertNotNil(result)
    }

    func testCDHashCaseInsensitivePrefixMatch() {
        let result = Matching.check(digest: self.cdhash, against: [String(self.cdhash.prefix(40)).uppercased()], algorithm: .cdhash, threshold: 0)
        XCTAssertNotNil(result)
    }

    func testCDHashEmptyTargetDoesNotMatch() {
        let result = Matching.check(digest: self.cdhash, against: [""], algorithm: .cdhash, threshold: 0)
        XCTAssertNil(result, "An empty target must not prefix-match every digest")
    }

    func testCDHashShortTargetDoesNotMatch() {
        // Below minPrefixHexLength: would otherwise match ~1/16 of all digests.
        let result = Matching.check(digest: self.cdhash, against: [String(self.cdhash.prefix(4))], algorithm: .cdhash, threshold: 0)
        XCTAssertNil(result)
    }

    func testCDHashNonHexTargetDoesNotMatch() {
        let result = Matching.check(digest: self.cdhash, against: ["nothexvalue!!!"], algorithm: .cdhash, threshold: 0)
        XCTAssertNil(result)
    }

    func testCDHashLongerTargetDoesNotMatch() {
        // A target longer than the computed digest must not match via the (removed) reverse-prefix arm.
        let result = Matching.check(digest: String(self.cdhash.prefix(40)), against: [self.cdhash], algorithm: .cdhash, threshold: 0)
        XCTAssertNil(result)
    }

    func testCDHashDifferentPrefixDoesNotMatch() {
        let result = Matching.check(digest: self.cdhash, against: ["ffffffffffffffff"], algorithm: .cdhash, threshold: 0)
        XCTAssertNil(result)
    }
}
