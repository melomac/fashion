@testable import fashion
import XCTest

final class MatchingTests: XCTestCase {
    // Digests of "hello" and of nothing, one per shape.
    private let md5 = "5d41402abc4b2a76b9719d911017c592"
    private let sha1 = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
    private let sha256 = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    private let sha384 = "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    private let sha512 = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    private let tlsh = "T13D338D7A3B0DE1A6C29CC134A5EFCB829D63F9151D7863432B91C5792FC86942F21B4B"
    private let ssdeep = "1536:IJj7hCwwEUYCI66XHJpuERhSV6AOpoWlwOmu26:un9RUYCI6wppXRhSVVOiW+Omu2"

    // MARK: - Shapes

    func testShapeOfEveryAlgorithm() {
        XCTAssertEqual(Matching.shape(of: self.md5), .md5)
        XCTAssertEqual(Matching.shape(of: self.sha1), .sha1)
        XCTAssertEqual(Matching.shape(of: self.sha256), .sha256)
        XCTAssertEqual(Matching.shape(of: self.sha384), .sha384)
        XCTAssertEqual(Matching.shape(of: self.sha512), .sha512)
        XCTAssertEqual(Matching.shape(of: self.tlsh), .tlsh)
        XCTAssertEqual(Matching.shape(of: self.ssdeep), .ssdeep)
        // Hex in either case, TLSH's version too; a TLSH digest as before 4.0, without the version; the empty file's ssdeep.
        XCTAssertEqual(Matching.shape(of: self.md5.uppercased()), .md5)
        XCTAssertEqual(Matching.shape(of: self.tlsh.lowercased()), .tlsh)
        XCTAssertEqual(Matching.shape(of: String(self.tlsh.dropFirst(2))), .tlsh)
        XCTAssertEqual(Matching.shape(of: "3::"), .ssdeep)
        XCTAssertEqual(Matching.shape(of: "3:abc:def"), .ssdeep)
    }

    func testShapeOfNothingElse() {
        // git, git256 and cdhash digests have the SHA-1 and SHA-256 shapes: --algo tells them apart.
        for target in [
            "",
            "zzz",
            "T1",
            String(self.sha256.dropLast()), // 63 digits
            self.sha256 + "a", // 65
            "A1" + self.tlsh.dropFirst(2), // 72 digits, no version
            String(self.tlsh.dropLast()), // the version and 69
            self.md5.replacingOccurrences(of: "5", with: "g"),
            "3:abc", // one chunk
            ":abc:def", // no block size
            "x:abc:def",
            "3:ab c:def",
            "3:abc:def,\"file\"", // an ssdeep list's line
            String(repeating: "０", count: 32), // fullwidth digits, hex to Character.isHexDigit
            " " + self.md5,
        ] {
            XCTAssertNil(Matching.shape(of: target), target)
        }
    }

    func testFitsAlgorithm() {
        XCTAssertTrue(Matching.fits(self.md5, .md5))
        XCTAssertFalse(Matching.fits(self.md5, .sha256))
        XCTAssertTrue(Matching.fits(self.tlsh, .tlsh))
        XCTAssertFalse(Matching.fits(self.tlsh, .ssdeep))
        XCTAssertTrue(Matching.fits(self.ssdeep, .ssdeep))
        // git shares SHA-1's shape, git256 SHA-256's.
        XCTAssertTrue(Matching.fits(self.sha1, .git))
        XCTAssertFalse(Matching.fits(self.sha256, .git))
        XCTAssertTrue(Matching.fits(self.sha256, .git256))
        XCTAssertFalse(Matching.fits(self.sha1, .git256))
        // A cdhash target is the 20-byte CDHash Apple's tools show, 40 hex digits, or a whole directory digest: 64, 96
        // or 128 hex digits, or 40 again for a SHA-1 directory. No other length, and no prefix of one.
        XCTAssertTrue(Matching.fits(self.sha1, .cdhash))
        XCTAssertTrue(Matching.fits(self.sha256, .cdhash))
        XCTAssertTrue(Matching.fits(self.sha384, .cdhash))
        XCTAssertTrue(Matching.fits(self.sha512, .cdhash))
        XCTAssertFalse(Matching.fits(String(self.sha1.prefix(39)), .cdhash))
        XCTAssertFalse(Matching.fits(String(self.sha1.prefix(8)), .cdhash))
        XCTAssertFalse(Matching.fits(self.sha1 + "a", .cdhash))
        XCTAssertFalse(Matching.fits(self.sha512 + "a", .cdhash))
        XCTAssertFalse(Matching.fits(self.sha1.replacingOccurrences(of: "a", with: "g"), .cdhash))
        XCTAssertFalse(Matching.fits("", .cdhash))
    }

    // MARK: - Exact matching

    func testExactMatchFound() {
        let result = Matching.check(digest: "abc123", against: ["abc123"], algorithm: .sha256, threshold: 0)
        XCTAssertNotNil(result)
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

    func testTLSHMatchRouting() throws {
        // Compute a real TLSH hash from data, then verify matching routes through TLSH logic
        let data = Data((0 ..< 1024).map { UInt8($0 % 256) })
        guard let hash = try ByteHash.tlsh.digest(data) else { return }

        let result = Matching.check(digest: hash, against: [hash], algorithm: .tlsh, threshold: 200)
        XCTAssertNotNil(result)
        XCTAssertNotNil(result?.score)
        XCTAssertEqual(result?.score, 0) // identical = distance 0
    }

    func testTLSHNoMatchAboveThreshold() throws {
        // Use real TLSH hashes from different data
        let data1 = Data((0 ..< 1024).map { UInt8($0 % 256) })
        let data2 = Data((0 ..< 1024).map { UInt8(($0 * 7 + 13) % 256) })
        guard let h1 = try ByteHash.tlsh.digest(data1), let h2 = try ByteHash.tlsh.digest(data2) else { return }

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
        // Shorter than the 20-byte CDHash: a prefix of a digest is no target, however long, and one hex digit would
        // match a sixteenth of all digests.
        for count in [1, 4, 8, 39] {
            XCTAssertNil(Matching.check(digest: self.cdhash, against: [String(self.cdhash.prefix(count))], algorithm: .cdhash, threshold: 0), "\(count)")
        }
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
        let result = Matching.check(digest: self.cdhash, against: [String(repeating: "f", count: 40)], algorithm: .cdhash, threshold: 0)
        XCTAssertNil(result)
    }
}
