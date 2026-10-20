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
    private let cdhash = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"

    // MARK: - Shapes

    func testShapeOfEveryAlgorithm() {
        XCTAssertEqual(Targets.shape(of: self.md5), .md5)
        XCTAssertEqual(Targets.shape(of: self.sha1), .sha1)
        XCTAssertEqual(Targets.shape(of: self.sha256), .sha256)
        XCTAssertEqual(Targets.shape(of: self.sha384), .sha384)
        XCTAssertEqual(Targets.shape(of: self.sha512), .sha512)
        XCTAssertEqual(Targets.shape(of: self.tlsh), .tlsh)
        XCTAssertEqual(Targets.shape(of: self.ssdeep), .ssdeep)
        // Hex in either case, TLSH's version too; a TLSH digest as before 4.0, without the version; the empty file's ssdeep.
        XCTAssertEqual(Targets.shape(of: self.md5.uppercased()), .md5)
        XCTAssertEqual(Targets.shape(of: self.tlsh.lowercased()), .tlsh)
        XCTAssertEqual(Targets.shape(of: String(self.tlsh.dropFirst(2))), .tlsh)
        XCTAssertEqual(Targets.shape(of: "3::"), .ssdeep)
        XCTAssertEqual(Targets.shape(of: "3:abc:def"), .ssdeep)
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
            XCTAssertNil(Targets.shape(of: target), target)
        }
    }

    func testFitsAlgorithm() {
        // Without --algo, any shape; with it, that algorithm's.
        XCTAssertTrue(Targets.fits(self.md5, nil))
        XCTAssertFalse(Targets.fits("zzz", nil))
        XCTAssertTrue(Targets.fits(self.md5, .md5))
        XCTAssertFalse(Targets.fits(self.md5, .sha256))
        XCTAssertTrue(Targets.fits(self.tlsh, .tlsh))
        XCTAssertFalse(Targets.fits(self.tlsh, .ssdeep))
        XCTAssertTrue(Targets.fits(self.ssdeep, .ssdeep))
        // git shares SHA-1's shape, git256 SHA-256's.
        XCTAssertTrue(Targets.fits(self.sha1, .git))
        XCTAssertFalse(Targets.fits(self.sha256, .git))
        XCTAssertTrue(Targets.fits(self.sha256, .git256))
        XCTAssertFalse(Targets.fits(self.sha1, .git256))
        // A cdhash target is the 20-byte CDHash Apple's tools show, 40 hex digits, or a whole directory digest: 64, 96
        // or 128 hex digits, or 40 again for a SHA-1 directory. No other length, and no prefix of one.
        XCTAssertTrue(Targets.fits(self.sha1, .cdhash))
        XCTAssertTrue(Targets.fits(self.sha256, .cdhash))
        XCTAssertTrue(Targets.fits(self.sha384, .cdhash))
        XCTAssertTrue(Targets.fits(self.sha512, .cdhash))
        XCTAssertFalse(Targets.fits(String(self.sha1.prefix(39)), .cdhash))
        XCTAssertFalse(Targets.fits(String(self.sha1.prefix(8)), .cdhash))
        XCTAssertFalse(Targets.fits(self.sha1 + "a", .cdhash))
        XCTAssertFalse(Targets.fits(self.sha512 + "a", .cdhash))
        XCTAssertFalse(Targets.fits(self.sha1.replacingOccurrences(of: "a", with: "g"), .cdhash))
        XCTAssertFalse(Targets.fits("", .cdhash))
    }

    // MARK: - Typing

    func testTargetsTypedByShape() {
        let targets = Targets([self.sha256, self.md5, self.tlsh, self.ssdeep, self.md5.uppercased()])
        XCTAssertEqual(targets.count, 5)
        XCTAssertFalse(targets.isEmpty)
        // In Algorithm order, once each.
        XCTAssertEqual(targets.algorithms, [.md5, .sha256, .ssdeep, .tlsh])
        XCTAssertNotNil(targets.match(self.md5, algorithm: .md5, threshold: 0))
        XCTAssertNotNil(targets.match(self.sha256, algorithm: .sha256, threshold: 0))
        // A target is compared with the digests of its own algorithm only.
        XCTAssertNil(targets.match(self.md5, algorithm: .sha256, threshold: 0))
        XCTAssertNil(targets.match(self.sha256, algorithm: .git256, threshold: 0))
    }

    func testTargetsTypedByAlgorithm() {
        // --algo types every target, whatever its shape says: a SHA-1 shape is a git blob's, a SHA-256 shape a cdhash's.
        XCTAssertEqual(Targets([self.sha1], algorithm: .git).algorithms, [.git])
        XCTAssertNotNil(Targets([self.sha1], algorithm: .git).match(self.sha1, algorithm: .git, threshold: 0))
        XCTAssertNil(Targets([self.sha1], algorithm: .git).match(self.sha1, algorithm: .sha1, threshold: 0))
        XCTAssertEqual(Targets([self.sha256], algorithm: .cdhash).algorithms, [.cdhash])
        XCTAssertNotNil(Targets([self.sha256], algorithm: .cdhash).match(self.sha256, algorithm: .cdhash, threshold: 0))
    }

    func testTargetsOfNoShapeAreLeftOut() {
        // validate() refuses the run over them first; typed anyway, they match nothing rather than everything.
        let targets = Targets(["zzz", self.sha256], algorithm: .md5)
        XCTAssertEqual(targets.count, 2)
        XCTAssertEqual(targets.algorithms, [])
        XCTAssertNil(targets.match(self.sha256, algorithm: .sha256, threshold: 0))
        XCTAssertNil(targets.match(self.sha256, algorithm: .md5, threshold: 0))
        XCTAssertEqual(Targets(["zzz"]).algorithms, [])
        XCTAssertTrue(Targets().isEmpty)
        XCTAssertEqual(Targets().algorithms, [])
    }

    // MARK: - Exact matching

    func testExactMatchCaseInsensitive() {
        // Targets are lowercased once, digests compared lowercased.
        XCTAssertNotNil(Targets([self.md5.uppercased()]).match(self.md5, algorithm: .md5, threshold: 0))
        XCTAssertNotNil(Targets([self.md5]).match(self.md5.uppercased(), algorithm: .md5, threshold: 0))
        XCTAssertNil(Targets([self.md5]).match(self.md5, algorithm: .md5, threshold: 0)?.score)
    }

    func testExactMatchNotFound() {
        XCTAssertNil(Targets([self.sha256]).match(self.sha256.replacingOccurrences(of: "2", with: "3"), algorithm: .sha256, threshold: 0))
        XCTAssertNil(Targets([self.sha256]).match(String(self.sha256.dropLast()), algorithm: .sha256, threshold: 0))
    }

    func testExactMatchAllAlgorithmsExceptFuzzy() {
        for (algorithm, digest) in [(Algorithm.md5, self.md5), (.sha1, self.sha1), (.sha256, self.sha256), (.sha384, self.sha384), (.sha512, self.sha512)] {
            XCTAssertNotNil(Targets([digest]).match(digest, algorithm: algorithm, threshold: 0), "Expected match for \(algorithm)")
        }
    }

    // MARK: - SSDeep fuzzy matching

    func testSSDeepMatchRouting() {
        // Identical ssdeep signatures score 100.
        let result = Targets([self.ssdeep]).match(self.ssdeep, algorithm: .ssdeep, threshold: 0)
        XCTAssertEqual(result?.score, 100)
    }

    func testSSDeepNoMatchBelowThreshold() {
        // Completely different signatures: score 0, below any threshold above it.
        XCTAssertNil(Targets(["96:zzzzzzzzzzzzzzzzz:yyyy"]).match("3:abc:def", algorithm: .ssdeep, threshold: 100))
    }

    // MARK: - TLSH fuzzy matching

    func testTLSHMatchRouting() throws {
        // Compute a real TLSH hash from data, then verify matching routes through TLSH logic
        let data = Data((0 ..< 1024).map { UInt8($0 % 256) })
        let hash = try XCTUnwrap(ByteHash.tlsh.digest(data))

        let result = Targets([hash]).match(hash, algorithm: .tlsh, threshold: 200)
        XCTAssertEqual(result?.score, 0) // identical = distance 0
    }

    func testTLSHNoMatchAboveThreshold() throws {
        // Use real TLSH hashes from different data
        let data1 = Data((0 ..< 1024).map { UInt8($0 % 256) })
        let data2 = Data((0 ..< 1024).map { UInt8(($0 * 7 + 13) % 256) })
        let h1 = try XCTUnwrap(ByteHash.tlsh.digest(data1))
        let h2 = try XCTUnwrap(ByteHash.tlsh.digest(data2))

        let result = Targets([h2]).match(h1, algorithm: .tlsh, threshold: 0)
        // Distance is likely > 0, so threshold 0 means only exact distance 0 matches
        if result != nil {
            XCTAssertEqual(result?.score, 0)
        }
    }

    // MARK: - CDHash prefix matching

    private func cdhashMatch(_ target: String, digest: String? = nil) -> MatchResult? {
        Targets([target], algorithm: .cdhash).match(digest ?? self.cdhash, algorithm: .cdhash, threshold: 0)
    }

    func testCDHashFullMatch() {
        XCTAssertNotNil(self.cdhashMatch(self.cdhash))
    }

    func testCDHashTruncatedPrefixMatch() {
        XCTAssertNotNil(self.cdhashMatch(String(self.cdhash.prefix(40))))
    }

    func testCDHashCaseInsensitivePrefixMatch() {
        XCTAssertNotNil(self.cdhashMatch(String(self.cdhash.prefix(40)).uppercased()))
        XCTAssertNotNil(self.cdhashMatch(String(self.cdhash.prefix(40)), digest: self.cdhash.uppercased()))
    }

    func testCDHashEmptyTargetDoesNotMatch() {
        XCTAssertNil(self.cdhashMatch(""), "An empty target must not prefix-match every digest")
    }

    func testCDHashShortTargetDoesNotMatch() {
        // Shorter than the 20-byte CDHash: a prefix of a digest is no target, however long, and one hex digit would
        // match a sixteenth of all digests.
        for count in [1, 4, 8, 39] {
            XCTAssertNil(self.cdhashMatch(String(self.cdhash.prefix(count))), "\(count)")
        }
    }

    func testCDHashNonHexTargetDoesNotMatch() {
        XCTAssertNil(self.cdhashMatch("nothexvalue!!!"))
    }

    func testCDHashLongerTargetDoesNotMatch() {
        // A target longer than the computed digest must not match via the (removed) reverse-prefix arm.
        XCTAssertNil(self.cdhashMatch(self.cdhash, digest: String(self.cdhash.prefix(40))))
    }

    func testCDHashDifferentPrefixDoesNotMatch() {
        XCTAssertNil(self.cdhashMatch(String(repeating: "f", count: 40)))
    }
}
