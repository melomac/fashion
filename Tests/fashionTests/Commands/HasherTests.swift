@testable import fashion
import XCTest

/**
 The options of the hash subcommand: what they refuse, and how targets are typed.
 */
final class HasherTests: XCTestCase {
    func testNegativeScoreIsRefused() {
        // `--score -1` reads `-1` as an option; joined with "=", the value reaches validation.
        XCTAssertEqual(usageError(["--score=-1"]), "--score must be zero or greater.")
    }

    func testUnsignDoesNotApplyToSymbolsOrXarToc() {
        // A signature changes neither the symbols nor a XAR table of contents, so --unsign would be silently ignored.
        let refused = "--unsign does not apply to --symhash or --xar-toc."
        XCTAssertEqual(usageError(["x", "--unsign", "--symhash"]), refused)
        XCTAssertEqual(usageError(["x", "--unsign", "--xar-toc"]), refused)
        XCTAssertNil(usageError(["x", "--unsign", "--slices", "--exact"]))
        XCTAssertNil(usageError(["x", "--unsign", "--algo", "cdhash"]))
    }

    func testUnpackDoesNotApplyToXarToc() {
        // A XAR archive is no Mach-O for UPX to have packed; the symbols of one it packed are those of its original.
        XCTAssertEqual(usageError(["x", "--unpack", "--xar-toc"]), "--unpack does not apply to --xar-toc.")
        XCTAssertNil(usageError(["x", "--unpack", "--symhash"]))
        XCTAssertNil(usageError(["x", "--unpack", "--unsign", "--slices", "--exact"]))
    }

    private let md5 = "5d41402abc4b2a76b9719d911017c592"
    private let sha1 = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
    private let sha256 = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    private let tlsh = "T13D338D7A3B0DE1A6C29CC134A5EFCB829D63F9151D7863432B91C5792FC86942F21B4B"

    func testXlenNeedsTLSHTarget() {
        // --xlen only changes how TLSH digests are compared: anywhere else it would be silently ignored. A TLSH target
        // among others is enough, with --algo tlsh or typed by its shape.
        let refused = "--xlen requires a TLSH digest to --match."
        XCTAssertEqual(usageError(["x", "--xlen"]), refused)
        XCTAssertEqual(usageError(["x", "--algo", "tlsh", "--xlen"]), refused)
        XCTAssertEqual(usageError(["x", "--algo", "ssdeep", "--match", "3:a:b", "--xlen"]), refused)
        XCTAssertEqual(usageError(["x", "--match", self.md5, "--xlen"]), refused)
        XCTAssertNil(usageError(["x", "--algo", "tlsh", "--match", self.tlsh, "--xlen"]))
        XCTAssertNil(usageError(["x", "--match", self.tlsh, "--xlen"]))
        XCTAssertNil(usageError(["x", "--match", self.md5, "--match", self.tlsh, "--xlen"]))
    }

    func testTargetsMustBeShapedLikeAlgorithm() throws {
        // With --algo, every target must be shaped like that algorithm's digests: one shaped otherwise would scan
        // everything and match nothing.
        XCTAssertEqual(usageError(["x", "--algo", "md5", "--match", self.sha256]), "--match '\(self.sha256)' is not shaped like md5 digests.")
        XCTAssertEqual(usageError(["x", "--algo", "tlsh", "--match", "T1"]), "--match 'T1' is not shaped like tlsh digests.")
        XCTAssertEqual(usageError(["x", "--algo", "ssdeep", "--match", self.md5]), "--match '\(self.md5)' is not shaped like ssdeep digests.")
        XCTAssertNil(usageError(["x", "--algo", "md5", "--match", self.md5]))
        XCTAssertNil(usageError(["x", "--algo", "tlsh", "--match", self.tlsh, "--match", String(self.tlsh.dropFirst(2))]))
        XCTAssertNil(usageError(["x", "--algo", "ssdeep", "--match", "3:abc:def"]))
        // git and git256 digests are shaped like SHA-1 and SHA-256 ones; a cdhash target is the 20-byte CDHash Apple's
        // tools show or a whole directory digest, never a shorter prefix.
        XCTAssertNil(usageError(["x", "--algo", "git", "--match", self.sha1]))
        XCTAssertEqual(usageError(["x", "--algo", "git", "--match", self.sha256]), "--match '\(self.sha256)' is not shaped like git digests.")
        XCTAssertNil(usageError(["x", "--algo", "git256", "--match", self.sha256]))
        XCTAssertEqual(usageError(["x", "--algo", "git256", "--match", self.sha1]), "--match '\(self.sha1)' is not shaped like git256 digests.")
        XCTAssertNil(usageError(["x", "--algo", "cdhash", "--match", self.sha1]))
        XCTAssertNil(usageError(["x", "--algo", "cdhash", "--match", self.sha256]))
        XCTAssertEqual(usageError(["x", "--algo", "cdhash", "--match", String(self.sha1.prefix(39))]), "--match '\(self.sha1.prefix(39))' is not shaped like cdhash digests.")
        XCTAssertEqual(usageError(["x", "--algo", "cdhash", "--match", String(self.sha1.prefix(8))]), "--match '\(self.sha1.prefix(8))' is not shaped like cdhash digests.")
        XCTAssertEqual(usageError(["x", "--algo", "cdhash", "--match", "nothexvalue!!!"]), "--match 'nothexvalue!!!' is not shaped like cdhash digests.")
        // A usage error, exit 64 before anything is hashed.
        let (status, errors) = try runFashion(["--algo", "md5", "--match", self.sha256, "."])
        XCTAssertEqual(status, 64) // EX_USAGE
        XCTAssertEqual(errors.first, "Error: --match '\(self.sha256)' is not shaped like md5 digests.")
    }

    func testTargetsOfNoShapeAreRefused() throws {
        // Without --algo the shape of a target picks its algorithm, so one shaped like no digest would scan everything
        // and match nothing. A SHA-1 or SHA-256 shape is a file's digest, never a git blob's or a cdhash: those take --algo.
        let noShape = { (target: String) in "--match '\(target)' is not shaped like MD5, SHA-1, SHA-2, ssdeep or TLSH digests; git, git256 and cdhash take --algo." }
        XCTAssertEqual(usageError(["x", "--match", "zzz"]), noShape("zzz"))
        XCTAssertEqual(usageError(["x", "--match", ""]), noShape(""))
        XCTAssertEqual(usageError(["x", "--match", self.md5, "--match", "T1"]), noShape("T1"))
        XCTAssertEqual(usageError(["x", "--match", String(self.sha1.prefix(8))]), noShape(String(self.sha1.prefix(8))))
        XCTAssertNil(usageError(["x", "--match", self.md5, "--match", self.sha256, "--match", self.tlsh, "--match", "3:abc:def"]))
        XCTAssertEqual(try Digester(Hasher.parse(["x", "--match", self.sha1, "--match", self.sha256])).algorithms, [.sha1, .sha256])
        // A usage error, exit 64 before anything is hashed.
        let (status, errors) = try runFashion(["--match", "zzz", "."])
        XCTAssertEqual(status, 64) // EX_USAGE
        XCTAssertEqual(errors.first, "Error: " + noShape("zzz"))
    }
}
