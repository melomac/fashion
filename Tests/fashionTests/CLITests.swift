@testable import fashion
import XCTest

final class CLITests: XCTestCase {
    /**
     The message the command line prints for `arguments`, or nil when they are valid.
     */
    private func error(_ arguments: [String]) -> String? {
        do {
            _ = try Hasher.parse(arguments)
            return nil
        } catch {
            return Hasher.message(for: error)
        }
    }

    func testNegativeCountsAreRefused() {
        // `--jobs -7` reads `-7` as an option; joined with "=", the value reaches validation.
        XCTAssertEqual(self.error(["--jobs=-7"]), "--jobs must be zero or greater.")
        XCTAssertEqual(self.error(["--score=-1"]), "--score must be zero or greater.")
    }

    private let md5 = "5d41402abc4b2a76b9719d911017c592"
    private let sha1 = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
    private let sha256 = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    private let tlsh = "T13D338D7A3B0DE1A6C29CC134A5EFCB829D63F9151D7863432B91C5792FC86942F21B4B"

    func testXlenNeedsTLSHTarget() {
        // --xlen only changes how TLSH digests are compared: anywhere else it would be silently ignored. A TLSH target
        // among others is enough, with --algo tlsh or typed by its shape.
        let refused = "--xlen requires a TLSH digest to --match."
        XCTAssertEqual(self.error(["x", "--xlen"]), refused)
        XCTAssertEqual(self.error(["x", "--algo", "tlsh", "--xlen"]), refused)
        XCTAssertEqual(self.error(["x", "--algo", "ssdeep", "--match", "3:a:b", "--xlen"]), refused)
        XCTAssertEqual(self.error(["x", "--match", self.md5, "--xlen"]), refused)
        XCTAssertNil(self.error(["x", "--algo", "tlsh", "--match", self.tlsh, "--xlen"]))
        XCTAssertNil(self.error(["x", "--match", self.tlsh, "--xlen"]))
        XCTAssertNil(self.error(["x", "--match", self.md5, "--match", self.tlsh, "--xlen"]))
    }

    func testTargetsMustBeShapedLikeAlgorithm() throws {
        // With --algo, every target must be shaped like that algorithm's digests: one shaped otherwise would scan
        // everything and match nothing.
        XCTAssertEqual(self.error(["x", "--algo", "md5", "--match", self.sha256]), "--match '\(self.sha256)' is not shaped like md5 digests.")
        XCTAssertEqual(self.error(["x", "--algo", "tlsh", "--match", "T1"]), "--match 'T1' is not shaped like tlsh digests.")
        XCTAssertEqual(self.error(["x", "--algo", "ssdeep", "--match", self.md5]), "--match '\(self.md5)' is not shaped like ssdeep digests.")
        XCTAssertNil(self.error(["x", "--algo", "md5", "--match", self.md5]))
        XCTAssertNil(self.error(["x", "--algo", "tlsh", "--match", self.tlsh, "--match", String(self.tlsh.dropFirst(2))]))
        XCTAssertNil(self.error(["x", "--algo", "ssdeep", "--match", "3:abc:def"]))
        // git and git256 digests are shaped like SHA-1 and SHA-256 ones; a cdhash target is the 20-byte CDHash Apple's
        // tools show or a whole directory digest, never a shorter prefix.
        XCTAssertNil(self.error(["x", "--algo", "git", "--match", self.sha1]))
        XCTAssertEqual(self.error(["x", "--algo", "git", "--match", self.sha256]), "--match '\(self.sha256)' is not shaped like git digests.")
        XCTAssertNil(self.error(["x", "--algo", "git256", "--match", self.sha256]))
        XCTAssertEqual(self.error(["x", "--algo", "git256", "--match", self.sha1]), "--match '\(self.sha1)' is not shaped like git256 digests.")
        XCTAssertNil(self.error(["x", "--algo", "cdhash", "--match", self.sha1]))
        XCTAssertNil(self.error(["x", "--algo", "cdhash", "--match", self.sha256]))
        XCTAssertEqual(self.error(["x", "--algo", "cdhash", "--match", String(self.sha1.prefix(39))]), "--match '\(self.sha1.prefix(39))' is not shaped like cdhash digests.")
        XCTAssertEqual(self.error(["x", "--algo", "cdhash", "--match", String(self.sha1.prefix(8))]), "--match '\(self.sha1.prefix(8))' is not shaped like cdhash digests.")
        XCTAssertEqual(self.error(["x", "--algo", "cdhash", "--match", "nothexvalue!!!"]), "--match 'nothexvalue!!!' is not shaped like cdhash digests.")
        // A usage error, exit 64 before anything is hashed.
        let (status, errors) = try runFashion(["--algo", "md5", "--match", self.sha256, "."])
        XCTAssertEqual(status, 64) // EX_USAGE
        XCTAssertEqual(errors.first, "Error: --match '\(self.sha256)' is not shaped like md5 digests.")
    }

    func testTargetsOfNoShapeAreRefused() throws {
        // Without --algo the shape of a target picks its algorithm, so one shaped like no digest would scan everything
        // and match nothing. A SHA-1 or SHA-256 shape is a file's digest, never a git blob's or a cdhash: those take --algo.
        let noShape = { (target: String) in "--match '\(target)' is not shaped like MD5, SHA-1, SHA-2, ssdeep or TLSH digests; git, git256 and cdhash take --algo." }
        XCTAssertEqual(self.error(["x", "--match", "zzz"]), noShape("zzz"))
        XCTAssertEqual(self.error(["x", "--match", ""]), noShape(""))
        XCTAssertEqual(self.error(["x", "--match", self.md5, "--match", "T1"]), noShape("T1"))
        XCTAssertEqual(self.error(["x", "--match", String(self.sha1.prefix(8))]), noShape(String(self.sha1.prefix(8))))
        XCTAssertNil(self.error(["x", "--match", self.md5, "--match", self.sha256, "--match", self.tlsh, "--match", "3:abc:def"]))
        XCTAssertEqual(try Digester(Hasher.parse(["x", "--match", self.sha1, "--match", self.sha256])).algorithms, [.sha1, .sha256])
        // A usage error, exit 64 before anything is hashed.
        let (status, errors) = try runFashion(["--match", "zzz", "."])
        XCTAssertEqual(status, 64) // EX_USAGE
        XCTAssertEqual(errors.first, "Error: " + noShape("zzz"))
    }

    func testArgumentsMustBeUTF8() throws {
        // CommandLine.arguments repairs bytes that are not UTF-8 to U+FFFD, another path that may name another file:
        // the run is refused before anything is hashed. A Japanese name is UTF-8 like any other.
        let dir = FileManager.default.temporaryDirectory / "fashion-argv-\(UUID())"
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer {
            try? FileManager.default.removeItem(at: dir)
        }
        let japanese = dir / "日本語"
        try Data("x".utf8).write(to: japanese)

        XCTAssertEqual(try runFashion([japanese.path]).status, 0)
        // sh makes the byte itself: a Swift string cannot hold it.
        let (status, errors) = try runFashion([japanese.path], sh: #"exec "$0" "$1" "$(printf '\377')""#)
        XCTAssertEqual(status, 64) // EX_USAGE
        XCTAssertEqual(errors.first, "Error: Argument 2 is not valid UTF-8.")
    }

    func testJobsResolveToTheProcessors() throws {
        let processors = ProcessInfo.processInfo.activeProcessorCount
        XCTAssertEqual(try Hasher.parse([]).scan.resolvedJobs, 1)
        XCTAssertEqual(try Hasher.parse(["--jobs=0"]).scan.resolvedJobs, processors)
        XCTAssertEqual(try Hasher.parse(["--jobs=1"]).scan.resolvedJobs, 1)
        XCTAssertEqual(try Hasher.parse(["--jobs=\(processors + 1)"]).scan.resolvedJobs, processors)
        // -J is --jobs 0, and says so rather than letting one silently win over the other.
        XCTAssertEqual(try Hasher.parse(["-J"]).scan.resolvedJobs, processors)
        XCTAssertEqual(self.error(["-J", "--jobs=0"]), "-J and --jobs are mutually exclusive.")
        XCTAssertEqual(self.error(["-J", "-j", "4"]), "-J and --jobs are mutually exclusive.")
    }

    func testHashIsTheDefaultSubcommand() throws {
        // `fashion [options] <paths>` reads as it did before subcommands: the root runs `hash` unless another is named,
        // and `fashion hash` spells it out. The option groups of a default subcommand are validated like any other.
        for arguments in [["--algo", "md5", "-J", "x"], ["hash", "--algo", "md5", "-J", "x"]] {
            let command = try XCTUnwrap(Fashion.parseAsRoot(arguments) as? Hasher)
            XCTAssertEqual(command.algo, .md5)
            XCTAssertEqual(command.scan.paths, ["x"])
            XCTAssertTrue(command.scan.allJobs)
        }
        XCTAssertEqual(try XCTUnwrap(Fashion.parseAsRoot([]) as? Hasher).scan.paths, ["."])
        XCTAssertEqual(try XCTUnwrap(Fashion.parseAsRoot(["hash"]) as? Hasher).scan.paths, ["."])
        XCTAssertThrowsError(try Fashion.parseAsRoot(["hash", "-J", "--jobs=0"]))
        // The root has no help flag of its own: `fashion --help` prints the default subcommand's help, every option
        // included, and `fashion help` lists the subcommands.
        func stdout(_ arguments: [String]) throws -> String {
            let process = Process()
            process.executableURL = try fashionExecutable()
            process.arguments = arguments
            let pipe = Pipe()
            process.standardOutput = pipe
            process.standardError = FileHandle.nullDevice
            try process.run()
            let output = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            process.waitUntilExit()
            return output
        }
        XCTAssertTrue(try stdout(["--help"]).contains("USAGE: fashion [hash] [<options>] [<paths> ...]"))
        XCTAssertTrue(try stdout(["help"]).contains("SUBCOMMANDS:"))
        // End to end, through the binary, both spellings.
        XCTAssertEqual(try runFashion(["--algo", "md5", "-q", "/bin/ls"]).status, 0)
        XCTAssertEqual(try runFashion(["hash", "--algo", "md5", "-q", "/bin/ls"]).status, 0)
    }
}
