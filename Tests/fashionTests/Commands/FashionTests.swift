@testable import fashion
import XCTest

final class FashionTests: XCTestCase {
    func testNegativeJobsAreRefused() {
        // `--jobs -7` reads `-7` as an option; joined with "=", the value reaches validation.
        XCTAssertEqual(usageError(["--jobs=-7"]), "--jobs must be zero or greater.")
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
        XCTAssertEqual(usageError(["-J", "--jobs=0"]), "-J and --jobs are mutually exclusive.")
        XCTAssertEqual(usageError(["-J", "-j", "4"]), "-J and --jobs are mutually exclusive.")
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
