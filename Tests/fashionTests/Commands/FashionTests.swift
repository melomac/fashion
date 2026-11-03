import ArgumentParser
@testable import fashion
import XCTest

final class FashionTests: XCTestCase {
    /**
     --jobs -7 reads `-7` as an option; joined with "=", the value reaches validation.
     */
    func testNegativeJobsAreRefused() {
        XCTAssertEqual(usageError(["--jobs=-7"]), "--jobs must be zero or greater.")
    }

    /**
     CommandLine.arguments repairs bytes that are not UTF-8 to U+FFFD, another path that may name another file:
     the run is refused before anything is hashed. A Japanese name is UTF-8 like any other.
     */
    func testArgumentsMustBeUTF8() throws {
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

    /**
     The copyright line claims one year until the year after fashion was first published, then a range; a clock set
     before publication still claims the first year.
     */
    func testCopyrightYears() {
        XCTAssertEqual(Fashion.copyrightYears(in: 2026), "2026")
        XCTAssertEqual(Fashion.copyrightYears(in: 2027), "2026-2027")
        XCTAssertEqual(Fashion.copyrightYears(in: 2025), "2026")
    }

    /**
     `fashion help` shows the copyright and the license; `fashion --help` falls through to `hash`, whose help does not.
     */
    func testHelpShowsTheCopyright() {
        let now = Calendar(identifier: .gregorian).component(.year, from: .now)
        let help = Fashion.helpMessage()
        XCTAssertTrue(help.contains("Copyright (c) Melomac \(Fashion.copyrightYears(in: now))"))
        XCTAssertTrue(help.contains("<https://codeberg.org/melomac/fashion/src/LICENSE>"))
        XCTAssertTrue(help.contains("<https://codeberg.org/melomac/fashion/src/NOTICE>"))

        XCTAssertTrue(Hasher.helpMessage().contains("Copyright"))
        XCTAssertTrue(Thinner.helpMessage().contains("Copyright"))
        XCTAssertTrue(Unpacker.helpMessage().contains("Copyright"))
        XCTAssertTrue(Unsigner.helpMessage().contains("Copyright"))
        XCTAssertTrue(Verify.helpMessage().contains("Copyright"))
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

    /**
     `fashion [options] <paths>` reads as it did before subcommands: the root runs `hash` unless another is named,
     and `fashion hash` spells it out. The option groups of a default subcommand are validated like any other.
     */
    func testHashIsTheDefaultSubcommand() throws {
        for arguments in [["--algo", "md5", "-J", "x"], ["hash", "--algo", "md5", "-J", "x"]] {
            let command = try XCTUnwrap(Fashion.parseAsRoot(arguments) as? Hasher)
            XCTAssertEqual(command.hash.algo, .md5)
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

    /**
     Each subcommand answers to one letter as well, `h` for `hash`, the default still, `t` for `thinr`, which
     answers to `thin` too, `i` for `unsign`, `p` for `unpack`, which answers to `upx` too, and `v` for `verify`,
     which `fashion help` lists beside the names.
     */
    func testSubcommandsAnswerToOneLetter() throws {
        XCTAssertEqual(try XCTUnwrap(Fashion.parseAsRoot(["h", "--algo", "md5", "x"]) as? Hasher).scan.paths, ["x"])
        for alias in Thinner.configuration.aliases {
            XCTAssertNotNil(try Fashion.parseAsRoot([alias, "x"]) as? Thinner, alias)
        }
        for alias in Unsigner.configuration.aliases {
            XCTAssertNotNil(try Fashion.parseAsRoot([alias, "x"]) as? Unsigner, alias)
        }
        for alias in Unpacker.configuration.aliases {
            XCTAssertNotNil(try Fashion.parseAsRoot([alias, "x"]) as? Unpacker, alias)
        }
        for alias in Verify.configuration.aliases {
            XCTAssertNotNil(try Fashion.parseAsRoot([alias, "x"]) as? Verify, alias)
        }
        XCTAssertTrue(Thinner.configuration.aliases.contains("t") && Thinner.configuration.aliases.contains("thinr"))
        XCTAssertEqual(Unsigner.configuration.aliases, ["i"])
        XCTAssertEqual(Unpacker.configuration.aliases, ["p", "upx"])
        XCTAssertEqual(Verify.configuration.aliases, ["v"])
        XCTAssertEqual(try XCTUnwrap(Fashion.parseAsRoot([]) as? Hasher).scan.paths, ["."], "hash stays the default")
        XCTAssertEqual(try runFashion(["h", "--algo", "md5", "-q", "/bin/ls"]).status, 0)

        let process = Process()
        process.executableURL = try fashionExecutable()
        process.arguments = ["help"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        try process.run()
        let listed = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        process.waitUntilExit()
        for command in [Hasher.self, Thinner.self, Unsigner.self, Unpacker.self, Verify.self] as [ParsableCommand.Type] {
            let name = try ([XCTUnwrap(command.configuration.commandName)] + command.configuration.aliases).joined(separator: ", ")
            XCTAssertTrue(listed.contains(name), name)
        }
        XCTAssertTrue(listed.contains("hash, h (default)"))
    }
}
