@testable import fashion
import XCTest

/**
 `fashion unsign`: a file written out beside it without its code signatures, whole: a universal file as `lipo` lays its
 unsigned architectures out, a thin file as `thin --unsign` writes it; one with no signature to remove gets nothing.
 */
final class UnsignerTests: XCTestCase {
    private func directory(_ name: String) throws -> URL {
        let url = FileManager.default.temporaryDirectory / "fashion-unsign-\(name)-\(UUID())"
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    /// The lines hash mode prints for `path` with `arguments`.
    private func hashLines(_ path: String, _ arguments: [String] = []) throws -> [String] {
        try Digester(Hasher.parse([path, "--quiet"] + arguments)).lines(for: path, reporter: Reporter(console: Console())).map(\.text)
    }

    func testUniversalFileIsWrittenWholeAsLipoLaysItOut() throws {
        // /bin/ls unsigned whole is what hash mode's --unsign hashes, and the universal file lipo makes of the slices
        // thin --unsign writes, byte for byte: codesign moved every architecture to 16 KiB, lipo aligns x86_64 to 4 KiB.
        // The artifact itself has nothing to unsign.
        let directory = try self.directory("universal")
        defer {
            try? FileManager.default.removeItem(at: directory)
        }
        let ls = directory / "ls"
        try FileManager.default.copyItem(at: URL(fileURLWithPath: "/bin/ls"), to: ls)
        guard case .fat = try Universal.open(path: ls.path) else {
            throw XCTSkip("/bin/ls is not universal")
        }
        let reporter = Reporter(console: Console())
        let artifact = directory / "ls_unsigned"
        XCTAssertEqual(Unsigner.lines(for: ls.path, exact: false, overwrite: false, reporter: reporter).map(\.text), [artifact.path])
        let unsigned = try Data(contentsOf: artifact)
        XCTAssertEqual(try self.hashLines(ls.path, ["--unsign"]), try [ByteHash.sha256.digest(unsigned)])
        XCTAssertEqual(try self.hashLines(artifact.path, ["--unsign"]), try [ByteHash.sha256.digest(unsigned)])

        let slices = Thinner.lines(for: ls.path, exact: false, unsign: true, unpack: false, overwrite: false, reporter: reporter).map(\.text)
        XCTAssertGreaterThan(slices.count, 1)
        let lipo = directory / "lipo"
        try XCTSkipUnless(execute("/usr/bin/xcrun", ["lipo", "-create"] + slices + ["-output", lipo.path]), "cannot run lipo")
        XCTAssertEqual(unsigned, try Data(contentsOf: lipo))

        XCTAssertEqual(Unsigner.lines(for: artifact.path, exact: false, overwrite: false, reporter: reporter).count, 0)
        // A second run finds the artifact in place.
        XCTAssertEqual(Unsigner.lines(for: ls.path, exact: false, overwrite: false, reporter: reporter).map(\.text), [artifact.path])
        XCTAssertEqual(reporter.errorCount, 0)
    }

    func testThinFileIsWrittenAsThinWritesIt() throws {
        // An x86_64 image as the linker leaves it, signed by codesign: unsign gives it back, named as thin --unsign names
        // it, through the root command too; the original, and a file that is not Mach-O, get nothing.
        let directory = try self.directory("thin")
        defer {
            try? FileManager.default.removeItem(at: directory)
        }
        let original = try compile("sample", in: directory, ["-arch", "x86_64"])
        let data = try Data(contentsOf: original)
        let signed = directory / "signed"
        try FileManager.default.createDirectory(at: signed, withIntermediateDirectories: false)
        try data.write(to: signed / "sample")
        _ = try codesign(["-s", "-", (signed / "sample").path])
        try Data("text\n".utf8).write(to: signed / "text")

        let reporter = Reporter(console: Console())
        XCTAssertEqual(Unsigner.lines(for: (signed / "sample").path, exact: false, overwrite: false, reporter: reporter).map(\.text), [(signed / "sample_unsigned").path])
        XCTAssertEqual(try Data(contentsOf: signed / "sample_unsigned"), data)
        XCTAssertEqual(Unsigner.lines(for: original.path, exact: false, overwrite: false, reporter: reporter).count, 0)
        XCTAssertEqual(Unsigner.lines(for: (signed / "text").path, exact: false, overwrite: false, reporter: reporter).count, 0)
        XCTAssertEqual(reporter.errorCount, 0)

        try FileManager.default.removeItem(at: signed / "sample_unsigned")
        let command = try XCTUnwrap(Fashion.parseAsRoot(["unsign", signed.path]) as? Unsigner)
        XCTAssertEqual(command.scan(), 0)
        XCTAssertEqual(try Data(contentsOf: signed / "sample_unsigned"), data)
        XCTAssertEqual(Thinner.lines(for: (signed / "sample").path, exact: false, unsign: true, unpack: false, overwrite: false, reporter: reporter).map(\.text), [(signed / "sample_unsigned").path])
    }

    func testExactCutsAppendedBytesBeforeTheSignatureComesOff() throws {
        // Eight bytes after the signature would be cut off with it: reported and nothing written, as codesign fails
        // too, unless --exact cuts them off first, which names the artifact for it.
        let directory = try self.directory("exact")
        defer {
            try? FileManager.default.removeItem(at: directory)
        }
        let original = try compile("sample", in: directory, ["-arch", "x86_64"])
        let data = try Data(contentsOf: original)
        let signed = directory / "signed"
        try data.write(to: signed)
        _ = try codesign(["-s", "-", signed.path])
        let file = directory / "appended"
        try (Data(contentsOf: signed) + Data(repeating: 0x4a, count: 8)).write(to: file)

        let reporter = Reporter(console: Console())
        let lines = Unsigner.lines(for: file.path, exact: false, overwrite: false, reporter: reporter)
        XCTAssertEqual(lines.count, 1)
        XCTAssertEqual(lines.first?.diagnostic, true)
        XCTAssertEqual(reporter.errorCount, 1)
        let (status, errors) = try runFashion(["unsign", file.path])
        XCTAssertEqual(status, 2)
        XCTAssertEqual(errors, ["fashion: \(file.path): LC_CODE_SIGNATURE does not point to end of file"])

        let artifact = directory / "appended_exact_unsigned"
        XCTAssertEqual(Unsigner.lines(for: file.path, exact: true, overwrite: false, reporter: Reporter(console: Console())).map(\.text), [artifact.path])
        XCTAssertEqual(try Data(contentsOf: artifact), data)
        XCTAssertFalse(FileManager.default.fileExists(atPath: (directory / "appended_unsigned").path))
    }
}
