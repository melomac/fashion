@testable import fashion
import XCTest

/**
 `fashion unsign`: a file written out beside it without its code signatures, whole: a universal file as `lipo` lays its
 unsigned architectures out, a thin file as `thin --unsign` writes it; one nothing is done to gets nothing, and one
 whose signature appended bytes keep in is cut as needed, `_exact_unsigned`.
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

    /**
     `/bin/ls` unsigned whole is what hash mode's --unsign hashes, and the universal file `lipo` makes of the slices
     thin --unsign writes, byte for byte: `codesign` moved every architecture to 16 KiB, `lipo` aligns `x86_64` to 4 KiB.
     The artifact itself has nothing to unsign.
     */
    func testUniversalFileIsWrittenWholeAsLipoLaysItOut() throws {
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
        XCTAssertEqual(Unsigner.lines(for: ls.path, write: false, reporter: reporter).map(\.text), [artifact.path])
        let unsigned = try Data(contentsOf: artifact)
        XCTAssertEqual(try self.hashLines(ls.path, ["--unsign"]), try [ByteHash.sha256.digest(unsigned)])
        XCTAssertEqual(try self.hashLines(artifact.path, ["--unsign"]), try [ByteHash.sha256.digest(unsigned)])

        // thin leaves the signed slices beside the unsigned ones: lipo gets the unsigned ones.
        let slices = Thinner.lines(for: ls.path, exact: false, unsign: true, unpack: false, write: false, reporter: reporter).map(\.text).filter { $0.hasSuffix("_unsigned") }
        XCTAssertGreaterThan(slices.count, 1)
        let lipo = directory / "lipo"
        try XCTSkipUnless(execute("/usr/bin/xcrun", ["lipo", "-create"] + slices + ["-output", lipo.path]), "cannot run lipo")
        XCTAssertEqual(unsigned, try Data(contentsOf: lipo))

        XCTAssertEqual(Unsigner.lines(for: artifact.path, write: false, reporter: reporter).count, 0)
        // A second run finds the artifact in place.
        XCTAssertEqual(Unsigner.lines(for: ls.path, write: false, reporter: reporter).map(\.text), [artifact.path])
        XCTAssertEqual(reporter.errorCount, 0)
    }

    /**
     An `x86_64` image as the linker leaves it, signed by `codesign`: unsign gives it back, named as thin --unsign names
     it, through the root command too; the original, and a file that is not Mach-O, get nothing.
     */
    func testThinFileIsWrittenAsThinWritesIt() throws {
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
        XCTAssertEqual(Unsigner.lines(for: (signed / "sample").path, write: false, reporter: reporter).map(\.text), [(signed / "sample_unsigned").path])
        XCTAssertEqual(try Data(contentsOf: signed / "sample_unsigned"), data)
        XCTAssertEqual(Unsigner.lines(for: original.path, write: false, reporter: reporter).count, 0)
        XCTAssertEqual(Unsigner.lines(for: (signed / "text").path, write: false, reporter: reporter).count, 0)
        XCTAssertEqual(reporter.errorCount, 0)

        try FileManager.default.removeItem(at: signed / "sample_unsigned")
        let command = try XCTUnwrap(Fashion.parseAsRoot(["unsign", signed.path]) as? Unsigner)
        XCTAssertEqual(command.scan(), 0)
        XCTAssertEqual(try Data(contentsOf: signed / "sample_unsigned"), data)
        XCTAssertEqual(Thinner.lines(for: (signed / "sample").path, exact: false, unsign: true, unpack: false, write: false, reporter: reporter).map(\.text), [(signed / "sample_unsigned").path])
    }

    /**
     A file with no signature to remove is left alone, bytes appended to it included, as is one that ends where its
     image ends: the cut alone is thin --exact's, written as `_exact`, what hash mode's --exact --unsign reads.
     */
    func testAFileWithNoSignatureIsLeftAloneAppendedBytesIncluded() throws {
        let directory = try self.directory("no-signature")
        defer {
            try? FileManager.default.removeItem(at: directory)
        }
        let original = try compile("sample", in: directory, ["-arch", "x86_64"])
        let data = try Data(contentsOf: original)
        let padded = directory / "padded"
        try (data + Data(repeating: 0x4a, count: 8)).write(to: padded)

        let reporter = Reporter(console: Console())
        XCTAssertEqual(Unsigner.lines(for: padded.path, write: false, reporter: reporter).count, 0)
        XCTAssertEqual(Unpacker.lines(for: padded.path, write: false, reporter: reporter).count, 0)
        XCTAssertEqual(Unsigner.lines(for: original.path, write: false, reporter: reporter).count, 0)
        let artifact = directory / "padded_exact"
        XCTAssertEqual(Thinner.lines(for: padded.path, exact: true, unsign: false, unpack: false, write: false, reporter: reporter).map(\.text), [artifact.path])
        XCTAssertEqual(try Data(contentsOf: artifact), data)
        XCTAssertEqual(try self.hashLines(padded.path, ["--exact", "--unsign"]), try [XCTUnwrap(ByteHash.sha256.digest(data))])
        XCTAssertEqual(reporter.errorCount, 0)
    }

    /**
     A universal file whose `x86_64` image is signed and whose `arm64` image is unsigned with 8 bytes appended:
     unsign leaves the image nothing is done to as the fat table places it, appended bytes included, as hash mode
     reads the file whole under --exact --unsign too; thin --exact writes that image cut, and its line under --slices
     is the cut's, so the whole artifact is not what `lipo` makes of thin's exact slices.
     */
    func testAnArchitectureNothingIsDoneToIsLeftAsTheFatTablePlacesIt() throws {
        let directory = try self.directory("exact-untouched")
        defer {
            try? FileManager.default.removeItem(at: directory)
        }
        let x86 = try compile("x86", in: directory, ["-arch", "x86_64"])
        let arm = try compile("arm", in: directory, ["-arch", "arm64"])
        let signed = directory / "x86_signed"
        try FileManager.default.copyItem(at: x86, to: signed)
        _ = try codesign(["-s", "-", signed.path])
        let armData = try Data(contentsOf: arm)
        let padded = directory / "arm_padded"
        try (armData + Data(repeating: 0x4a, count: 8)).write(to: padded)
        let fat = directory / "fat"
        try XCTSkipUnless(execute("/usr/bin/xcrun", ["lipo", "-create", signed.path, padded.path, "-output", fat.path]), "cannot run lipo")

        let reporter = Reporter(console: Console())
        let artifact = directory / "fat_unsigned"
        XCTAssertEqual(Unsigner.lines(for: fat.path, write: false, reporter: reporter).map(\.text), [artifact.path])
        let written = try Data(contentsOf: artifact)
        XCTAssertEqual(try self.hashLines(fat.path, ["--exact", "--unsign"]), try [XCTUnwrap(ByteHash.sha256.digest(written))])
        guard case let .fat(archs) = try Universal.open(data: written), archs.count == 2 else {
            return XCTFail("the artifact is not universal")
        }
        XCTAssertEqual(Universal.sliceData(fileData: written, arch: archs[0]), try Data(contentsOf: x86))
        XCTAssertEqual(Universal.sliceData(fileData: written, arch: archs[1]), armData + Data(repeating: 0x4a, count: 8))

        let lines = Thinner.lines(for: fat.path, exact: true, unsign: true, unpack: false, write: false, reporter: reporter).map(\.text)
        XCTAssertEqual(Set(lines), Set(["fat_x86_64", "fat_x86_64_unsigned", "fat_arm64", "fat_arm64_exact"].map { (directory / $0).path }))
        XCTAssertEqual(try Data(contentsOf: directory / "fat_arm64_exact"), armData)
        XCTAssertEqual(try self.hashLines(fat.path, ["--exact", "--unsign", "--slices"]).last, try XCTUnwrap(ByteHash.sha256.digest(armData)))
        XCTAssertEqual(reporter.errorCount, 0)
    }

    /**
     Eight bytes after the signature would be cut off with it: hash mode's --unsign reports the file and hashes
     nothing, as `codesign` fails too, where unsign cuts them off first, as --exact --unsign reads the file, and names
     the artifact for it; through the root command too.
     */
    func testBytesAppendedPastTheSignatureAreCutForItToComeOff() throws {
        let directory = try self.directory("appended")
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
        let artifact = directory / "appended_exact_unsigned"
        XCTAssertEqual(Unsigner.lines(for: file.path, write: false, reporter: reporter).map(\.text), [artifact.path])
        XCTAssertEqual(try Data(contentsOf: artifact), data)
        XCTAssertEqual(reporter.errorCount, 0)
        XCTAssertFalse(FileManager.default.fileExists(atPath: (directory / "appended_unsigned").path))
        XCTAssertEqual(try self.hashLines(file.path, ["--exact", "--unsign"]), try [XCTUnwrap(ByteHash.sha256.digest(data))])
        XCTAssertEqual(try runFashion(["--unsign", file.path]).errors, ["fashion: \(file.path): LC_CODE_SIGNATURE does not point to end of file"])

        try FileManager.default.removeItem(at: artifact)
        let (status, errors) = try runFashion(["unsign", file.path])
        XCTAssertEqual(status, 0)
        XCTAssertEqual(errors, [])
        XCTAssertEqual(try Data(contentsOf: artifact), data)
    }
}
