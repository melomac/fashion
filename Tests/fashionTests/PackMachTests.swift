@testable import fashion
import XCTest

/**
 `--unpack`: a Mach-O UPX packed, given back as it was before packing, as `upx -d` gives it back, and where `upx -d`
 gives up, behind a signature added after packing. The packed fixtures are made at test time by the `upx` installed,
 with `--force-macos`, since UPX 4.2 no longer packs for macOS by default, and signed after packing by the Developer ID
 `local.xcconfig` names, or ad hoc without one.
 */
final class PackMachTests: XCTestCase {
    /// The package, three folders up from this file.
    private static let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()

    /**
     The folder a test makes its files in, kept after it as the fuzzer keeps its own under `.build/fuzz`: the packed
     and unpacked files of the last run of each test stay in `.build/tests/PackMachTests/<name>` to look at, until the
     next run empties it.
     */
    private func directory(_ name: String) throws -> URL {
        let url = Self.root / ".build/tests/PackMachTests/\(name)"
        try? FileManager.default.removeItem(at: url)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    /**
     The `upx` installed, on `PATH` or where a build from source, Homebrew and MacPorts put it, which `xcodebuild`'s `PATH`
     may not hold, in that order, so a devel build in /usr/local/bin is found before a release; skips the test without one,
     since not everyone may install it.
     */
    private func upx() throws -> String {
        let directories = (ProcessInfo.processInfo.environment["PATH"] ?? "").split(separator: ":").map(String.init) + ["/usr/local/bin", "/opt/homebrew/bin", "/opt/local/bin"]
        guard let path = directories.map({ $0 + "/upx" }).first(where: { FileManager.default.isExecutableFile(atPath: $0) }) else {
            throw XCTSkip("upx unavailable: brew install upx")
        }
        return path
    }

    /// `file` packed by UPX with `options` into `<file>_packed` beside it, made anew; skips the test when UPX does not
    /// pack it.
    private func packed(_ file: URL, _ options: [String] = []) throws -> URL {
        let packed = URL(fileURLWithPath: file.path + "_packed")
        try? FileManager.default.removeItem(at: packed)
        try XCTSkipUnless(execute(self.upx(), ["-q", "--force-macos"] + options + ["-o", packed.path, file.path]), "upx cannot pack it")
        saveFixture(path: packed.path)
        return packed
    }

    /**
     The signing identity `local.xcconfig` names, `CODE_SIGN_IDENTITY`, the Developer ID releases are signed with on
     the user's Mac; "-", ad hoc, without the file or the line, so the tests sign everywhere.
     */
    private static let identity: String = {
        let lines = (try? String(contentsOf: PackMachTests.root / "local.xcconfig", encoding: .utf8))?.split(separator: "\n") ?? []
        let settings = lines.map { $0.split(separator: "=", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) } }
        return settings.first { $0.count == 2 && $0[0] == "CODE_SIGN_IDENTITY" }?[1] ?? "-"
    }()

    /// `file` signed into `<file>_resigned` beside it, made anew: a sample signed after packing, by `identity`, without
    /// the timestamp a Developer ID signature asks a server for.
    private func resigned(_ file: URL) throws -> URL {
        let resigned = URL(fileURLWithPath: file.path + "_resigned")
        try? FileManager.default.removeItem(at: resigned)
        try FileManager.default.copyItem(at: file, to: resigned)
        _ = try codesign(["-s", Self.identity, "--timestamp=none", resigned.path])
        saveFixture(path: resigned.path)
        return resigned
    }

    /// The x86_64 and arm64e slices of `/bin/ls` without their signature, as thin --unsign writes them, by name.
    private func unsignedLs(in directory: URL) throws -> [(name: String, file: URL, data: Data)] {
        let ls = directory / "ls"
        try FileManager.default.copyItem(at: URL(fileURLWithPath: "/bin/ls"), to: ls)
        _ = Thinner.lines(for: ls.path, exact: false, unsign: true, unpack: false, overwrite: false, reporter: Reporter(console: Console()))
        let slices = try ["x86_64", "arm64e"].map { ($0, directory / "ls_\($0)_unsigned") }.filter { FileManager.default.fileExists(atPath: $0.1.path) }.map { try ($0.0, $0.1, Data(contentsOf: $0.1)) }
        try XCTSkipIf(slices.isEmpty, "/bin/ls has neither an x86_64 nor an arm64e slice")
        return slices
    }

    /// The lines hash mode prints for `path` with `arguments`.
    private func hashLines(_ path: String, _ arguments: [String] = []) throws -> [String] {
        try Digester(Hasher.parse([path, "--quiet"] + arguments)).lines(for: path, reporter: Reporter(console: Console())).map(\.text)
    }

    func testUnpackRestoresWhatUPXPacked() throws {
        // Each compression method UPX packs Mach-O with, x86_64 and arm64, each in a folder of its own: --unpack gives
        // the image back byte for byte, as upx -d does, and thin writes it out. An image UPX did not pack is left as it is.
        let directory = try self.directory("methods")
        for (name, unsigned, original) in try self.unsignedLs(in: directory) {
            let digest = try XCTUnwrap(ByteHash.sha256.digest(original))
            XCTAssertEqual(try self.hashLines(unsigned.path, ["--unpack"]), [digest])
            for method in ["--nrv2b", "--nrv2d", "--nrv2e", "--lzma"] {
                let folder = directory / String(method.dropFirst(2))
                try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
                let source = folder / unsigned.lastPathComponent
                try FileManager.default.copyItem(at: unsigned, to: source)
                let file = try self.packed(source, [method])
                XCTAssertNotEqual(try Data(contentsOf: file), original)
                XCTAssertEqual(try self.hashLines(file.path, ["--unpack"]), [digest], "\(name) \(method)")

                let artifact = URL(fileURLWithPath: file.path + "_unpacked")
                XCTAssertEqual(Thinner.lines(for: file.path, exact: false, unsign: false, unpack: true, overwrite: false, reporter: Reporter(console: Console())).map(\.text), [artifact.path])
                XCTAssertEqual(try Data(contentsOf: artifact), original, "\(name) \(method)")
                // upx -d, the oracle, into a file of its own, where it unpacks: for a __TEXT of a single page it looks for
                // its pack header from before the file's start and gives up, where --unpack starts looking at the file's
                // start.
                let upxd = URL(fileURLWithPath: file.path + "_upx-d")
                if try execute(self.upx(), ["-q", "-d", "-o", upxd.path, file.path]) {
                    XCTAssertEqual(try Data(contentsOf: upxd), original, "\(name) \(method)")
                }
            }
        }
    }

    func testUnpackUndoesTheArm64ConditionalBranchFilter() throws {
        // Filter 0x53, which UPX added after 5.2.1 for arm64 and packs with when asked, takes the conditional branches
        // too. An older upx packs with 0x52 when asked for it, and the test is skipped.
        let directory = try self.directory("filter-0x53")
        guard let (_, unsigned, original) = try self.unsignedLs(in: directory).first(where: { $0.name == "arm64e" }) else {
            throw XCTSkip("/bin/ls has no arm64e slice")
        }
        let file = try self.packed(unsigned, ["--filter=0x53"])
        let packed = try Data(contentsOf: file)
        // The pack header's filter follows its version, format, method, level, sizes and checksums.
        let header = try XCTUnwrap(packed.ranges(of: Data("UPX!".utf8)).last).lowerBound
        try XCTSkipUnless(packed[header + 28] == 0x53, "upx packs with filter 0x\(String(packed[header + 28], radix: 16)), not 0x53")

        XCTAssertEqual(try self.hashLines(file.path, ["--unpack"]), try [XCTUnwrap(ByteHash.sha256.digest(original))])
        let upxd = URL(fileURLWithPath: file.path + "_upx-d")
        if try execute(self.upx(), ["-q", "-d", "-o", upxd.path, file.path]) {
            XCTAssertEqual(try Data(contentsOf: upxd), original)
        }
    }

    func testUnfilterUndoesUPXsArm64BranchFilters() throws {
        // UPX's arm64 doctest instructions, filtered by UPX's own Filter as its Mach-O packer filters them (addvalue 0),
        // with three bytes after the last word: 0x52 takes B and BL, the last word only with bytes after it; 0x53 takes
        // the conditional branches too, and the last word always. The bytes after the last word stay as they are.
        // nop, b, bl, b.ne, cbz w5, cbz x5, cbnz w7, cbnz x7, tbz, tbnz, add, b
        let original: [UInt32] = [0xd503_201f, 0x17ff_ffff, 0x9400_0010, 0x54ff_ffe1, 0x3400_0065, 0xb4ff_ffc5, 0x35ff_ffe7, 0xb500_0047, 0x361f_fff1, 0xb7f8_0024, 0x9100_0400, 0x1400_0002]
        let filtered: [(id: UInt8, length: Int, words: [UInt32])] = [
            (0x52, 48, [0xd503_201f, 0x1400_0000, 0x9400_0012, 0x54ff_ffe1, 0x3400_0065, 0xb4ff_ffc5, 0x35ff_ffe7, 0xb500_0047, 0x361f_fff1, 0xb7f8_0024, 0x9100_0400, 0x1400_0002]),
            (0x52, 51, [0xd503_201f, 0x1400_0000, 0x9400_0012, 0x54ff_ffe1, 0x3400_0065, 0xb4ff_ffc5, 0x35ff_ffe7, 0xb500_0047, 0x361f_fff1, 0xb7f8_0024, 0x9100_0400, 0x1400_000d]),
            (0x53, 48, [0xd503_201f, 0x1400_0000, 0x9400_0012, 0x5400_0041, 0x3400_00e5, 0xb400_0065, 0x3500_00a7, 0xb500_0127, 0x3618_00f1, 0xb7f8_0144, 0x9100_0400, 0x1400_000d]),
            (0x53, 51, [0xd503_201f, 0x1400_0000, 0x9400_0012, 0x5400_0041, 0x3400_00e5, 0xb400_0065, 0x3500_00a7, 0xb500_0127, 0x3618_00f1, 0xb7f8_0144, 0x9100_0400, 0x1400_000d]),
        ]
        let block = { (words: [UInt32], length: Int) in
            Data(words.flatMap { withUnsafeBytes(of: $0.littleEndian, Array.init) } + [0xa5, 0xa5, 0xa5]).prefix(length)
        }
        for (id, length, words) in filtered {
            var unfiltered = block(words, length)
            try unfiltered.withUnsafeMutableBytes { try PackMach.unfilter($0, id: id, cto: 0) }
            XCTAssertEqual(unfiltered, block(original, length), "0x\(String(id, radix: 16)), \(length) bytes")
        }
    }

    func testUnpackSeesPastASignatureAddedAfterPacking() throws {
        // Signed after packing, the image no longer has the 16-byte __LINKEDIT UPX leaves, so upx -d gives up on it;
        // --unpack looks past the signature. A signed image that UPX packed comes back signed, and without its signature
        // too with --unsign.
        let directory = try self.directory("signed")
        let (name, unsigned, data) = try XCTUnwrap(self.unsignedLs(in: directory).first)
        let file = try self.resigned(self.packed(unsigned))
        XCTAssertFalse(try execute(self.upx(), ["-q", "-d", "-o", file.path + "_upx-d", file.path]))
        XCTAssertEqual(try self.hashLines(file.path, ["--unpack"]), try [ByteHash.sha256.digest(data)])

        let ls = try Data(contentsOf: URL(fileURLWithPath: "/bin/ls"))
        guard case let .fat(slices) = try Universal.open(data: ls), let slice = slices.first(where: { $0.name == name }) else {
            throw XCTSkip("/bin/ls has no \(name) slice")
        }
        let signed = Universal.sliceData(fileData: ls, arch: slice)
        let apple = directory / "ls_\(name)"
        try signed.write(to: apple)
        let packed = try self.resigned(self.packed(apple))
        XCTAssertEqual(try self.hashLines(packed.path, ["--unpack"]), try [ByteHash.sha256.digest(signed)])
        XCTAssertEqual(try self.hashLines(packed.path, ["--unpack", "--unsign"]), try [ByteHash.sha256.digest(data)])
        // thin writes Apple's slice back, signature and all: codesign's strict validation is the second oracle.
        let unpacked = URL(fileURLWithPath: packed.path + "_unpacked")
        XCTAssertEqual(Thinner.lines(for: packed.path, exact: false, unsign: false, unpack: true, overwrite: false, reporter: Reporter(console: Console())).map(\.text), [unpacked.path])
        XCTAssertEqual(try Data(contentsOf: unpacked), signed)
        _ = try codesign(["--verify", "--strict", unpacked.path])
        // unpack names a thin file's artifact as thin does, found in place; unsign over it takes Apple's signature off.
        XCTAssertEqual(Unpacker.lines(for: packed.path, exact: false, overwrite: false, reporter: Reporter(console: Console())).map(\.text), [unpacked.path])
        XCTAssertEqual(Unsigner.lines(for: unpacked.path, exact: false, overwrite: false, reporter: Reporter(console: Console())).map(\.text), [unpacked.path + "_unsigned"])
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: unpacked.path + "_unsigned")), data)
    }

    func testUnpackRestoresAUniversalFile() throws {
        // A universal file with a slice UPX packed comes back as lipo made it of the originals, and thin writes them.
        let directory = try self.directory("universal")
        let slices = try self.unsignedLs(in: directory)
        try XCTSkipIf(slices.count < 2, "/bin/ls has no x86_64 and arm64e slices")
        let originals = slices.map(\.file)
        let packed = try self.packed(originals[0])
        let universal = directory / "universal"
        let original = directory / "original"
        try XCTSkipUnless(execute("/usr/bin/xcrun", ["lipo", "-create", packed.path, originals[1].path, "-output", universal.path]), "cannot run lipo")
        XCTAssertTrue(try execute("/usr/bin/xcrun", ["lipo", "-create"] + originals.map(\.path) + ["-output", original.path]))

        XCTAssertEqual(try self.hashLines(universal.path, ["--unpack"]), try [ByteHash.sha256.digest(Data(contentsOf: original))])
        // unpack writes the universal file whole, as lipo made it of the originals; thin writes its slices.
        XCTAssertEqual(Unpacker.lines(for: universal.path, exact: false, overwrite: false, reporter: Reporter(console: Console())).map(\.text), [universal.path + "_unpacked"])
        XCTAssertEqual(try Data(contentsOf: directory / "universal_unpacked"), try Data(contentsOf: original))
        XCTAssertEqual(Thinner.lines(for: universal.path, exact: false, unsign: false, unpack: true, overwrite: false, reporter: Reporter(console: Console())).count, 2)
        // The slice UPX packed is named for its unpacking; the other, as it was, keeps its name.
        XCTAssertEqual(try Data(contentsOf: directory / "universal_\(slices[0].name)_unpacked"), slices[0].data)
        XCTAssertEqual(try Data(contentsOf: directory / "universal_\(slices[1].name)"), slices[1].data)

        // Signed after its slices were packed, which lays the universal file out again: --unpack sees past each
        // slice's signature, and with --unsign gives the file lipo made of the originals; thin writes both slices, the
        // packed one named for its unpacking alone, since the signature came off before the image was unpacked.
        let resigned = try self.resigned(universal)
        XCTAssertEqual(try self.hashLines(resigned.path, ["--unpack", "--unsign"]), try [ByteHash.sha256.digest(Data(contentsOf: original))])
        XCTAssertEqual(Thinner.lines(for: resigned.path, exact: false, unsign: true, unpack: true, overwrite: false, reporter: Reporter(console: Console())).count, 2)
        XCTAssertEqual(try Data(contentsOf: directory / "universal_resigned_\(slices[0].name)_unpacked"), slices[0].data)
        XCTAssertEqual(try Data(contentsOf: directory / "universal_resigned_\(slices[1].name)_unsigned"), slices[1].data)
        // unpack alone leaves the other slice signed, laid out again; unsign over the artifact gives the originals' file.
        let reporter = Reporter(console: Console())
        XCTAssertEqual(Unpacker.lines(for: resigned.path, exact: false, overwrite: false, reporter: reporter).map(\.text), [resigned.path + "_unpacked"])
        XCTAssertEqual(try self.hashLines(resigned.path + "_unpacked", ["--unsign"]), try [ByteHash.sha256.digest(Data(contentsOf: original))])
        XCTAssertEqual(Unsigner.lines(for: resigned.path + "_unpacked", exact: false, overwrite: false, reporter: reporter).map(\.text), [resigned.path + "_unpacked_unsigned"])
        XCTAssertEqual(try Data(contentsOf: directory / "universal_resigned_unpacked_unsigned"), try Data(contentsOf: original))
        XCTAssertEqual(reporter.errorCount, 0)
    }

    func testCorruptPackHeaderIsReported() throws {
        // A pack header whose checksum does not hold is malformed UPX data: red, counted, nothing written. So is a
        // header block that claims more than a block, 2 GiB less a byte, refused before any of it is made room for.
        let directory = try self.directory("corrupt")
        let (_, unsigned, _) = try XCTUnwrap(self.unsignedLs(in: directory).first)
        let packed = try Data(contentsOf: self.packed(unsigned))
        let header = try XCTUnwrap(packed.ranges(of: Data("UPX!".utf8)).last).lowerBound
        var corrupt = packed
        corrupt[header + 31] ^= 0xff
        // The overlay offset follows the 32-byte pack header; its p_info is 12 bytes, then the first block's b_info.
        let overlay = Int(packed.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: header + 32, as: UInt32.self) }.littleEndian)
        var huge = packed
        huge.replaceSubrange(overlay + 12 ..< overlay + 16, with: withUnsafeBytes(of: UInt32(0x7fff_ffff).littleEndian) { Data($0) })

        for (name, data, message) in [("corrupt", corrupt, "header corrupted 3"), ("huge", huge, "file header corrupted")] {
            let file = directory / name
            try data.write(to: file)
            let reporter = Reporter(console: Console())
            let lines = Thinner.lines(for: file.path, exact: false, unsign: false, unpack: true, overwrite: false, reporter: reporter)
            XCTAssertEqual(lines.count, 1, name)
            XCTAssertEqual(lines.first?.tint, .malformed, name)
            XCTAssertEqual(reporter.errorCount, 1, name)
            XCTAssertFalse(FileManager.default.fileExists(atPath: (directory / "\(name)_unpacked").path), name)
            let (status, errors) = try runFashion(["--unpack", file.path])
            XCTAssertEqual(status, 2, name)
            XCTAssertEqual(errors, ["fashion: \(file.path): Invalid UPX data: \(message)"], name)
        }
    }

    func testImagesUPXDidNotPackAreLeftAlone() throws {
        // --unpack meets every Mach-O. One of three segments, __DATA, __TEXT and a __LINKEDIT too short for a block
        // header, is where UPX gives up ("bad offLINK") though it never packed it: hashed as it is, nothing to write.
        let directory = try self.directory("not-packed")
        let image = makeBigEndianMachO(is64: false, textOffset: 0x1000, linkeditSize: 8, infoPlist: Data("<plist/>".utf8))
        let file = directory / "ppc"
        try image.write(to: file)

        let reporter = Reporter(console: Console())
        XCTAssertEqual(try self.hashLines(file.path, ["--unpack"]), try [ByteHash.sha256.digest(image)])
        XCTAssertEqual(Thinner.lines(for: file.path, exact: false, unsign: false, unpack: true, overwrite: false, reporter: reporter).count, 0)
        XCTAssertEqual(reporter.errorCount, 0)
    }

    func testUnpackedSlicesMatchTheFatFilesUnsignedSlices() throws {
        // The whole chain over every slice of /bin/ls: thin --unsign writes each without its signature, UPX packs each,
        // codesign signs each again ad hoc, and thin --unpack gives each back. --match, given the digests of the fat
        // file's slices with --unsign, finds every artifact, and the packed files themselves only with --unpack.
        let directory = try self.directory("chain")
        let ls = directory / "ls"
        try FileManager.default.copyItem(at: URL(fileURLWithPath: "/bin/ls"), to: ls)
        guard case let .fat(slices) = try Universal.open(path: ls.path) else {
            throw XCTSkip("/bin/ls is not universal")
        }
        let reporter = Reporter(console: Console())
        XCTAssertEqual(Thinner.lines(for: ls.path, exact: false, unsign: true, unpack: false, overwrite: false, reporter: reporter).count, slices.count)

        // ls_x86_64_unsigned packed into ls_x86_64_unsigned_packed, signed into ls_x86_64_unsigned_packed_resigned, then
        // unpacked into ls_x86_64_unsigned_packed_resigned_unpacked.
        let packed = try slices.map { slice in
            try self.resigned(self.packed(directory / "ls_\(slice.name)_unsigned"))
        }
        for file in packed {
            XCTAssertEqual(Thinner.lines(for: file.path, exact: false, unsign: false, unpack: true, overwrite: false, reporter: reporter).map(\.text), [file.path + "_unpacked"])
        }
        XCTAssertEqual(reporter.errorCount, 0)

        // Hash mode prints the whole file's digest before its slices'.
        let targets = try self.hashLines(ls.path, ["--slices", "--unsign"]).dropFirst()
        XCTAssertEqual(targets.count, slices.count)
        let match = targets.flatMap { ["--match", $0] }
        for file in packed {
            XCTAssertEqual(try self.hashLines(file.path + "_unpacked", match), [file.path + "_unpacked"])
            XCTAssertEqual(try self.hashLines(file.path, match), [])
            XCTAssertEqual(try self.hashLines(file.path, match + ["--unpack"]), [file.path])
        }
        let (status, errors) = try runFashion(match + packed.map { $0.path + "_unpacked" })
        XCTAssertEqual(status, 0)
        XCTAssertEqual(errors, [])
    }
}
