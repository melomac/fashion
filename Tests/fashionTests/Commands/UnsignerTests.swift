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

    /// The lines hash mode prints for `path` with `arguments`. The file seeds the fuzzer's corpora.
    private func hashLines(_ path: String, _ arguments: [String] = []) throws -> [String] {
        saveFixture(path: path)
        return try Digester(Hasher.parse([path, "--quiet"] + arguments)).lines(for: path, reporter: Reporter(console: Console())).map(\.text)
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
        XCTAssertEqual(try Unsigner.lines(for: ls.path, write: false, reporter: reporter).map(\.text), [artifact.path])
        let unsigned = try Data(contentsOf: artifact)
        XCTAssertEqual(try self.hashLines(ls.path, ["--unsign"]).last, try ByteHash.sha256.digest(unsigned))
        XCTAssertEqual(try self.hashLines(artifact.path, ["--unsign"]), try [ByteHash.sha256.digest(unsigned)])

        // thin leaves the signed slices beside the unsigned ones: lipo gets the unsigned ones.
        let slices = try Thinner.lines(for: ls.path, exact: false, unsign: true, unpack: false, write: true, reporter: reporter).map(\.text).filter { $0.hasSuffix("_unsigned") }
        XCTAssertGreaterThan(slices.count, 1)
        let lipo = directory / "lipo"
        try XCTSkipUnless(execute("/usr/bin/xcrun", ["lipo", "-create"] + slices + ["-output", lipo.path]), "cannot run lipo")
        XCTAssertEqual(unsigned, try Data(contentsOf: lipo))

        XCTAssertEqual(try Unsigner.lines(for: artifact.path, write: false, reporter: reporter).count, 0)
        // A second run finds the artifact in place.
        XCTAssertEqual(try Unsigner.lines(for: ls.path, write: false, reporter: reporter).map(\.text), [artifact.path])
        XCTAssertEqual(reporter.errorCount, 0)
    }

    /**
     Without --write, a different file under the artifact's name stays as it is, executable bit included, and standard
     error names it with its size and SHA-256 and the artifact's; the run fails. With --write it is replaced, without
     the execute bit, and nothing is said: the unified log alone records the replacement.
     */
    func testADifferentFileInTheWayIsReportedAndLeftAloneWithoutWrite() throws {
        let directory = try self.directory("differs")
        defer {
            try? FileManager.default.removeItem(at: directory)
        }
        let ls = directory / "ls"
        try FileManager.default.copyItem(at: URL(fileURLWithPath: "/bin/ls"), to: ls)
        let artifact = directory / "ls_unsigned"
        let other = Data("in the way".utf8)
        try other.write(to: artifact)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: artifact.path)

        let (status, errors) = try runFashion(["unsign", ls.path])
        XCTAssertEqual(status, 2)
        XCTAssertEqual(errors.count, 1)
        let prefix = try "fashion: \(artifact.path): exists and differs, 10 bytes, sha256 \(XCTUnwrap(ByteHash.sha256.digest(other))) where the artifact is "
        XCTAssertTrue(errors.first?.hasPrefix(prefix) ?? false, errors.first ?? "")
        XCTAssertTrue(errors.first?.hasSuffix("; left alone without --write") ?? false, errors.first ?? "")
        XCTAssertEqual(try Data(contentsOf: artifact), other)
        XCTAssertEqual(try XCTUnwrap(FileManager.default.attributesOfItem(atPath: artifact.path)[.posixPermissions] as? Int) & 0o111, 0o111)

        let (written, quiet) = try runFashion(["unsign", "--write", ls.path])
        XCTAssertEqual(written, 0)
        XCTAssertEqual(quiet, [])
        XCTAssertEqual(try self.hashLines(ls.path, ["--unsign"]).last, try ByteHash.sha256.digest(Data(contentsOf: artifact)))
        XCTAssertEqual(try XCTUnwrap(FileManager.default.attributesOfItem(atPath: artifact.path)[.posixPermissions] as? Int) & 0o111, 0)
    }

    /**
     With --quiet, a file that has an artifact is printed once, its own path, and the artifact is written all the same;
     the artifact, which has nothing to unsign, prints nothing.
     */
    func testQuietNamesTheFileOnce() throws {
        let directory = try self.directory("quiet")
        defer {
            try? FileManager.default.removeItem(at: directory)
        }
        let ls = directory / "ls"
        try FileManager.default.copyItem(at: URL(fileURLWithPath: "/bin/ls"), to: ls)
        let reporter = Reporter(console: Console())
        let artifact = directory / "ls_unsigned"

        XCTAssertEqual(try Unsigner.lines(for: ls.path, write: false, quiet: true, reporter: reporter).map(\.text), [ls.path])
        XCTAssertTrue(FileManager.default.fileExists(atPath: artifact.path))
        XCTAssertEqual(try Unsigner.lines(for: artifact.path, write: false, quiet: true, reporter: reporter).count, 0)
        XCTAssertEqual(reporter.errorCount, 0)
        XCTAssertEqual(try Unsigner.parse(["-q", directory.path]).scan(), 0)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path).sorted(), ["ls", "ls_unsigned"])
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
        XCTAssertEqual(try Unsigner.lines(for: (signed / "sample").path, write: false, reporter: reporter).map(\.text), [(signed / "sample_unsigned").path])
        XCTAssertEqual(try Data(contentsOf: signed / "sample_unsigned"), data)
        XCTAssertEqual(try Unsigner.lines(for: original.path, write: false, reporter: reporter).count, 0)
        XCTAssertEqual(try Unsigner.lines(for: (signed / "text").path, write: false, reporter: reporter).count, 0)
        XCTAssertEqual(reporter.errorCount, 0)

        try FileManager.default.removeItem(at: signed / "sample_unsigned")
        let command = try XCTUnwrap(Fashion.parseAsRoot(["unsign", signed.path]) as? Unsigner)
        XCTAssertEqual(command.scan(), 0)
        XCTAssertEqual(try Data(contentsOf: signed / "sample_unsigned"), data)
        XCTAssertEqual(try Thinner.lines(for: (signed / "sample").path, exact: false, unsign: true, unpack: false, write: true, reporter: reporter).map(\.text), [(signed / "sample_unsigned").path])
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
        XCTAssertEqual(try Unsigner.lines(for: padded.path, write: false, reporter: reporter).count, 0)
        XCTAssertEqual(try Unpacker.lines(for: padded.path, write: false, reporter: reporter).count, 0)
        XCTAssertEqual(try Unsigner.lines(for: original.path, write: false, reporter: reporter).count, 0)
        let artifact = directory / "padded_exact"
        XCTAssertEqual(try Thinner.lines(for: padded.path, exact: true, unsign: false, unpack: false, write: true, reporter: reporter).map(\.text), [artifact.path])
        XCTAssertEqual(try Data(contentsOf: artifact), data)
        XCTAssertEqual(try self.hashLines(padded.path, ["--exact", "--unsign"]).last, try XCTUnwrap(ByteHash.sha256.digest(data)))
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
        XCTAssertEqual(try Unsigner.lines(for: fat.path, write: false, reporter: reporter).map(\.text), [artifact.path])
        let written = try Data(contentsOf: artifact)
        XCTAssertEqual(try self.hashLines(fat.path, ["--exact", "--unsign"]).last, try XCTUnwrap(ByteHash.sha256.digest(written)))
        guard case let .fat(archs) = try Universal.open(data: written), archs.count == 2 else {
            return XCTFail("the artifact is not universal")
        }
        XCTAssertEqual(Universal.sliceData(fileData: written, arch: archs[0]), try Data(contentsOf: x86))
        XCTAssertEqual(Universal.sliceData(fileData: written, arch: archs[1]), armData + Data(repeating: 0x4a, count: 8))

        let lines = try Thinner.lines(for: fat.path, exact: true, unsign: true, unpack: false, write: true, reporter: reporter).map(\.text)
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
        XCTAssertEqual(try Unsigner.lines(for: file.path, write: false, reporter: reporter).map(\.text), [artifact.path])
        XCTAssertEqual(try Data(contentsOf: artifact), data)
        XCTAssertEqual(reporter.errorCount, 0)
        XCTAssertFalse(FileManager.default.fileExists(atPath: (directory / "appended_unsigned").path))
        XCTAssertEqual(try self.hashLines(file.path, ["--exact", "--unsign"]).last, try XCTUnwrap(ByteHash.sha256.digest(data)))
        // Hash mode cuts as needed too, and names the state for it.
        XCTAssertEqual(try self.hashLines(file.path, ["--unsign"]).last, try XCTUnwrap(ByteHash.sha256.digest(data)))
        XCTAssertEqual(try runFashion(["--unsign", file.path]).errors, [])

        try FileManager.default.removeItem(at: artifact)
        let (status, errors) = try runFashion(["unsign", file.path])
        XCTAssertEqual(status, 0)
        XCTAssertEqual(errors, [])
        XCTAssertEqual(try Data(contentsOf: artifact), data)
    }

    /**
     An arm64 slice `lipo -hideARM64` hid past the table's count stays hidden in the file written whole: the table
     counts the slices as the kernel reads them, the hidden one lying last, where `Universal` and Security find it.
     */
    func testAHiddenSliceStaysHiddenInTheFileWrittenWhole() throws {
        let directory = try self.directory("hidden")
        defer {
            try? FileManager.default.removeItem(at: directory)
        }
        let x86 = try compile("x86", in: directory, ["-arch", "x86_64"])
        let arm = try compile("arm", in: directory, ["-arch", "arm64"])
        for program in [x86, arm] {
            _ = try codesign(["-s", "-", program.path])
        }
        let file = directory / "fat"
        try makeUniversal([(CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, Data(contentsOf: x86), 12), (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, Data(contentsOf: arm), 14)], hideLast: true).write(to: file)
        // Security finds the hidden slice: codesign lists it with the other.
        XCTAssertEqual(try codesignArchs(file.path), ["x86_64", "arm64"])
        let reporter = Reporter(console: Console())
        let artifact = directory / "fat_unsigned"
        XCTAssertEqual(try Unsigner.lines(for: file.path, write: false, reporter: reporter).map(\.text), [artifact.path])
        let unsigned = try Data(contentsOf: artifact)
        XCTAssertEqual(UInt32(bigEndian: unsigned.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 4, as: UInt32.self) }), 1, "nfat_arch counts the x86_64 slice alone")
        guard case let .fat(archs) = try Universal.open(path: artifact.path) else {
            return XCTFail("a universal file")
        }
        XCTAssertEqual(archs.map(\.name), ["x86_64", "arm64"])
        XCTAssertEqual(archs.map(\.hidden), [false, true])
        for arch in archs {
            XCTAssertNil(try XCTUnwrap(MachO(File(path: artifact.path), offset: arch.offset, length: arch.length)).findCodeSignature(), arch.name)
        }
        XCTAssertEqual(reporter.errorCount, 0)
    }

    /**
     A signature laid over the header and the load commands, `LC_CODE_SIGNATURE` pointing at offset 0, is no image to
     give back: reported, nothing written, where the edit would rewrite the headers under it.
     */
    func testASignatureInsideTheLoadCommandsIsRefused() throws {
        let directory = try self.directory("inside")
        defer {
            try? FileManager.default.removeItem(at: directory)
        }
        let original = try compile("sample", in: directory, ["-arch", "x86_64"])
        let signed = directory / "signed"
        try Data(contentsOf: original).write(to: signed)
        _ = try codesign(["-s", "-", signed.path])
        var data = try Data(contentsOf: signed)
        let command = try XCTUnwrap(XCTUnwrap(MachO(File(data: data))).findCommand(UInt32(LC_CODE_SIGNATURE)))
        data.replaceSubrange(command.data.startIndex + 8 ..< command.data.startIndex + 16, with: withUnsafeBytes(of: (UInt32(0), UInt32(data.count))) { Data($0) }) // dataoff, datasize
        let file = directory / "inside"
        try data.write(to: file)
        let reporter = Reporter(console: Console())
        let refusal = "fashion: \(file.path): LC_CODE_SIGNATURE points inside the load commands"
        XCTAssertEqual(try Unsigner.lines(for: file.path, write: false, reporter: reporter).map(\.text), [refusal])
        XCTAssertEqual(reporter.errorCount, 1)
        XCTAssertFalse(FileManager.default.fileExists(atPath: file.path + "_unsigned"))
        // Hash mode hashes the file as it is, the refusal a warning: the run succeeds.
        let (status, errors) = try runFashion(["--unsign", file.path])
        XCTAssertEqual(status, 0)
        XCTAssertEqual(errors, [refusal + ", hashed as it is"])
        XCTAssertEqual(try self.hashLines(file.path, ["--unsign"]), try [refusal + ", hashed as it is", XCTUnwrap(ByteHash.sha256.digest(data))])
    }

    /**
     A universal file past 4 GiB, which a 32-bit table cannot place, gets a 64-bit table, as `lipo` writes one for it,
     where a smaller file keeps the 32-bit table it had.
     */
    func testAUniversalFilePast4GiBGetsA64BitTable() throws {
        func table(_ pieces: [File.Piece]) throws -> (magic: UInt32, count: Int) {
            guard case let .bytes(table)? = pieces.first else {
                throw XCTSkip("no table")
            }
            return (UInt32(bigEndian: table.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }), table.count)
        }
        let arch = Universal.Architecture(cpuType: CPU_TYPE_X86_64, cpuSubtype: CPU_SUBTYPE_X86_64_ALL, offset: 0x1000, length: 0x1_0000_0000, align: 12, hidden: false)
        let large = MachOEditor.universal([MachOEditor.Slice(arch: arch, pieces: [.range(0 ..< 0x1_0000_0000)], align: 12)], is64: false)
        XCTAssertEqual(try table(large).magic, FAT_MAGIC_64)
        XCTAssertEqual(try table(large).count, 8 + 32)
        XCTAssertEqual(large.reduce(0) { $0 + $1.count }, 0x1000 + 0x1_0000_0000)
        let small = MachOEditor.universal([MachOEditor.Slice(arch: arch, pieces: [.range(0 ..< 0x1000)], align: 12)], is64: false)
        XCTAssertEqual(try table(small).magic, FAT_MAGIC)
        XCTAssertEqual(try table(small).count, 8 + 20)

        // A hidden slice is counted in a 64-bit table, where no reader looks past the count.
        let hidden = Universal.Architecture(cpuType: CPU_TYPE_ARM64, cpuSubtype: CPU_SUBTYPE_ARM64_ALL, offset: 0x1_0000_4000, length: 0x1000, align: 14, hidden: true)
        let both = MachOEditor.universal([MachOEditor.Slice(arch: arch, pieces: [.range(0 ..< 0x1_0000_0000)], align: 12), MachOEditor.Slice(arch: hidden, pieces: [.range(0 ..< 0x1000)], align: 14)], is64: false)
        guard case let .bytes(wide)? = both.first else {
            return XCTFail("no table")
        }
        XCTAssertEqual(UInt32(bigEndian: wide.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 4, as: UInt32.self) }), 2)
        XCTAssertEqual(wide.count, 8 + 2 * 32)
    }

    /**
     Security's `remove_signature_space` walks the `ncmds` commands the loaders read and takes the last `__LINKEDIT`,
     the last `LC_SYMTAB` and the last `LC_CODE_SIGNATURE` of them, an `LC_SEGMENT` named `__LINKEDIT` before an
     `LC_SEGMENT_64` one, whatever the image's width. An arm64 program given a second, empty `__LINKEDIT`
     after its own, signed by codesign, comes back as it was, byte for byte: codesign extends and shrinks the second,
     and leaves the 16 KiB signing gave it where unsign restores the nothing it had. One given a second `LC_SYMTAB`
     whose string table ends nowhere near the signature unsigns to what `codesign --remove-signature` writes, byte for
     byte, the padding before the signature kept. A signature command hidden past `ncmds`, or under `ncmds` 0, is none
     to either: codesign leaves the file as it is, and so does unsign.
     */
    func testUnsignTakesTheLastCommandsAsCodesignDoes() throws {
        let directory = try self.directory("last")
        defer {
            try? FileManager.default.removeItem(at: directory)
        }
        let program = try Data(contentsOf: compile("arm", in: directory, ["-arch", "arm64", "-Wl,-headerpad,0x800"]))
        let linkedit = try XCTUnwrap(XCTUnwrap(MachO(File(data: program))).findSegment("__LINKEDIT")).load(segment_command_64.self)
        var decoyLinkedit = Data()
        [UInt32(LC_SEGMENT_64), 72].forEach { decoyLinkedit.appendUInt32($0) }
        decoyLinkedit.append(Data("__LINKEDIT".utf8)); decoyLinkedit.append(Data(count: 6))
        [linkedit.vmaddr + linkedit.vmsize, 0, linkedit.fileoff + linkedit.filesize, 0].forEach { decoyLinkedit.appendUInt64($0) }
        [UInt32(1), 1, 0, 0].forEach { decoyLinkedit.appendUInt32($0) }
        var decoySymtab = Data()
        [UInt32(LC_SYMTAB), 24, 0, 0, 0, 0].forEach { decoySymtab.appendUInt32($0) }
        for (name, decoy, roundTrip) in [("linkedit", decoyLinkedit, true), ("symtab", decoySymtab, false)] {
            let file = directory / name
            let original = appending(decoy, to: program)
            try original.write(to: file)
            _ = try codesign(["-s", "-", file.path])
            let oracle = directory / "\(name)-codesign"
            try FileManager.default.copyItem(at: file, to: oracle)
            _ = try codesign(["--remove-signature", oracle.path])
            let reporter = Reporter(console: Console())
            XCTAssertEqual(try Unsigner.lines(for: file.path, write: false, reporter: reporter).map(\.text), [file.path + "_unsigned"], name)
            let unsigned = try Data(contentsOf: URL(fileURLWithPath: file.path + "_unsigned"))
            XCTAssertEqual(unsigned, try roundTrip ? original : Data(contentsOf: oracle), name)
            XCTAssertEqual(unsigned.count, try Data(contentsOf: oracle).count, name)
        }

        let signed = directory / "signed"
        try program.write(to: signed)
        _ = try codesign(["-s", "-", signed.path])
        let data = try Data(contentsOf: signed)
        let commands = try XCTUnwrap(MachO(File(data: data))).loadCommands
        XCTAssertEqual(commands.last?.cmd, UInt32(LC_CODE_SIGNATURE))

        // An `LC_SEGMENT` named `__LINKEDIT` beside the image's own `LC_SEGMENT_64` one, put first among the commands
        // of the signed program. Security shrinks the `LC_SEGMENT` one, whatever the image's width, and leaves the
        // other as it was. So does unsign, byte for byte but for the vmsize it rounds where Security leaves it.
        let own = try XCTUnwrap(XCTUnwrap(MachO(File(data: data))).findSegment("__LINKEDIT")).load(segment_command_64.self)
        var narrow = Data()
        [UInt32(LC_SEGMENT), 56].forEach { narrow.appendUInt32($0) }
        narrow.append(Data("__LINKEDIT".utf8)); narrow.append(Data(count: 6))
        [UInt32(own.vmaddr & 0xffff_ffff), 0, UInt32(own.fileoff), UInt32(own.filesize), 1, 1, 0, 0].forEach { narrow.appendUInt32($0) }
        var both = data
        let sizeofcmds = Int(both.load(UInt32.self, at: 20))
        XCTAssertTrue(both[32 + sizeofcmds ..< 32 + sizeofcmds + narrow.count].allSatisfy { $0 == 0 }, "room in the header pad")
        both.removeSubrange(32 + sizeofcmds ..< 32 + sizeofcmds + narrow.count)
        both.insert(contentsOf: narrow, at: 32)
        both.store(both.load(UInt32.self, at: 16) + 1, at: 16)
        both.store(UInt32(sizeofcmds + narrow.count), at: 20)
        let mixed = directory / "mixed"
        try both.write(to: mixed)
        let removed = directory / "mixed-codesign"
        try FileManager.default.copyItem(at: mixed, to: removed)
        _ = try codesign(["--remove-signature", removed.path])
        XCTAssertEqual(try Unsigner.lines(for: mixed.path, write: false, reporter: Reporter(console: Console())).map(\.text), [mixed.path + "_unsigned"])
        /// `image` with the vmsize of the `LC_SEGMENT` put first zeroed.
        func masked(_ image: Data) -> Data {
            var image = image
            image.replaceSubrange(32 + 28 ..< 32 + 32, with: Data(count: 4))
            return image
        }
        let oracle = try Data(contentsOf: removed)
        XCTAssertEqual(try masked(Data(contentsOf: URL(fileURLWithPath: mixed.path + "_unsigned"))), masked(oracle))
        XCTAssertLessThan(oracle.load(UInt32.self, at: 32 + 36), UInt32(own.filesize), "codesign shrank the LC_SEGMENT one")
        for (name, ncmds) in [("hidden", UInt32(commands.count - 1)), ("none", UInt32(0))] {
            var crafted = data
            crafted.replaceSubrange(16 ..< 20, with: withUnsafeBytes(of: ncmds.littleEndian) { Data($0) })
            let file = directory / name
            try crafted.write(to: file)
            XCTAssertNil(try XCTUnwrap(MachO(File(data: crafted))).removingSignature(end: crafted.count), name)
            let reporter = Reporter(console: Console())
            XCTAssertEqual(try Unsigner.lines(for: file.path, write: false, reporter: reporter).count, 0, name)
            _ = try execute("/usr/bin/codesign", ["--remove-signature", file.path])
            XCTAssertEqual(try Data(contentsOf: file), crafted, "\(name): codesign leaves it as it is")
        }
    }
}
