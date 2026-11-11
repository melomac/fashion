import CryptoKit
@testable import fashion
import MachO
import XCTest

/**
 `verify` names what is odd about a Mach-O, one line each, and nothing about one with nothing to say.
 */
final class VerifierTests: XCTestCase {
    /// The package root, which the fixtures are kept under whatever the test process's working directory.
    private static let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()

    private func directory(_ name: String) throws -> URL {
        let url = Self.root / ".build/tests/VerifierTests/\(name)"
        try? FileManager.default.removeItem(at: url)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    /// What `verify` says of `path`, and the errors it counted. The file seeds the fuzzer's corpora.
    private func verify(_ path: String) -> (lines: [String], errors: Int) {
        saveFixture(path: path)
        let reporter = Reporter(console: Console())
        return (Verify.lines(for: path, reporter: reporter).map(\.text), reporter.errorCount)
    }

    /// `verify` says `lines` of `path`, and counts no error.
    private func assertVerify(_ path: String, _ lines: [String], file: StaticString = #filePath, line: UInt = #line) {
        let verified = self.verify(path)
        XCTAssertEqual(verified.lines, lines, file: file, line: line)
        XCTAssertEqual(verified.errors, 0, file: file, line: line)
    }

    /// The `x86_64` slice of `/bin/ls`, as the fat table places it.
    private func lsX86() throws -> Data {
        let data = try Data(contentsOf: URL(fileURLWithPath: "/bin/ls"))
        guard case let .fat(archs) = try Universal.open(File(path: "/bin/ls")), let arch = archs.first(where: { $0.cpuType == CPU_TYPE_X86_64 }) else {
            throw XCTSkip("/bin/ls has no x86_64 slice")
        }
        return Universal.sliceData(fileData: data, arch: arch)
    }

    /**
     Apple's own binaries, universal and thin, have nothing to say, nor has a program as the toolchain links, strips
     and signs it, nor a file that is not Mach-O. Unsigned, an arm64 program is one the kernel refuses to run, which
     is all there is to say about it.
     */
    func testSoundFilesSayNothing() throws {
        let directory = try self.directory("sound")
        let built = try compile("built", in: directory, ["-arch", "arm64"])
        self.assertVerify("/bin/ls", [])
        self.assertVerify(built.path, ["\(built.path): not signed, which the kernel refuses to run as arm64"])
        try XCTSkipUnless(execute("/usr/bin/xcrun", ["strip", built.path]), "cannot run strip")
        self.assertVerify(built.path, ["\(built.path): not signed, which the kernel refuses to run as arm64"])
        _ = try codesign(["-f", "-s", "-", built.path])
        self.assertVerify(built.path, [])
        try Data("not a Mach-O".utf8).write(to: directory / "text")
        self.assertVerify((directory / "text").path, [])
    }

    /**
     A crafted executable of `size` bytes in `directory`, `x86_64` unless `cpuType` says otherwise, its load commands
     the `segments` given as name, vmaddr, vmsize, fileoff, filesize and protection, then `commands` as given.
     */
    private func crafted(_ name: String, in directory: URL, cpuType: cpu_type_t = CPU_TYPE_X86_64, size: Int, segments: [(String, UInt64, UInt64, UInt64, UInt64, UInt32)], commands: [Data] = []) throws -> URL {
        var data = Data()
        data.appendUInt32(MH_MAGIC_64)
        data.appendInt32(cpuType)
        data.appendInt32(0)
        data.appendUInt32(UInt32(MH_EXECUTE))
        data.appendUInt32(UInt32(segments.count + commands.count)) // ncmds
        data.appendUInt32(UInt32(segments.count * 72 + commands.reduce(0) { $0 + $1.count })) // sizeofcmds
        data.appendUInt32(0)
        data.appendUInt32(0)
        for (name, vmaddr, vmsize, fileoff, filesize, prot) in segments {
            data.appendUInt32(UInt32(LC_SEGMENT_64))
            data.appendUInt32(72)
            data.append(Data(name.utf8)); data.append(Data(repeating: 0, count: 16 - name.utf8.count))
            data.appendUInt64(vmaddr); data.appendUInt64(vmsize); data.appendUInt64(fileoff); data.appendUInt64(filesize)
            data.appendUInt32(prot); data.appendUInt32(prot); data.appendUInt32(0); data.appendUInt32(0) // maxprot, initprot, nsects, flags
        }
        commands.forEach { data.append($0) }
        data.append(Data(count: size - data.count))
        let file = directory / name
        try data.write(to: file)
        return file
    }

    /**
     The structural lines a crafted image draws, each pinned on a file with one thing wrong: an `LC_SEGMENT_64` in a
     32-bit image, two `LC_BUILD_VERSION`, two `LC_VERSION_MIN_*`, both kinds, a file size over the vmsize, protection
     bits beyond rwx, a protection over its maximum, `__TEXT` not at offset 0, too small for the load commands or
     not r-x, no `__TEXT`, `__LINKEDIT` not r--, `__DATA` not rw-, a `__DATA_CONST` of a bundle not rw-; and the
     dylib rules: no `LC_ID_DYLIB` in a dylib, one in an executable, a dynamic image linking nothing, flat namespace.
     */
    func testTheStructuralLinesAreNamed() throws {
        let directory = try self.directory("structural")
        let text: (String, UInt64, UInt64, UInt64, UInt64, UInt32) = ("__TEXT", 0x1000, 0x1000, 0, 0x1000, 5)
        let linkedit: (String, UInt64, UInt64, UInt64, UInt64, UInt32) = ("__LINKEDIT", 0x3000, 0x1000, 0x1000, 0x10, 1)
        func build(_ platform: UInt32 = 1) -> Data {
            var command = Data()
            [UInt32(LC_BUILD_VERSION), 24, platform, 0x000e_0000, 0x000e_0000, 0].forEach { command.appendUInt32($0) }
            return command
        }
        func versionMin() -> Data {
            var command = Data()
            [UInt32(LC_VERSION_MIN_MACOSX), 16, 0x000e_0000, 0x000e_0000].forEach { command.appendUInt32($0) }
            return command
        }
        /// The lines of the crafted file `name` of `segments` and `commands`, `edited` in place first.
        func lines(_ name: String, segments: [(String, UInt64, UInt64, UInt64, UInt64, UInt32)], commands: [Data] = [], edited: (inout Data) -> Void = { _ in }) throws -> [String] {
            let file = try self.crafted(name, in: directory, size: 0x1010, segments: segments, commands: commands)
            var data = try Data(contentsOf: file)
            edited(&data)
            try data.write(to: file)
            return self.verify(file.path).lines.map { $0.replacingOccurrences(of: file.path, with: "") }
        }
        var thin = Data()
        [MH_MAGIC, UInt32(CPU_TYPE_I386), 3, UInt32(MH_EXECUTE), 1, 72, 0].forEach { thin.appendUInt32($0) }
        thin += try Data(contentsOf: self.crafted("wide", in: directory, size: 0x1010, segments: [text])).subdata(in: 32 ..< 104)
        thin.append(Data(count: 0x1010 - thin.count))
        try thin.write(to: directory / "thin")
        XCTAssertTrue(self.verify((directory / "thin").path).lines.contains("\((directory / "thin").path): LC_SEGMENT_64 in a 32-bit image"))

        let builds = try lines("builds", segments: [text, linkedit], commands: [build(), build(2)])
        XCTAssertTrue(builds.contains(": 2 LC_BUILD_VERSION commands"), builds.joined(separator: "\n"))
        let mins = try lines("mins", segments: [text, linkedit], commands: [versionMin(), versionMin()])
        XCTAssertTrue(mins.contains(": 2 LC_VERSION_MIN_* commands"), mins.joined(separator: "\n"))
        let both = try lines("both", segments: [text, linkedit], commands: [build(), versionMin()])
        XCTAssertTrue(both.contains(": LC_BUILD_VERSION and LC_VERSION_MIN_* both"), both.joined(separator: "\n"))

        XCTAssertTrue(try lines("filesize", segments: [("__TEXT", 0x1000, 0x800, 0, 0x1000, 5), linkedit]).contains(": segment __TEXT's file size 0x1000 exceeds its vmsize 0x800"))
        XCTAssertTrue(try lines("bits", segments: [text, ("__DATA", 0x2000, 0x1000, 0x1000, 0x10, 0x13), linkedit]).contains(": segment __DATA's protection has bits beyond rwx: 0x13 within 0x13"))
        XCTAssertTrue(try lines("maximum", segments: [text, ("__DATA", 0x2000, 0x1000, 0x1000, 0x10, 3), linkedit]) { $0.store(UInt32(7), at: 32 + 72 + 60) }.contains(": segment __DATA's protection rwx exceeds its maximum rw-"))
        XCTAssertTrue(try lines("offset", segments: [("__TEXT", 0x1000, 0x1000, 0x1000, 0x10, 5), linkedit]).contains(": __TEXT starts at file offset 0x1000, not 0"))
        XCTAssertTrue(try lines("small", segments: [("__TEXT", 0x1000, 0x1000, 0, 0x10, 5), linkedit]).contains(": the load commands, 0xb0 bytes, do not fit in __TEXT's 0x10"))
        XCTAssertTrue(try lines("rwx", segments: [("__TEXT", 0x1000, 0x1000, 0, 0x1000, 7), linkedit]).contains(": __TEXT's protection is rwx, not r-x"))
        XCTAssertTrue(try lines("notext", segments: [("__DATA", 0x1000, 0x1000, 0, 0x1000, 3), linkedit]).contains(": no __TEXT segment"))
        XCTAssertTrue(try lines("linkedit", segments: [text, ("__LINKEDIT", 0x3000, 0x1000, 0x1000, 0x10, 3)]).contains(": __LINKEDIT's protection is rw-, not r--"))
        XCTAssertTrue(try lines("data", segments: [text, ("__DATA", 0x2000, 0x1000, 0x1000, 0x10, 5), linkedit]).contains(": __DATA's protection is r-x, not rw-"))
        let bundle = try lines("bundle", segments: [text, ("__DATA_CONST", 0x2000, 0x1000, 0x1000, 0x10, 1), linkedit]) { $0.store(UInt32(MH_BUNDLE), at: 12) }
        XCTAssertTrue(bundle.contains(": __DATA_CONST's protection is r--, not rw-, which dyld refuses"), bundle.joined(separator: "\n"))

        let dylib = try lines("dylib", segments: [text, linkedit]) { $0.store(UInt32(MH_DYLIB), at: 12) }
        XCTAssertTrue(dylib.contains(": no LC_ID_DYLIB for a dylib"), dylib.joined(separator: "\n"))
        XCTAssertTrue(dylib.contains(": links no dylib"))
        var id = Data()
        [UInt32(LC_ID_DYLIB), 48, 24, 0, 0, 0].forEach { id.appendUInt32($0) } // name 24 bytes in, after the versions
        id += Data("/usr/lib/libx.dylib".utf8) + Data(count: 5)
        let named = try lines("named", segments: [text, linkedit], commands: [id])
        XCTAssertTrue(named.contains(": LC_ID_DYLIB /usr/lib/libx.dylib in an MH_EXECUTE"), named.joined(separator: "\n"))
        let flat = try lines("flat", segments: [text, linkedit]) { $0.store(UInt32(MH_DYLDLINK), at: 24) }
        XCTAssertTrue(flat.contains(": flat namespace: no MH_TWOLEVEL"), flat.joined(separator: "\n"))
        XCTAssertTrue(flat.contains(": links no dylib"))
    }

    /**
     Segments out of order in the file and in memory, as a crafted image lays them, an executable with no entry point
     and no version command: each is a line, in the order the headers are read.
     */
    func testACraftedImageHasItsOddsNamed() throws {
        let directory = try self.directory("crafted")
        let file = try self.crafted("crafted", in: directory, size: 0x1110, segments: [("__DATA", 0x2000, 0x1000, 0x1000, 0x100, 3), ("__TEXT", 0x1000, 0x1000, 0, 0x1000, 5), ("__LINKEDIT", 0x3000, 0x1000, 0x1100, 0x10, 1)])
        self.assertVerify(file.path, [
            "\(file.path): no external symbol table",
            "\(file.path): segment __TEXT's file offset 0x0 is out of order after __DATA's 0x1000",
            "\(file.path): segment __TEXT's address 0x1000 is out of order after __DATA's 0x2000",
            "\(file.path): segment __LINKEDIT's file offset 0x1100 is not page aligned",
            "\(file.path): __TEXT has no sections",
            "\(file.path): no LC_MAIN nor LC_UNIXTHREAD for an executable",
            "\(file.path): no LC_UUID",
            "\(file.path): no MH_DYLDLINK: a static executable",
            "\(file.path): no LC_BUILD_VERSION nor LC_VERSION_MIN_* dates it",
        ])
    }

    /**
     A segment's file offset is held to the page the platform maps, as codesign's `MachORep::pageSize` has it: an
     arm64 image for iOS 7 lays its segments on 4 KiB, which the kernel maps on 4 KiB pages, where one for macOS on
     4 KiB is off its 16 KiB page.
     */
    func testTheSegmentPageIsThePlatformsAsCodesignHasIt() throws {
        let directory = try self.directory("page")
        let segments: [(String, UInt64, UInt64, UInt64, UInt64, UInt32)] = [("__TEXT", 0x1000, 0x1000, 0, 0x1000, 5), ("__DATA", 0x2000, 0x1000, 0x1000, 0x1000, 3)]
        var versionMin = Data()
        [UInt32(LC_VERSION_MIN_IPHONEOS), 16, 0x0007_0000, 0x0007_0000].forEach { versionMin.appendUInt32($0) }
        let ios = try self.crafted("ios", in: directory, cpuType: CPU_TYPE_ARM64, size: 0x2000, segments: segments, commands: [versionMin])
        XCTAssertFalse(self.verify(ios.path).lines.contains { $0.contains("is not page aligned") })
        var build = Data()
        [UInt32(LC_BUILD_VERSION), 24, UInt32(PLATFORM_MACOS), 0x000e_0000, 0x000e_0000, 0].forEach { build.appendUInt32($0) }
        let mac = try self.crafted("mac", in: directory, cpuType: CPU_TYPE_ARM64, size: 0x2000, segments: segments, commands: [build])
        XCTAssertTrue(self.verify(mac.path).lines.contains("\(mac.path): segment __DATA's file offset 0x1000 is not page aligned"))
    }

    /**
     A filetype no loader knows, one past `Int32` among them, which the fuzzer found tripping a conversion, is named
     rather than tripped over; `__TEXT` is not asked of it.
     */
    func testAFiletypeNoLoaderKnowsIsNamed() throws {
        let directory = try self.directory("filetype")
        let file = try self.crafted("filetype", in: directory, size: 0x1000, segments: [("__TEXT", 0x1000, 0x1000, 0, 0x1000, 5)])
        var data = try Data(contentsOf: file)
        data.store(UInt32(0xdefa_0002), at: 12)
        try data.write(to: file)
        self.assertVerify(file.path, [
            "\(file.path): no external symbol table",
            "\(file.path): filetype unknown(3740925954), which no loader knows",
            "\(file.path): no LC_BUILD_VERSION nor LC_VERSION_MIN_* dates it",
            "\(file.path): neither a __LINKEDIT segment nor an LC_SYMTAB ends the image, which codesign's strict validation refuses",
        ])
    }

    /**
     A segment whose address and vmsize add up past the address space, which no loader maps, is named rather than
     tripped over, and overlaps nothing.
     */
    func testAnAddressRangeThatWrapsAroundIsNamed() throws {
        let directory = try self.directory("wrap")
        let file = try self.crafted("wrap", in: directory, size: 0x1002, segments: [("__TEXT", 0, 0x1000, 0, 0x1000, 5), ("__DATA", UInt64.max, 2, 0x1000, 2, 3)])
        self.assertVerify(file.path, [
            "\(file.path): no external symbol table",
            "\(file.path): segment __DATA's address 0xffffffffffffffff and vmsize 0x2 wrap around the address space",
            "\(file.path): __TEXT has no sections",
            "\(file.path): no LC_MAIN nor LC_UNIXTHREAD for an executable",
            "\(file.path): no LC_UUID",
            "\(file.path): no MH_DYLDLINK: a static executable",
            "\(file.path): no LC_BUILD_VERSION nor LC_VERSION_MIN_* dates it",
            "\(file.path): neither a __LINKEDIT segment nor an LC_SYMTAB ends the image, which codesign's strict validation refuses",
        ])
    }

    /**
     What no loader maps says nothing: a universal archive, whose slices `lipo` aligns to 8 for their members' symbols,
     and a dSYM companion, thin or universal, which dsymutil lays out with `__TEXT` empty and `__DWARF` after
     `__LINKEDIT`.
     */
    func testWhatNoLoaderMapsSaysNothing() throws {
        let directory = try self.directory("unmapped")
        let x86 = try compile("x86", in: directory, ["-arch", "x86_64", "-g"])
        let arm = try compile("arm", in: directory, ["-arch", "arm64", "-g"])
        let fat = directory / "fat"
        try XCTSkipUnless(execute("/usr/bin/xcrun", ["lipo", "-create", x86.path, arm.path, "-output", fat.path]), "cannot run lipo")
        for binary in [x86, fat] {
            let dsym = directory / "\(binary.lastPathComponent).dSYM"
            try XCTSkipUnless(execute("/usr/bin/xcrun", ["dsymutil", binary.path, "-o", dsym.path]), "cannot run dsymutil")
            self.assertVerify((dsym / "Contents/Resources/DWARF/\(binary.lastPathComponent)").path, [])
        }

        for arch in ["x86_64", "arm64"] {
            try XCTSkipUnless(execute("/usr/bin/xcrun", ["clang", "-c", "-arch", arch, (directory / "main.c").path, "-o", (directory / "\(arch).o").path]), "cannot compile an object")
            try XCTSkipUnless(execute("/usr/bin/xcrun", ["ar", "rcs", (directory / "\(arch).a").path, (directory / "\(arch).o").path]), "cannot run ar")
        }
        let archive = directory / "fat.a"
        try XCTSkipUnless(execute("/usr/bin/xcrun", ["lipo", "-create", (directory / "x86_64.a").path, (directory / "arm64.a").path, "-output", archive.path]), "cannot run lipo")
        guard case let .fat(archs) = try Universal.open(File(path: archive.path)) else {
            return XCTFail("lipo made no universal archive")
        }
        XCTAssertTrue(archs.contains { $0.offset % 0x1000 != 0 }, "lipo aligns an archive's slices below the page")
        self.assertVerify(archive.path, [])
    }

    /**
     A slice the parser refuses, its `__LINKEDIT` past the slice, is red and counted, named for its architecture, where
     the lines of the file and of the other slices stand.
     */
    func testASliceTheParserRefusesIsRedBesideTheOthers() throws {
        let directory = try self.directory("refused-slice")
        let slice = try self.lsX86()
        let x86 = slice + Data(repeating: 0x4a, count: 100)
        var arm = try Data(contentsOf: compile("arm", in: directory, ["-arch", "arm64"]))
        let linkedit = try XCTUnwrap(XCTUnwrap(MachO(File(data: arm))).findSegment("__LINKEDIT"))
        let fileoff = try linkedit.data.startIndex + XCTUnwrap(MemoryLayout<segment_command_64>.offset(of: \.fileoff))
        arm.replaceSubrange(fileoff ..< fileoff + 8, with: withUnsafeBytes(of: UInt64(arm.count + 0x1000).littleEndian) { Data($0) })

        let armOffset = 0x1000 + (x86.count + 0xfff) & ~0xfff
        var fat = Data()
        for word in [FAT_MAGIC, 2] + [UInt32(bitPattern: CPU_TYPE_X86_64), 3, UInt32(0x1000), UInt32(x86.count), 12] + [UInt32(bitPattern: CPU_TYPE_ARM64), 0, UInt32(armOffset), UInt32(arm.count), 12] {
            fat.append(contentsOf: withUnsafeBytes(of: word.bigEndian) { Data($0) })
        }
        fat.append(Data(count: 0x1000 - fat.count)); fat.append(x86); fat.append(Data(count: armOffset - fat.count)); fat.append(arm)
        let file = directory / "fat"
        try fat.write(to: file)

        let reporter = Reporter(console: Console())
        let lines = Verify.lines(for: file.path, reporter: reporter)
        XCTAssertEqual(lines.map(\.text).first, "\(file.path) (x86_64): 0x64 bytes appended past the image's end at \(slice.count.hex)")
        XCTAssertEqual(lines.count, 2)
        XCTAssertEqual(lines.last?.tint, .malformed)
        XCTAssertTrue(try XCTUnwrap(lines.last).text.hasPrefix("fashion: \(file.path) (arm64): Invalid Mach-O: segment __LINKEDIT at offset"))
        XCTAssertEqual(reporter.errorCount, 1)
    }

    /**
     Bytes appended past a slice's image are named with their count and where the image ends; a universal file with
     bytes past its last slice too, and the slices themselves say nothing.
     */
    func testAppendedBytesAreNamed() throws {
        let directory = try self.directory("appended")
        let slice = try self.lsX86()
        let thin = directory / "ls_x86_64"
        try (slice + Data(repeating: 0x4a, count: 100)).write(to: thin)
        self.assertVerify(thin.path, ["\(thin.path): 0x64 bytes appended past the image's end at \(slice.count.hex)"])

        let arm = try compile("arm", in: directory, ["-arch", "arm64"])
        let x86 = try compile("x86", in: directory, ["-arch", "x86_64"])
        let fat = directory / "fat"
        try XCTSkipUnless(execute("/usr/bin/xcrun", ["lipo", "-create", x86.path, arm.path, "-output", fat.path]), "cannot run lipo")
        let size = try Data(contentsOf: fat).count
        try (Data(contentsOf: fat) + Data(repeating: 0x4a, count: 10)).write(to: fat)
        self.assertVerify(fat.path, ["\(fat.path): 0xa bytes past the last slice, arm64's end at \(size.hex)", "\(fat.path) (arm64): not signed, which the kernel refuses to run as arm64"])
    }

    /**
     `codesign --remove-signature` leaves `__LINKEDIT`'s vmsize at the 16 KiB the signature needed, which names a
     signature that came out, where `unsign` restores it as the linker or `strip` left it and leaves no such trace;
     nothing is named of a stripped image whose linker is unknown, whose `strip` may have rounded it so itself, nor of an
     `x86_64` image linked on 16 KiB pages (`ld -segalign 0x4000`), whose linker rounded it so, nor of one `strip -S`
     kept every symbol of, which `strip` rounded all the same.
     */
    func testASignatureThatCameOutIsNamed() throws {
        let directory = try self.directory("residue")
        let signed = directory / "ls_x86_64"
        try self.lsX86().write(to: signed)
        self.assertVerify(signed.path, [])
        let apple = directory / "apple"
        try FileManager.default.copyItem(at: signed, to: apple)
        _ = try codesign(["--remove-signature", apple.path])
        let vmsize = try XCTUnwrap(XCTUnwrap(MachO(File(path: apple.path))).findSegment("__LINKEDIT")).load(segment_command_64.self).vmsize
        self.assertVerify(apple.path, ["\(apple.path): __LINKEDIT's vmsize \(vmsize.hex) is a signature's 16 KiB rounding on an image without one: a signature came out"])
        XCTAssertEqual(try Unsigner.lines(for: signed.path, write: false, reporter: Reporter(console: Console())).map(\.text), [signed.path + "_unsigned"])
        self.assertVerify(signed.path + "_unsigned", [])

        // A stripped image built for macOS 10.13 records no linker, since ld writes LC_VERSION_MIN_MACOSX for it; its
        // SDK, today's, dates it to a strip that rounds __LINKEDIT's vmsize to 16 KiB itself: no signature came out.
        let old = try compile("old", in: directory, ["-arch", "x86_64", "-mmacosx-version-min=10.13"])
        try XCTSkipUnless(execute("/usr/bin/xcrun", ["strip", old.path]), "cannot run strip")
        let stripped = try XCTUnwrap(MachO(File(path: old.path)))
        XCTAssertNil(stripped.linkerVersion)
        XCTAssertEqual(stripped.linkeditSizeRounding, 0x4000)
        self.assertVerify(old.path, [])

        // An image linked on 16 KiB pages was never signed: its vmsize is the linker's, more than 4 KiB gives it.
        let wide = try compile("linked-16k", in: directory, ["-arch", "x86_64", "-Wl,-segalign,0x4000"])
        XCTAssertEqual(try XCTUnwrap(XCTUnwrap(MachO(File(path: wide.path))).findSegment("__LINKEDIT")).load(segment_command_64.self).vmsize, 0x4000)
        self.assertVerify(wide.path, [])

        // strip rounds to 16 KiB whatever it keeps, here every symbol: it was never signed either.
        let kept = try compile("kept", in: directory, ["-arch", "x86_64"])
        try XCTSkipUnless(execute("/usr/bin/xcrun", ["strip", "-S", kept.path]), "cannot run strip")
        XCTAssertEqual(try XCTUnwrap(XCTUnwrap(MachO(File(path: kept.path))).findSegment("__LINKEDIT")).load(segment_command_64.self).vmsize, 0x4000)
        self.assertVerify(kept.path, [])
    }

    /**
     A file UPX packed is named for it, by a modified UPX with its marker, and signed after packing as such, the
     signature hiding what UPX left from a look at the file as it is, with bytes appended after signing too. A pack
     header that does not hold is named as unpack refuses it, behind a signature added after packing as well. A
     `p_info` whose size for the original is not the pack header's is told apart: UPX writes the one value in both,
     and only the pack header's lies under a checksum.
     */
    func testUPXIsNamed() throws {
        let directory = try self.directory("upx")
        let unsigned = directory / "ls_x86_64"
        try self.lsX86().write(to: unsigned)
        _ = try codesign(["--remove-signature", unsigned.path])
        let packed = directory / "packed"
        try XCTSkipUnless(execute(upxExecutable(), ["-q", "--force-macos", "-o", packed.path, unsigned.path]), "upx cannot pack it")
        XCTAssertTrue(self.verify(packed.path).lines.contains("\(packed.path): packed by UPX"))
        let swapped = directory / "swapped"
        try Data(contentsOf: packed).replacing(Data("UPX!".utf8), with: Data("VQY\"".utf8)).write(to: swapped)
        XCTAssertTrue(self.verify(swapped.path).lines.contains("\(swapped.path): packed by a modified UPX, its marker \"VQY\\\"\" in place of \"UPX!\""))
        let signed = directory / "signed"
        try FileManager.default.copyItem(at: packed, to: signed)
        _ = try codesign(["-f", "-s", "-", signed.path])
        XCTAssertTrue(self.verify(signed.path).lines.contains("\(signed.path): packed by UPX, signed after packing"))
        let appended = directory / "appended"
        try (Data(contentsOf: signed) + Data(repeating: 0x41, count: 16)).write(to: appended)
        let lines = self.verify(appended.path).lines
        XCTAssertTrue(try lines.contains("\(appended.path): 0x10 bytes appended past the image's end at \(Data(contentsOf: signed).count.hex)"))
        XCTAssertTrue(lines.contains("\(appended.path): packed by UPX, signed after packing"))
        // A pack header that does not hold, its checksum wrong, is named as unpack refuses it; so is none before
        // UPX's 16-byte __LINKEDIT, a byte written into the padding after the header hiding it from the scan.
        var broken = try Data(contentsOf: packed)
        let header = try XCTUnwrap(broken.ranges(of: Data("UPX!".utf8)).last).lowerBound
        broken[header + 31] ^= 0xff
        let corrupt = directory / "corrupt"
        try broken.write(to: corrupt)
        XCTAssertTrue(self.verify(corrupt.path).lines.contains("\(corrupt.path): Invalid UPX data: header corrupted 3, which unpack refuses"))
        let corruptSigned = directory / "corrupt-signed"
        try FileManager.default.copyItem(at: corrupt, to: corruptSigned)
        _ = try codesign(["-f", "-s", "-", corruptSigned.path])
        XCTAssertTrue(self.verify(corruptSigned.path).lines.contains("\(corruptSigned.path): Invalid UPX data: header corrupted 3, signed after packing, which unpack refuses"))
        var padded = try Data(contentsOf: packed)
        XCTAssertEqual(padded[header + 40], 0)
        padded[header + 40] = 1
        let hidden = directory / "hidden"
        try padded.write(to: hidden)
        XCTAssertTrue(self.verify(hidden.path).lines.contains("\(hidden.path): Invalid UPX data: file corrupted: no pack header before the 16-byte __LINKEDIT UPX writes, which unpack refuses"))
        // The p_info's size for the original, 4 bytes into the 12 at the overlay offset the pack header ends with,
        // raised by a page: the file is packed all the same, and the two sizes are told apart; as UPX wrote it, not.
        var claimed = try Data(contentsOf: packed)
        let overlay = Int(claimed.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: header + 32, as: UInt32.self) }.littleEndian)
        let original = Int(claimed.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: overlay + 4, as: UInt32.self) }.littleEndian)
        claimed.replaceSubrange(overlay + 4 ..< overlay + 8, with: withUnsafeBytes(of: UInt32(original + 0x1000).littleEndian) { Data($0) })
        let overstated = directory / "overstated"
        try claimed.write(to: overstated)
        let claims = self.verify(overstated.path).lines
        XCTAssertTrue(claims.contains("\(overstated.path): packed by UPX"))
        XCTAssertTrue(claims.contains("\(overstated.path): UPX's p_info claims \(original + 0x1000) bytes for the original where its pack header, under its checksum, says \(original)"))
        XCTAssertFalse(self.verify(packed.path).lines.contains { $0.contains("UPX's p_info claims") })
    }

    /**
     What the parser refuses, a segment lying past the file, comes out red and counted, as hash mode reports it.
     */
    func testWhatTheParserRefusesIsRed() throws {
        let directory = try self.directory("refused")
        var data = try self.lsX86()
        let linkedit = try XCTUnwrap(XCTUnwrap(MachO(File(data: data))).findSegment("__LINKEDIT"))
        let fileoff = try linkedit.data.startIndex + XCTUnwrap(MemoryLayout<segment_command_64>.offset(of: \.fileoff))
        data.replaceSubrange(fileoff ..< fileoff + 8, with: withUnsafeBytes(of: UInt64(data.count + 0x1000).littleEndian) { Data($0) })
        let file = directory / "cut"
        try data.write(to: file)
        let reporter = Reporter(console: Console())
        let lines = Verify.lines(for: file.path, reporter: reporter)
        XCTAssertEqual(lines.map(\.tint), [.malformed])
        XCTAssertTrue(try XCTUnwrap(lines.first).text.hasPrefix("fashion: \(file.path): Invalid Mach-O: segment __LINKEDIT at offset"))
        XCTAssertEqual(reporter.errorCount, 1)
    }

    // MARK: - Crafted from a program

    /**
     A program as clang links it for `arch`, with headerpad room for commands appended and a call into libSystem, so
     that it has stubs and a `__DATA_CONST` segment, as bytes to patch into a crafted file.
     */
    private func program(_ arch: String, in directory: URL) throws -> Data {
        try Data(contentsOf: compile("program_\(arch)", in: directory, source: "#include <stdio.h>\nstatic int local(int x) { return x + 1; }\nint main(void) { printf(\"%d\\n\", local(1)); return 0; }\n", ["-arch", arch, "-Wl,-headerpad,0x800"]))
    }

    /// What `verify` says of `data` written as `name` in `directory`, the path cut off, and whether it counted an error.
    private func verify(_ data: Data, _ name: String, in directory: URL) throws -> (lines: [String], errors: Int) {
        let file = directory / name
        try data.write(to: file)
        let verified = self.verify(file.path)
        return (verified.lines.map { $0.replacingOccurrences(of: "fashion: ", with: "").replacingOccurrences(of: file.path, with: "") }, verified.errors)
    }

    /// The first load command of type `cmd` in `data`.
    private func command(_ cmd: UInt32, in data: Data) throws -> MachO.LoadCommand {
        try XCTUnwrap(XCTUnwrap(MachO(File(data: data))).findCommand(cmd))
    }

    /// The offset in `data` of the `section_64` named `name` in the segment named `segment`.
    private func section(_ segment: String, _ name: String, in data: Data) throws -> Int {
        let command = try XCTUnwrap(XCTUnwrap(MachO(File(data: data))).findSegment(segment))
        let count = try Int(command.load(segment_command_64.self).nsects)
        for index in 0 ..< count {
            let at = command.data.startIndex + MemoryLayout<segment_command_64>.size + index * MemoryLayout<section_64>.size
            if MachO.field(data.bytes(in: at ..< at + 16), is: name) {
                return at
            }
        }
        throw XCTSkip("no section \(segment),\(name)")
    }

    /// `data` with a load command appended to its table, in the headerpad.
    private func appending(_ command: Data, to data: Data) -> Data {
        var data = data
        let sizeofcmds = Int(data.load(UInt32.self, at: 20))
        data.replaceSubrange(32 + sizeofcmds ..< 32 + sizeofcmds + command.count, with: command)
        data.store(data.load(UInt32.self, at: 16) + 1, at: 16)
        data.store(UInt32(sizeofcmds + command.count), at: 20)
        return data
    }

    /// An `LC_SEGMENT_64` command, with no sections.
    private func segment64(_ name: String, vmaddr: UInt64, vmsize: UInt64, fileoff: UInt64 = 0, filesize: UInt64 = 0, prot: Int32) -> Data {
        var command = Data()
        command.appendUInt32(UInt32(LC_SEGMENT_64))
        command.appendUInt32(72)
        command.append(Data(name.utf8)); command.append(Data(count: 16 - name.utf8.count))
        [vmaddr, vmsize, fileoff, filesize].forEach { command.appendUInt64($0) }
        command.appendInt32(prot); command.appendInt32(prot); command.appendUInt32(0); command.appendUInt32(0)
        return command
    }

    /// A load command of type `cmd` carrying `string` as its `lc_str`, 8 bytes in, NUL-terminated and padded to 8.
    private func string(_ cmd: Int32, _ string: String) -> Data {
        var variable = Data(string.utf8) + [0]
        variable.append(Data(count: (8 - (12 + variable.count) % 8) % 8))
        var command = Data()
        command.appendUInt32(UInt32(cmd))
        command.appendUInt32(UInt32(12 + variable.count))
        command.appendUInt32(12)
        command.append(variable)
        return command
    }

    /// An `LC_UNIXTHREAD` command with `x86_64`'s thread state, its rip at `rip`; `flavor` and `count` as given otherwise.
    private func unixthread(rip: UInt64, flavor: UInt32 = 4, count: UInt32 = 42) -> Data {
        self.unixthread(states: [(flavor, count, rip)])
    }

    /// An `LC_UNIXTHREAD` command of `states` in turn, each a flavor, a count of words and a pc at `x86_64`'s rip,
    /// register 16, or at `register`, when the state has the words for it.
    private func unixthread(states: [(flavor: UInt32, count: UInt32, pc: UInt64)], register: Int = 16) -> Data {
        var command = Data()
        command.appendUInt32(UInt32(LC_UNIXTHREAD))
        command.appendUInt32(UInt32(8 + states.reduce(0) { $0 + 8 + Int($1.count) * 4 }))
        for state in states {
            command.appendUInt32(state.flavor)
            command.appendUInt32(state.count)
            var registers = Data(count: Int(state.count) * 4)
            if registers.count >= register * 8 + 8 {
                registers.replaceSubrange(register * 8 ..< register * 8 + 8, with: withUnsafeBytes(of: state.pc.littleEndian) { Data($0) })
            }
            command.append(registers)
        }
        return command
    }

    /**
     The table as the loaders walk it: `ncmds` short of the commands the table holds names the commands hidden from
     the loaders, one more than it holds is named too, as are bytes past the last command inside `sizeofcmds`, a
     command size that is not a multiple of 4, a command of
     a fixed structure sized otherwise, a command dyld does not know when it is flagged `LC_REQ_DYLD` and not when it
     is not, a 32-bit `LC_SEGMENT` in a 64-bit image, the reserved field holding anything, a command the loaders take
     once twice, `LC_DYSYMTAB` without `LC_SYMTAB` or partitioning the symbol table other than as the linker lays it,
     `LC_LINKER_OPTION` in an executable, and `LC_MAIN` beside `LC_UNIXTHREAD`.
     */
    func testTheTableAsTheLoadersWalkItIsNamed() throws {
        let directory = try self.directory("table")
        let program = try self.program("x86_64", in: directory)
        let commands = try XCTUnwrap(MachO(File(data: program))).loadCommands

        var short = program
        short.store(UInt32(commands.count - 1), at: 16)
        XCTAssertEqual(try self.verify(short, "short", in: directory).lines, try [": ncmds \(commands.count - 1) hides the last 1 command of \(commands.count) from the loaders: \(XCTUnwrap(commands.last).name)"])
        // A segment hidden past ncmds lying past the file: the kernel never reads it, codesign signs and verifies the
        // image, hash mode hashes it, and verify names the hidden command alone.
        var hidden = program
        let end = 32 + Int(program.load(UInt32.self, at: 20))
        XCTAssertTrue(hidden[end ..< end + 72].allSatisfy { $0 == 0 }, "room in the header pad")
        var segment = Data()
        [UInt32(LC_SEGMENT_64), 72].forEach { segment.appendUInt32($0) }
        segment.append(Data("__HIDDEN".utf8)); segment.append(Data(count: 8))
        [UInt64(0), 0x1000, UInt64(program.count) + 0x1000, 0x1000].forEach { segment.appendUInt64($0) } // vmaddr, vmsize, fileoff, filesize
        [UInt32(1), 1, 0, 0].forEach { segment.appendUInt32($0) }
        hidden.replaceSubrange(end ..< end + 72, with: segment)
        hidden.store(UInt32(end - 32 + 72), at: 20)
        XCTAssertEqual(try self.verify(hidden, "hidden", in: directory).lines, [": ncmds \(commands.count) hides the last 1 command of \(commands.count + 1) from the loaders: LC_SEGMENT_64"])
        XCTAssertFalse(try CDHash.hash(fixture: hidden).isEmpty)
        _ = try codesign(["-s", "-", (directory / "hidden").path])
        XCTAssertTrue(try execute("/usr/bin/codesign", ["--verify", "--strict", (directory / "hidden").path]))
        var long = program
        long.store(UInt32(commands.count + 1), at: 16)
        XCTAssertEqual(try self.verify(long, "long", in: directory).lines, [": ncmds \(commands.count + 1) exceeds the \(commands.count) commands the table holds"])
        // dyld counts LC_DYLD_INFO_ONLY with LC_DYLD_INFO: one of each is two to it.
        var info = Data()
        info.appendUInt32(UInt32(LC_DYLD_INFO)); info.appendUInt32(48); info.append(Data(count: 40))
        var only = info
        only.store(LC_DYLD_INFO_ONLY, at: 0)
        XCTAssertTrue(try self.verify(self.appending(only, to: self.appending(info, to: program)), "aliased", in: directory).lines.contains(": LC_DYLD_INFO beside LC_DYLD_INFO_ONLY, which dyld counts as two LC_DYLD_INFO commands"))
        // The linker pads the header with zeros past the commands: sizeofcmds taking 8 of them in holds a tail.
        var tailed = program
        let sizeofcmds = try XCTUnwrap(MachO(File(data: program))).sizeofcmds
        XCTAssertEqual(program[(program.startIndex + 32 + sizeofcmds) ..< (program.startIndex + 32 + sizeofcmds + 8)], Data(count: 8))
        tailed.store(UInt32(sizeofcmds + 8), at: 20)
        XCTAssertEqual(try self.verify(tailed, "tailed", in: directory).lines, [": sizeofcmds holds 0x8 bytes past the last load command, which the loaders never read and Security's walk stops short of: codesign verifies the image and cannot re-sign it, Rosetta refuses it"])

        // The last command clang's linker writes is LC_DATA_IN_CODE, 16 bytes of fixed structure.
        var odd = program
        let last = try XCTUnwrap(commands.last)
        odd.store(UInt32(last.data.count + 2), at: last.data.startIndex + 4)
        try odd.store(UInt32(XCTUnwrap(MachO(File(data: program))).sizeofcmds + 2), at: 20)
        XCTAssertEqual(try self.verify(odd, "odd", in: directory).lines, [
            ": load command #\(commands.count - 1), \(last.name), has a size \((last.data.count + 2).hex) that is not a multiple of 8",
            ": load command #\(commands.count - 1), \(last.name), is \((last.data.count + 2).hex) bytes, not its structure's \(last.data.count.hex), which dyld refuses",
        ])
        var padded = program
        padded.store(UInt32(last.data.count + 8), at: last.data.startIndex + 4)
        try padded.store(UInt32(XCTUnwrap(MachO(File(data: program))).sizeofcmds + 8), at: 20)
        XCTAssertEqual(try self.verify(padded, "padded", in: directory).lines, [": load command #\(commands.count - 1), \(last.name), is \((last.data.count + 8).hex) bytes, not its structure's \(last.data.count.hex), which dyld refuses"])

        var unknown = Data()
        [UInt32(0x7f), 16, 0, 0].forEach { unknown.appendUInt32($0) }
        XCTAssertEqual(try self.verify(self.appending(unknown, to: program), "unknown", in: directory).lines, [])
        var required = Data()
        [UInt32(LC_REQ_DYLD) | 0x7f, 16, 0, 0].forEach { required.appendUInt32($0) }
        XCTAssertEqual(try self.verify(self.appending(required, to: program), "required", in: directory).lines, [": load command #\(commands.count), load command 0x8000007f, is unknown and flagged LC_REQ_DYLD, which dyld refuses"])

        let dysymtab = try self.command(UInt32(LC_DYSYMTAB), in: program)
        let fields = try dysymtab.load(dysymtab_command.self)
        var locals = program
        locals.store(UInt32(1), at: dysymtab.data.startIndex + 8)
        XCTAssertEqual(try self.verify(locals, "locals", in: directory).lines, [": LC_DYSYMTAB's local symbols start at 1, not 0, which dyld refuses"])
        // Relocation tables beside the chained fixups the linker wrote: dyld takes one fixup encoding.
        var relocated = program
        try relocated.store(self.command(UInt32(LC_SYMTAB), in: program).load(symtab_command.self).symoff, at: dysymtab.data.startIndex + 72)
        relocated.store(UInt32(2), at: dysymtab.data.startIndex + 76)
        XCTAssertEqual(try self.verify(relocated, "relocated", in: directory).lines, [": LC_DYSYMTAB holds 2 local relocations beside LC_DYLD_CHAINED_FIXUPS, which dyld refuses", ": the symbol table and the local relocations overlap in __LINKEDIT"])
        var externals = program
        externals.store(fields.iextdefsym + 1, at: dysymtab.data.startIndex + 16)
        XCTAssertEqual(try self.verify(externals, "externals", in: directory).lines, [
            ": LC_DYSYMTAB's external symbols start at \(fields.iextdefsym + 1), not after the \(String(Int(fields.nlocalsym), pluralizing: "local")) at 0, which dyld refuses",
            ": LC_DYSYMTAB's undefined symbols start at \(fields.iundefsym), not after the \(String(Int(fields.nextdefsym), pluralizing: "external")) at \(fields.iextdefsym + 1), which dyld refuses",
        ])

        var option = Data()
        [UInt32(LC_LINKER_OPTION), 16, 1].forEach { option.appendUInt32($0) }
        option.append(Data("-lz".utf8)); option.append(Data(count: 1))
        XCTAssertEqual(try self.verify(self.appending(option, to: program), "option", in: directory).lines, [": LC_LINKER_OPTION in an MH_EXECUTE, which dyld refuses: the compiler writes it in an object, for the linker"])

        var segment32 = Data()
        segment32.appendUInt32(UInt32(LC_SEGMENT)); segment32.appendUInt32(56); segment32.append(Data(count: 48))
        var reserved = self.appending(segment32, to: program)
        reserved.store(UInt32(0xdead_beef), at: 28)
        XCTAssertEqual(try self.verify(reserved, "reserved", in: directory).lines, [
            ": LC_SEGMENT in a 64-bit image",
            ": the header's reserved field holds 0xdeadbeef",
            ": a segment with an empty name",
            ": __LINKEDIT is not the last segment",
        ])

        let symtab = try self.command(UInt32(LC_SYMTAB), in: program)
        let twice = try self.verify(self.appending(symtab.data, to: program), "twice", in: directory).lines
        XCTAssertEqual(twice.first, ": 2 LC_SYMTAB commands")
        XCTAssertTrue(twice.contains(": the symbol table and the symbol table overlap in __LINKEDIT"))
        var without = program
        without.store(UInt32(0x7f), at: symtab.data.startIndex)
        XCTAssertEqual(try self.verify(without, "without", in: directory).lines.prefix(2), [": no external symbol table", ": LC_DYSYMTAB without LC_SYMTAB"])

        let text = try self.section("__TEXT", "__text", in: program)
        let both = self.appending(self.unixthread(rip: program.load(UInt64.self, at: text + 32)), to: program)
        XCTAssertEqual(try self.verify(both, "both", in: directory).lines, [": LC_MAIN and LC_UNIXTHREAD both"])
    }

    /**
     Segments and sections as dyld's `validSegments` reads them, and as a disassembler does: a segment's name with
     bytes after its NUL, a section's name that is not ASCII, a section's file offset not where its address lays it,
     which overlaps the next and leaves bytes no section covers, a section's address range outside its segment, which
     leaves the entry in no section, a segment both writable and executable, two segments of one name, a segment's
     file offset off the page, `__TEXT` with room past its file size, a segment flagged Apple-protected, `__DATA_CONST`
     not rw- and more segments than dyld takes.
     */
    func testSegmentsAndSectionsAreNamed() throws {
        let directory = try self.directory("segments")
        let program = try self.program("x86_64", in: directory)
        let text = try XCTUnwrap(XCTUnwrap(MachO(File(data: program))).findSegment("__TEXT")).data.startIndex
        let linkedit = try XCTUnwrap(XCTUnwrap(MachO(File(data: program))).findSegment("__LINKEDIT")).data.startIndex
        let section = try self.section("__TEXT", "__text", in: program)

        var junk = program
        junk.replaceSubrange(text + 15 ..< text + 19, with: "junk".utf8)
        XCTAssertEqual(try self.verify(junk, "junk", in: directory).lines, [": segment __TEXT's name has bytes after its NUL"])
        var cyrillic = program
        cyrillic.replaceSubrange(section ..< section + 16, with: Data("__t\u{0435}xt".utf8) + Data(count: 9))
        // The entry follows the name: in a section that is no longer `__text`.
        XCTAssertEqual(try self.verify(cyrillic, "cyrillic", in: directory).lines, try [
            ": section __TEXT,\"__t\u{0435}xt\"'s name is not printable ASCII",
            ": LC_MAIN's entry \((0x1_0000_0000 + UInt64(self.command(LC_MAIN, in: program).payload(as: entry_point_command.self)!.entryoff)).hex) lies in __TEXT,\"__t\u{0435}xt\", not __text",
        ])

        var desync = program
        let offset = program.load(UInt32.self, at: section + 48)
        desync.store(offset + 16, at: section + 48)
        let desynced = try self.verify(desync, "desync", in: directory).lines
        XCTAssertEqual(desynced.count, 3)
        XCTAssertEqual(desynced.first, ": section __TEXT,__text's file offset \((offset + 16).hex) is not where its address lays it, \(offset.hex)")
        XCTAssertEqual(desynced.dropFirst().first, ": sections __TEXT,__text and __TEXT,__stubs overlap in the file")
        // The 16 bytes of code the section moved off: as many of them are not zero as the compiler left.
        XCTAssertTrue(try XCTUnwrap(desynced.last).hasSuffix(" bytes of __TEXT that no section covers are not zero, the first at \(offset.hex)"))
        var outside = program
        let addr = program.load(UInt64.self, at: section + 32)
        outside.store(addr + 0x100000, at: section + 32)
        let size = program.load(UInt64.self, at: section + 40)
        XCTAssertEqual(try self.verify(outside, "outside", in: directory).lines, [
            ": section __TEXT,__text's address range \((addr + 0x100000).hex)...\((addr + 0x100000 + size).hex) lies outside its segment's 0x100000000...0x100001000",
            ": LC_MAIN's entry \(addr.hex) lies in no section of __TEXT",
        ])

        let end = try XCTUnwrap(XCTUnwrap(MachO(File(data: program))).findSegment("__LINKEDIT")).load(segment_command_64.self)
        let shell = self.appending(self.segment64("__SHELL", vmaddr: end.vmaddr + end.vmsize, vmsize: 0x1000, prot: 7), to: program)
        XCTAssertEqual(try self.verify(shell, "shell", in: directory).lines, [": __LINKEDIT is not the last segment", ": segment __SHELL is writable and executable"])
        let twice = self.appending(self.segment64("__TEXT", vmaddr: end.vmaddr + end.vmsize, vmsize: 0x1000, prot: 1), to: program)
        XCTAssertEqual(try self.verify(twice, "twice", in: directory).lines, [": 2 segments named __TEXT", ": __LINKEDIT is not the last segment"])

        var unaligned = program
        unaligned.store(end.fileoff + 8, at: linkedit + 40)
        unaligned.store(end.filesize - 8, at: linkedit + 48)
        XCTAssertEqual(try self.verify(unaligned, "unaligned", in: directory).lines.first, ": segment __LINKEDIT's file offset \((end.fileoff + 8).hex) is not page aligned")
        var room = program
        room.store(UInt64(0x101000), at: text + 32)
        XCTAssertTrue(try self.verify(room, "room", in: directory).lines.contains(": __TEXT's vmsize 0x101000 exceeds its file size 0x1000 by more than a page"))

        var protected = program
        protected.store(program.load(UInt32.self, at: text + 68) | UInt32(SG_PROTECTED_VERSION_1), at: text + 68)
        XCTAssertEqual(try self.verify(protected, "protected", in: directory).lines, [": segment __TEXT is Apple-protected (SG_PROTECTED_VERSION_1): the kernel decrypts it past its first 0x3000 bytes as it maps it, the image's first 0x3000 bytes left clear"])
        // The three pages left clear are the image's first, not each segment's: a protected segment past them is
        // decrypted whole, one inside them for what lies past them.
        let linkeditOffset = try XCTUnwrap(XCTUnwrap(MachO(File(data: program))).findSegment("__LINKEDIT")).load(segment_command_64.self).fileoff
        var protectedLinkedit = program
        protectedLinkedit.store(program.load(UInt32.self, at: linkedit + 68) | UInt32(SG_PROTECTED_VERSION_1), at: linkedit + 68)
        let clear = linkeditOffset < 0x3000 ? 0x3000 - linkeditOffset : 0
        XCTAssertEqual(try self.verify(protectedLinkedit, "protected-linkedit", in: directory).lines, [": segment __LINKEDIT is Apple-protected (SG_PROTECTED_VERSION_1): the kernel decrypts it \(clear > 0 ? "past its first \(clear.hex) bytes" : "whole") as it maps it, the image's first 0x3000 bytes left clear"])

        // The live dyld's validSemanticsSingleSegment: __DATA_CONST maps rw- in an image dyld manages.
        var constant = program
        let dataConst = try XCTUnwrap(XCTUnwrap(MachO(File(data: program))).findSegment("__DATA_CONST")).data.startIndex
        constant.store(UInt32(VM_PROT_READ), at: dataConst + 60)
        XCTAssertEqual(try self.verify(constant, "constant", in: directory).lines, [": __DATA_CONST's protection is r--, not rw-, which dyld refuses"])
        // dyld's validSemanticsSegments: 255 segments at most.
        let many = try self.crafted("many", in: directory, size: 0x8000, segments: (0 ..< 256).map { ("__S\($0)", 0x1_0000_0000 + UInt64($0) * 0x1000, 0x1000, 0, 0, 1) })
        XCTAssertTrue(self.verify(many.path).lines.contains("\(many.path): 256 segments, more than the 255 dyld takes"))
    }

    /**
     Sections as the live dyld's `Header::validSections` reads them: an address not aligned to the align field, a
     section with content but no file offset, two sections sharing addresses; and as its `validSemanticsSingleSegment`
     reads them in an image built against the SDK of fall 2026 or later, a zero-fill section with a file offset and a
     section with no name.
     */
    func testSectionsAsTheLiveDyldReadsThemAreNamed() throws {
        let directory = try self.directory("sections")
        let program = try self.program("x86_64", in: directory)
        let section = try self.section("__TEXT", "__text", in: program)
        let addr = program.load(UInt64.self, at: section + 32)

        var align = program
        align.store(UInt32(12), at: section + 52)
        XCTAssertEqual(try self.verify(align, "unaligned", in: directory).lines, [": section __TEXT,__text's address \(addr.hex) is not aligned to the 2^12 its align field declares"])

        var zero = program
        zero.store(UInt32(0), at: section + 48)
        XCTAssertTrue(try self.verify(zero, "zero", in: directory).lines.contains(": section __TEXT,__text has no file offset though it is not zero-fill"))

        var shared = program
        let stubs = try self.section("__TEXT", "__stubs", in: program)
        shared.store(addr, at: stubs + 32)
        XCTAssertTrue(try self.verify(shared, "shared", in: directory).lines.contains(": sections __TEXT,__text and __TEXT,__stubs overlap in memory"))

        // Built against this toolchain's SDK, the program is one the live dyld holds to its newest rules: a zero-fill
        // section with a file offset, and a section with no name.
        try XCTSkipUnless(XCTUnwrap(XCTUnwrap(MachO(File(data: program))).version()).sdk >> 16 >= 27, "an SDK before fall 2026")
        var zerofill = program
        zerofill.store(program.load(UInt32.self, at: section + 64) & ~UInt32(SECTION_TYPE) | UInt32(S_ZEROFILL), at: section + 64)
        // The code is then bytes no section covers.
        let zeroed = try self.verify(zerofill, "zerofill", in: directory).lines
        XCTAssertEqual(zeroed.count, 2)
        XCTAssertEqual(zeroed.first, ": section __TEXT,__text is zero-fill with a file offset \(program.load(UInt32.self, at: section + 48).hex), which dyld refuses")
        XCTAssertTrue(try XCTUnwrap(zeroed.last).hasSuffix(" bytes of __TEXT that no section covers are not zero, the first at \(program.load(UInt32.self, at: section + 48).hex)"))
        var nameless = program
        nameless.replaceSubrange(stubs ..< stubs + 16, with: Data(count: 16))
        XCTAssertEqual(try self.verify(nameless, "nameless", in: directory).lines, [": a section of __TEXT with an empty name, which dyld refuses"])
    }

    /**
     The entry point as dyld's `validMain` finds it: `LC_MAIN`'s `entryoff` in a segment that is not executable,
     `LC_UNIXTHREAD`'s pc there, a thread state that is not the architecture's, a first state dyld does not read, the
     full state the kernel refuses under Rosetta, `LC_UNIXTHREAD` alone in an arm64 executable, an entry in no
     section of `__TEXT`, and one in a section of it that holds no code, where a stub section does. The arm64 and
     the `x86_64` full-state executables were run on macOS 27.2 (Apple silicon): dyld halts the first, "main executable
     has no entry point", the kernel kills the second, where the `x86_64` thread state alone runs under Rosetta.
     */
    func testTheEntryPointIsNamed() throws {
        let directory = try self.directory("entry")
        let program = try self.program("x86_64", in: directory)
        let data = try XCTUnwrap(XCTUnwrap(MachO(File(data: program))).findSegment("__DATA_CONST")).load(segment_command_64.self)
        let main = try self.command(LC_MAIN, in: program)

        var inData = program
        inData.store(data.fileoff, at: main.data.startIndex + 8)
        XCTAssertEqual(try self.verify(inData, "main", in: directory).lines, [": LC_MAIN's entry \((0x1_0000_0000 + data.fileoff).hex) lies in __DATA_CONST, which is not executable"])

        var thread = program
        thread.store(UInt32(0x7f), at: main.data.startIndex)
        XCTAssertEqual(try self.verify(self.appending(self.unixthread(rip: data.vmaddr), to: thread), "thread", in: directory).lines, [": LC_UNIXTHREAD's pc \(data.vmaddr.hex) lies in __DATA_CONST, which is not executable"])
        XCTAssertEqual(try self.verify(self.appending(self.unixthread(rip: data.vmaddr, flavor: 1, count: 16), to: thread), "flavor", in: directory).lines, [": LC_UNIXTHREAD's thread state, flavor 1 of 16 words, is not x86_64's"])
        // The full state, the segment registers after the others, is x86_64's too to an Intel Mac's kernel, the pc
        // at the same register, where the kernel on Apple silicon refuses it for the translated process; dyld reads
        // the thread state alone, and finds no entry in a command that begins with the full one.
        let dyld = ": LC_UNIXTHREAD's first thread state, flavor 23 of 50 words, is not the one dyld reads, flavor 4 of 42: the kernel enters by it, dyld finds no entry"
        let rosetta = ": LC_UNIXTHREAD holds a thread state, flavor 23 of 50 words, which the kernel takes on an Intel Mac and refuses under Rosetta"
        XCTAssertEqual(try self.verify(self.appending(self.unixthread(rip: data.vmaddr, flavor: 23, count: 50), to: thread), "full", in: directory).lines, [dyld, rosetta, ": LC_UNIXTHREAD's pc \(data.vmaddr.hex) lies in __DATA_CONST, which is not executable"])
        let code = try program.load(UInt64.self, at: self.section("__TEXT", "__text", in: program) + 32)
        XCTAssertEqual(try self.verify(self.appending(self.unixthread(rip: code, flavor: 23, count: 50), to: thread), "fullcode", in: directory).lines, [dyld, rosetta])
        XCTAssertEqual(try self.verify(self.appending(self.unixthread(states: [(4, 42, data.vmaddr), (23, 50, code)]), to: thread), "fullsecond", in: directory).lines, [": LC_UNIXTHREAD holds 2 thread states: the kernel enters by the last, dyld reads the first", rosetta])
        XCTAssertEqual(try self.verify(self.appending(self.unixthread(rip: code), to: thread), "code", in: directory).lines, [])
        // dyld takes an arm64 executable's entry from LC_MAIN alone.
        var arm = try self.program("arm64", in: directory)
        try arm.store(UInt32(0x7f), at: self.command(LC_MAIN, in: arm).data.startIndex)
        let armCode = try arm.load(UInt64.self, at: self.section("__TEXT", "__text", in: arm) + 32)
        XCTAssertEqual(try self.verify(self.appending(self.unixthread(states: [(6, 68, armCode)], register: 32), to: arm), "arm", in: directory).lines, [": LC_UNIXTHREAD alone enters an arm64 executable, which dyld takes no entry from", ": not signed, which the kernel refuses to run as arm64"])
        // Two thread states: the kernel enters by the last, in __text here, where dyld reads the first; a float state
        // among them, which the kernel's thread_entrypoint does not take, fails the load.
        XCTAssertEqual(try self.verify(self.appending(self.unixthread(states: [(4, 42, data.vmaddr), (4, 42, code)]), to: thread), "states", in: directory).lines, [": LC_UNIXTHREAD holds 2 thread states: the kernel enters by the last, dyld reads the first"])
        XCTAssertEqual(try self.verify(self.appending(self.unixthread(states: [(4, 42, code), (5, 42, 0)]), to: thread), "float", in: directory).lines, [": LC_UNIXTHREAD's thread state, flavor 5 of 42 words, is not x86_64's"])

        var padding = program
        let text = try XCTUnwrap(XCTUnwrap(MachO(File(data: program))).findSegment("__TEXT")).load(segment_command_64.self)
        padding.store(text.filesize - 8, at: main.data.startIndex + 8)
        XCTAssertEqual(try self.verify(padding, "padding", in: directory).lines, [": LC_MAIN's entry \((0x1_0000_0000 + text.filesize - 8).hex) lies in no section of __TEXT"])

        // A stub is an entry too: an app extension enters through the one for `_NSExtensionMain`.
        var stubs = program
        let stub = try self.section("__TEXT", "__stubs", in: program)
        stubs.store(UInt64(program.load(UInt32.self, at: stub + 48)), at: main.data.startIndex + 8)
        XCTAssertEqual(try self.verify(stubs, "stubs", in: directory).lines, [])
        var strings = program
        let cstring = try self.section("__TEXT", "__cstring", in: program)
        strings.store(UInt64(program.load(UInt32.self, at: cstring + 48)), at: main.data.startIndex + 8)
        XCTAssertEqual(try self.verify(strings, "cstring", in: directory).lines, [": LC_MAIN's entry \(program.load(UInt64.self, at: cstring + 32).hex) lies in __TEXT,__cstring, not __text"])
    }

    /**
     What the image links, as dyld's `validEmbeddedPaths` and the kernel read it: no `LC_UUID`, a dylinker other than
     `/usr/lib/dyld`, `LC_DYLD_ENVIRONMENT`, a dylib name not terminated inside its command, `LC_ID_DYLIB` in an
     executable, encryption as the kernel takes it, an executable not position independent, with a flat namespace and
     an executable stack,
     a static one, and one the kernel refuses for want of `MH_PIE` on arm64.
     */
    func testWhatTheImageLinksIsNamed() throws {
        let directory = try self.directory("links")
        let program = try self.program("x86_64", in: directory)

        var uuid = program
        try uuid.store(UInt32(0x7f), at: self.command(UInt32(LC_UUID), in: program).data.startIndex)
        XCTAssertEqual(try self.verify(uuid, "uuid", in: directory).lines, [": no LC_UUID"])

        // No symbol table: what symhash says too, and the LC_DYSYMTAB left without it, both before the table itself.
        var symtab = program
        try symtab.store(UInt32(0x7f), at: self.command(UInt32(LC_SYMTAB), in: program).data.startIndex)
        XCTAssertEqual(try self.verify(symtab, "symtab", in: directory).lines.prefix(2), [": no external symbol table", ": LC_DYSYMTAB without LC_SYMTAB"])

        var dylinker = program
        let command = try self.command(UInt32(LC_LOAD_DYLINKER), in: program)
        let name = try XCTUnwrap(program.range(of: Data("/usr/lib/dyld".utf8), in: command.data.startIndex ..< command.data.endIndex))
        dylinker.replaceSubrange(name, with: "/usr/lib/dylX".utf8)
        XCTAssertEqual(try self.verify(dylinker, "dylinker", in: directory).lines, [": LC_LOAD_DYLINKER names /usr/lib/dylX, not /usr/lib/dyld"])

        var environment = Data()
        let variable = Data("DYLD_INSERT_LIBRARIES=/tmp/evil.dylib".utf8) + Data(count: 7)
        environment.appendUInt32(UInt32(LC_DYLD_ENVIRONMENT)); environment.appendUInt32(UInt32(12 + variable.count)); environment.appendUInt32(12); environment.append(variable)
        XCTAssertEqual(try self.verify(self.appending(environment, to: program), "environment", in: directory).lines, [": LC_DYLD_ENVIRONMENT sets DYLD_INSERT_LIBRARIES=/tmp/evil.dylib"])
        // A right-to-left override in a value is escaped, where a terminal would show the line reordered; a value
        // over 128 bytes is cut at 80 scalars, which one grapheme cluster of combining marks does not get around.
        let reordered = self.string(LC_DYLD_ENVIRONMENT, "DYLD_INSERT_LIBRARIES=/tmp/\u{202E}bilyd.live")
        XCTAssertEqual(try self.verify(self.appending(reordered, to: program), "reordered", in: directory).lines, [": LC_DYLD_ENVIRONMENT sets \"DYLD_INSERT_LIBRARIES=/tmp/\\u{202E}bilyd.live\""])
        let marks = self.string(LC_DYLD_ENVIRONMENT, "X=e" + String(repeating: "\u{301}", count: 100))
        XCTAssertEqual(try self.verify(self.appending(marks, to: program), "marks", in: directory).lines, [": LC_DYLD_ENVIRONMENT sets \"X=e" + String(repeating: "\u{301}", count: 77) + "\"… (203 bytes)"])

        var unterminated = program
        let dylib = try self.command(UInt32(LC_LOAD_DYLIB), in: program)
        let offset = Int(program.load(UInt32.self, at: dylib.data.startIndex + 8))
        unterminated.replaceSubrange(dylib.data.startIndex + offset ..< dylib.data.endIndex, with: Data(repeating: UInt8(ascii: "x"), count: dylib.data.count - offset))
        XCTAssertEqual(try self.verify(unterminated, "unterminated", in: directory).lines, [": LC_LOAD_DYLIB's name is not terminated inside the command", ": links no dylib"])
        // A name starting inside the command's fixed fields, 24 bytes for a dylib command, which dyld refuses.
        var early = program
        early.store(UInt32(16), at: dylib.data.startIndex + 8)
        XCTAssertEqual(try self.verify(early, "early", in: directory).lines, [": LC_LOAD_DYLIB's name starts 0x10 bytes in, inside the command's 0x18 fixed bytes, which dyld refuses", ": links no dylib"])

        var id = Data()
        let install = Data("/tmp/evil.dylib".utf8) + Data(count: 1)
        [UInt32(LC_ID_DYLIB), UInt32(24 + install.count), 24, 0, 0x10000, 0x10000].forEach { id.appendUInt32($0) }
        id.append(install)
        XCTAssertEqual(try self.verify(self.appending(id, to: program), "id", in: directory).lines, [": LC_ID_DYLIB /tmp/evil.dylib in an MH_EXECUTE"])

        // Encryption as the kernel's set_code_unprotect takes it: cryptid 1 and 0x10 name its crypters, any other it
        // refuses; a size of 0 it ignores; the range must lie inside one segment's file bytes, which one straddling
        // __TEXT's end does not.
        func encryption(cryptoff: UInt32, cryptsize: UInt32, cryptid: UInt32, in image: Data = program) -> Data {
            var command = Data()
            [UInt32(LC_ENCRYPTION_INFO_64), 24, cryptoff, cryptsize, cryptid, 0].forEach { command.appendUInt32($0) }
            return self.appending(command, to: image)
        }
        XCTAssertEqual(try self.verify(encryption(cryptoff: 0x1000, cryptsize: 0x1000, cryptid: 1), "encrypted", in: directory).lines, [": encrypted: cryptid 1 over 0x1000 bytes at 0x1000"])
        XCTAssertEqual(try self.verify(encryption(cryptoff: 0x1000, cryptsize: 0x1000, cryptid: 0x10), "null", in: directory).lines, [": encrypted: cryptid 0x10, the kernel's null crypter com.apple.null, over 0x1000 bytes at 0x1000"])
        XCTAssertEqual(try self.verify(encryption(cryptoff: 0x1000, cryptsize: 0x1000, cryptid: 2), "cryptid", in: directory).lines, [": encrypted: cryptid 2 over 0x1000 bytes at 0x1000, which the kernel refuses: 1 names its FairPlay crypter, 0x10 its null one"])
        XCTAssertEqual(try self.verify(encryption(cryptoff: 0x1000, cryptsize: 0, cryptid: 1), "empty", in: directory).lines, [": encrypted: cryptid 1 over 0x0 bytes at 0x1000, which the kernel ignores"])
        let text = try XCTUnwrap(XCTUnwrap(MachO(File(data: program))).findSegment("__TEXT")).load(segment_command_64.self)
        let straddling = UInt32(text.fileoff + text.filesize) - 0x1000
        XCTAssertEqual(try self.verify(encryption(cryptoff: straddling, cryptsize: 0x2000, cryptid: 1), "straddling", in: directory).lines, [": encrypted: cryptid 1 over 0x2000 bytes at \(straddling.hex), which no one segment's file bytes hold: the kernel refuses it"])
        // A segment laid inside another: a range past the inner one's end lies in the outer one's bytes all the same,
        // and one over the outer one's end in no one segment's.
        let nested = try Data(contentsOf: self.crafted("nested", in: directory, size: 0x4000, segments: [("__TEXT", 0x1000, 0x3000, 0, 0x3000, 5), ("__INNER", 0x4000, 0x100, 0x1000, 0x100, 1), ("__DATA", 0x5000, 0x1000, 0x3000, 0x1000, 3)]))
        func nestedEncryption(cryptoff: UInt32, cryptsize: UInt32) throws -> [String] {
            try self.verify(encryption(cryptoff: cryptoff, cryptsize: cryptsize, cryptid: 1, in: nested), "nested-\(cryptoff.hex)", in: directory).lines.filter { $0.contains("encrypted") }
        }
        XCTAssertEqual(try nestedEncryption(cryptoff: 0x1800, cryptsize: 0x800), [": encrypted: cryptid 1 over 0x800 bytes at 0x1800"])
        XCTAssertEqual(try nestedEncryption(cryptoff: 0x2800, cryptsize: 0x1000), [": encrypted: cryptid 1 over 0x1000 bytes at 0x2800, which no one segment's file bytes hold: the kernel refuses it"])

        // Ten of them: the first few are said, the rest counted.
        let many = (0 ..< 10).reduce(program) { encryption(cryptoff: 0x1000, cryptsize: UInt32(0x100 + $1), cryptid: 1, in: $0) }
        XCTAssertEqual(try self.verify(many, "many", in: directory).lines, [": 10 LC_ENCRYPTION_INFO_64 commands"] + (0 ..< 8).map { ": encrypted: cryptid 1 over \((0x100 + $0).hex) bytes at 0x1000" } + [": and 2 more encryption commands naming a crypter"])

        var flags = program
        flags.store(program.load(UInt32.self, at: 24) & ~UInt32(MH_PIE) & ~UInt32(MH_TWOLEVEL) | UInt32(MH_ALLOW_STACK_EXECUTION), at: 24)
        XCTAssertEqual(try self.verify(flags, "flags", in: directory).lines, [": flat namespace: no MH_TWOLEVEL", ": no MH_PIE: loaded without ASLR", ": MH_ALLOW_STACK_EXECUTION: an executable stack"])
        var isStatic = program
        isStatic.store(program.load(UInt32.self, at: 24) & ~UInt32(MH_DYLDLINK), at: 24)
        XCTAssertEqual(try self.verify(isStatic, "static", in: directory).lines, [": no MH_DYLDLINK: a static executable"])

        let arm = try self.program("arm64", in: directory)
        var noPIE = arm
        noPIE.store(arm.load(UInt32.self, at: 24) & ~UInt32(MH_PIE), at: 24)
        XCTAssertEqual(try self.verify(noPIE, "nopie", in: directory).lines, [": no MH_PIE on an arm64 executable, which the kernel refuses", ": not signed, which the kernel refuses to run as arm64"])
    }

    /**
     Bytes nobody references: the header pad, `__TEXT`'s page padding after its last section, bytes between two
     segments' content, bytes of `__LINKEDIT` no table references, and a table that lies outside `__LINKEDIT`, as
     dyld's `isValidLinkeditLayout` wants them inside.
     */
    func testBytesNobodyReferencesAreNamed() throws {
        let directory = try self.directory("padding")
        let program = try self.program("x86_64", in: directory)
        let image = try XCTUnwrap(MachO(File(data: program)))
        let text = try XCTUnwrap(image.findSegment("__TEXT"))
        let textCommand = try text.load(segment_command_64.self)
        let section = try self.section("__TEXT", "__text", in: program)
        let first = Int(program.load(UInt32.self, at: section + 48))
        let commandsEnd = MemoryLayout<mach_header_64>.size + image.sizeofcmds

        var pad = program
        pad.replaceSubrange(commandsEnd + 16 ..< first, with: Data(repeating: 0x41, count: first - commandsEnd - 16))
        XCTAssertEqual(try self.verify(pad, "pad", in: directory).lines, [": \((first - commandsEnd - 16).hex) bytes of __TEXT that no section covers are not zero, the first at \((commandsEnd + 16).hex)"])

        let last = try XCTUnwrap((0 ..< Int(textCommand.nsects)).map { text.data.startIndex + 72 + $0 * 80 }.map { Int(program.load(UInt32.self, at: $0 + 48)) + Int(program.load(UInt64.self, at: $0 + 40)) }.max())
        var tail = program
        tail.replaceSubrange(last ..< Int(textCommand.filesize), with: Data(repeating: 0x42, count: Int(textCommand.filesize) - last))
        XCTAssertEqual(try self.verify(tail, "tail", in: directory).lines, [": \((Int(textCommand.filesize) - last).hex) bytes of __TEXT that no section covers are not zero, the first at \(last.hex)"])

        var between = tail
        between.store(textCommand.filesize - 0x10, at: text.data.startIndex + 48)
        XCTAssertTrue(try self.verify(between, "between", in: directory).lines.contains(": 0x10 bytes between __TEXT and __DATA_CONST are not zero, the first at \((Int(textCommand.filesize) - 0x10).hex)"))

        let linkedit = try XCTUnwrap(image.findSegment("__LINKEDIT"))
        let linkeditCommand = try linkedit.load(segment_command_64.self)
        var slack = program + Data(repeating: 0x43, count: 0x100)
        slack.store(linkeditCommand.filesize + 0x100, at: linkedit.data.startIndex + 48)
        XCTAssertEqual(try self.verify(slack, "slack", in: directory).lines, [": 0x100 bytes of __LINKEDIT that no table references are not zero, the first at \(program.count.hex)"])

        var outside = program
        let starts = try self.command(UInt32(LC_FUNCTION_STARTS), in: program)
        outside.store(UInt32(0x100), at: starts.data.startIndex + 8)
        XCTAssertEqual(try self.verify(outside, "outside", in: directory).lines.first, ": the LC_FUNCTION_STARTS at 0x100 with size \(program.load(UInt32.self, at: starts.data.startIndex + 12).hex) lies outside __LINKEDIT")
    }

    /**
     The signature as Security verifies it and the kernel takes it: a page of code that no longer hashes to its slot,
     a code limit short of the signature, which leaves the rest unsigned, an entitlements blob edited after signing,
     entitlements that opt out of hardening, and a superblob Security cannot read, which is red after the image's
     other lines and counted.
     */
    func testTheSignatureIsVerified() throws {
        let directory = try self.directory("signature")
        let signed = directory / "signed"
        try self.program("x86_64", in: directory).write(to: signed)
        _ = try codesign(["-s", "-", signed.path])
        let program = try Data(contentsOf: signed)
        let image = try XCTUnwrap(MachO(File(data: program)))
        XCTAssertEqual(try self.verify(program, "sound", in: directory).lines, [])
        XCTAssertEqual(try CDHash.hash(fixture: program).map(\.invalid), [false])

        var modified = program
        let section = try self.section("__TEXT", "__text", in: program)
        modified[Int(program.load(UInt32.self, at: section + 48)) + 4] ^= 0xff
        XCTAssertEqual(try self.verify(modified, "modified", in: directory).lines, [": page 0 of the code does not hash to the sha256 code directory"])
        XCTAssertEqual(try CDHash.hash(fixture: modified).map(\.invalid), [true])

        // The code directory: slot 0 of the superblob LC_CODE_SIGNATURE points at.
        let signature = try XCTUnwrap(image.findCodeSignature())
        let directoryOffset = signature.offset + Int(UInt32(bigEndian: program.load(UInt32.self, at: signature.offset + 16)))
        var short = program
        let page = 1 << Int(program[directoryOffset + 39])
        let slots = Int(UInt32(bigEndian: program.load(UInt32.self, at: directoryOffset + 28)))
        short.store(UInt32((slots - 1) * page).bigEndian, at: directoryOffset + 32)
        short.store(UInt32(slots - 1).bigEndian, at: directoryOffset + 28)
        XCTAssertEqual(try self.verify(short, "short", in: directory).lines, [": the sha256 code directory covers \(((slots - 1) * page).hex) bytes, \((signature.offset - (slots - 1) * page).hex) short of the signature at \(signature.offset.hex): the rest is unsigned, and strict validation refuses the signature"])
        XCTAssertEqual(try CDHash.hash(fixture: short).map(\.invalid), [true], "strict validation refuses a code limit short of the signature")

        var refused = program
        refused.store(UInt32(0), at: signature.offset)
        let verified = try self.verify(refused, "refused", in: directory)
        XCTAssertEqual(verified.lines, [": Invalid Mach-O: code signature has invalid magic 0x00000000"])
        XCTAssertEqual(verified.errors, 1)

        let plist = directory / "entitlements.plist"
        try """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict><key>com.apple.security.get-task-allow</key><true/><key>com.apple.security.cs.disable-library-validation</key><true/></dict></plist>
        """.write(to: plist, atomically: true, encoding: .utf8)
        let entitled = directory / "entitled"
        try self.program("x86_64", in: directory).write(to: entitled)
        _ = try codesign(["-s", "-", "--entitlements", plist.path, entitled.path])
        let weakened = try Data(contentsOf: entitled)
        let hardening = ": entitled to opt out of hardening: com.apple.security.cs.disable-library-validation, com.apple.security.get-task-allow"
        XCTAssertEqual(try self.verify(weakened, "weakened", in: directory).lines, [hardening])
        // The XML broken, the DER form, which codesign wrote beside it, still says what the code is entitled to.
        var tampered = weakened
        let flag = try XCTUnwrap(weakened.range(of: Data("<true/>".utf8)))
        tampered.replaceSubrange(flag, with: "<trux/>".utf8)
        XCTAssertEqual(try self.verify(tampered, "tampered", in: directory).lines, [": the entitlements blob does not hash to its slot in the sha256 code directory", ": entitlements that do not parse as a plist", hardening])
        XCTAssertEqual(try CDHash.hash(fixture: tampered).map(\.invalid), [true], "a sealed blob changed")
        XCTAssertEqual(try CDHash.hash(fixture: weakened).map(\.invalid), [false])

        // The DER form changed to disagree with the XML and sealed again: the disagreement is named, and the verdict
        // is the DER form's, which AMFI reads.
        let entitledImage = try XCTUnwrap(MachO(File(data: weakened)))
        let entitledSignature = try XCTUnwrap(entitledImage.findCodeSignature())
        let superblob = try entitledImage.signingData(entitledSignature)
        let der = try XCTUnwrap(MachO.component(7, of: superblob), "codesign wrote no DER entitlements")
        let codeDirectory = try XCTUnwrap(MachO.component(0, of: superblob))
        var disagreeing = weakened
        let key = try XCTUnwrap(der.range(of: Data("com.apple.security.get-task-allow".utf8)))
        disagreeing[entitledSignature.offset + key.upperBound - 1] = UInt8(ascii: "x")
        let hashOffset = Int(UInt32(bigEndian: codeDirectory.load(UInt32.self, at: 16))) // from the slice's start
        let hashSize = Int(codeDirectory[codeDirectory.startIndex + 36])
        XCTAssertGreaterThanOrEqual(UInt32(bigEndian: codeDirectory.load(UInt32.self, at: 24)), 7, "the directory seals the DER slot")
        let slot = entitledSignature.offset + codeDirectory.startIndex + hashOffset - 7 * hashSize
        let resealed = SHA256.hash(data: disagreeing[entitledSignature.offset + der.startIndex ..< entitledSignature.offset + der.endIndex])
        disagreeing.replaceSubrange(slot ..< slot + hashSize, with: Data(resealed).prefix(hashSize))
        XCTAssertEqual(try self.verify(disagreeing, "disagreeing", in: directory).lines, [
            ": the entitlements and their DER form, which AMFI reads, disagree on com.apple.security.get-task-allow, com.apple.security.get-task-allox",
            ": entitled to opt out of hardening: com.apple.security.cs.disable-library-validation",
        ])

        // The kernel takes each entitlements blob under its magic alone, and refuses the signature otherwise: what
        // the blob says is granted to nothing, and verify says nothing of it.
        let xml = try XCTUnwrap(MachO.component(5, of: superblob))
        var mismagic = weakened
        mismagic.store(UInt32(0xfade_7170).bigEndian, at: entitledSignature.offset + xml.startIndex)
        XCTAssertEqual(try self.verify(mismagic, "mismagic", in: directory).lines, [
            ": the entitlements blob does not hash to its slot in the sha256 code directory",
            ": the entitlements blob's magic is 0xfade7170, not 0xfade7171, which the kernel refuses the signature for; codesign warns of an invalid entitlements blob",
        ])
        var misder = weakened
        misder.store(UInt32(0xfade_7173).bigEndian, at: entitledSignature.offset + der.startIndex)
        XCTAssertEqual(try self.verify(misder, "misder", in: directory).lines, [
            ": the DER entitlements blob does not hash to its slot in the sha256 code directory",
            ": the DER entitlements blob's magic is 0xfade7173, not 0xfade7172, which the kernel refuses the signature for",
        ])
    }

    /**
     The DER entitlements are read as AMFI reads them at exec: a program signed with a boolean, a string and a
     dictionary; then the same bytes resealed with the first two pairs swapped, the root dictionary a SET, the string
     a GeneralizedTime, then an OCTET STRING, the nested dictionary a SET, and bytes after the dictionary within the
     wrapper, each of which AMFI refuses the code for and verify names with no verdict; and bytes after the wrapper,
     and the whole as a version 0 dictionary, a bare SET padded to the length, which AMFI takes and verify reads. The
     programs run, or do not, as the oracle; codesign decodes what AMFI takes and refuses the rest but the nested SET,
     its validator run under other options.
     */
    func testDEREntitlementsAreReadAsAMFIReadsThem() throws {
        let directory = try self.directory("der")
        let plist = directory / "entitlements.plist"
        try """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict><key>com.apple.security.cs.allow-jit</key><true/><key>com.apple.security.fashion</key><string>20250101000000Z</string><key>com.apple.security.fashion.dict</key><dict><key>idVendorX</key><integer>1</integer></dict></dict></plist>
        """.write(to: plist, atomically: true, encoding: .utf8)
        let signed = directory / "signed"
#if arch(arm64)
        let arch = "arm64"
#else
        let arch = "x86_64"
#endif
        try self.program(arch, in: directory).write(to: signed)
        _ = try codesign(["-s", "-", "--entitlements", plist.path, signed.path])
        let program = try Data(contentsOf: signed)
        let image = try XCTUnwrap(MachO(File(data: program)))
        let signature = try XCTUnwrap(image.findCodeSignature())
        let superblob = try image.signingData(signature)
        let der = try XCTUnwrap(MachO.component(7, of: superblob))
        let bytes = Data(der.dropFirst(8))
        // 70 { 02 01 01, b0 { 30 { 0c key, value } ... } }, the keys sorted, the dictionary value a b0 of its own
        var reader = DER.Reader(bytes)
        let wrapper = try XCTUnwrap(reader.next())
        XCTAssertEqual(wrapper.tag, 0x70)
        let (version, root) = try (XCTUnwrap(DER.elements(of: wrapper.content)?.first), XCTUnwrap(DER.elements(of: wrapper.content)?.last))
        XCTAssertEqual(root.tag, 0xb0)
        let pairs = try XCTUnwrap(DER.elements(of: root.content))
        XCTAssertEqual(pairs.count, 3)
        let string = try XCTUnwrap(DER.elements(of: pairs[1].content))
        let nested = try XCTUnwrap(DER.elements(of: pairs[2].content))
        XCTAssertEqual([string[1].tag, nested[1].tag], [0x0c, 0xb0])
        let hardening = ": entitled to opt out of hardening: com.apple.security.cs.allow-jit"
        XCTAssertEqual(try self.verify(program, "signed", in: directory).lines, [hardening])
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: signed.path)
        try XCTSkipUnless(execute(signed.path, []), "the signed program does not run here")
        XCTAssertTrue(try execute("/usr/bin/codesign", ["-d", "--entitlements", "-", signed.path]))

        /// `program` with its DER replaced by `replacement`, of the same length, resealed in every code directory.
        func resealed(_ replacement: Data) -> Data {
            XCTAssertEqual(replacement.count, bytes.count)
            var data = program
            let start = signature.offset + der.startIndex + 8
            data.replaceSubrange(start ..< start + replacement.count, with: replacement)
            let blob = data[signature.offset + der.startIndex ..< signature.offset + der.endIndex]
            for slot: UInt32 in [0, 0x1000] {
                guard let codeDirectory = MachO.component(slot, of: superblob) else {
                    continue
                }
                let hashOffset = Int(UInt32(bigEndian: codeDirectory.load(UInt32.self, at: 16)))
                let hashSize = Int(codeDirectory[codeDirectory.startIndex + 36])
                let digest = switch codeDirectory[codeDirectory.startIndex + 37] {
                case 1: Data(Insecure.SHA1.hash(data: blob))
                case 4: Data(SHA384.hash(data: blob))
                default: Data(SHA256.hash(data: blob))
                }
                let at = signature.offset + codeDirectory.startIndex + hashOffset - 7 * hashSize
                data.replaceSubrange(at ..< at + hashSize, with: digest.prefix(hashSize))
            }
            return data
        }
        /// What verify says of `data` as `name`, whether it runs, and whether codesign decodes its entitlements.
        func verified(_ data: Data, _ name: String) throws -> (lines: [String], runs: Bool, decodes: Bool) {
            let lines = try self.verify(data, name, in: directory).lines
            let path = (directory / name).path
            try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: path)
            return try (lines, execute(path, []), execute("/usr/bin/codesign", ["-d", "--entitlements", "-", path]))
        }
        func wrapped(_ root: Data, _ trailing: Data = Data()) -> Data {
            DER.encode(0x70, version.raw + root + trailing)
        }
        func refused(_ what: String) -> String {
            ": DER entitlements holding \(what), which AMFI refuses the code for"
        }
        /// `pairs` with the second one's value `value`.
        func valued(_ value: Data) -> Data {
            pairs[0].raw + DER.encode(0x30, string[0].raw + value) + pairs[2].raw
        }
        /// `pairs` with the dictionary tagged `tag`.
        func dictionary(_ tag: UInt8) -> Data {
            pairs[0].raw + pairs[1].raw + DER.encode(0x30, nested[0].raw + DER.encode(tag, nested[1].content))
        }

        let swapped = try verified(resealed(wrapped(DER.encode(0xb0, pairs[1].raw + pairs[0].raw + pairs[2].raw))), "swapped")
        XCTAssertEqual(swapped.lines, [refused("keys out of order, com.apple.security.cs.allow-jit after com.apple.security.fashion")])
        XCTAssertEqual([swapped.runs, swapped.decodes], [false, false])
        // A key is the blob's own word: one with a newline in it is quoted, and makes no line of its own.
        /// A pair of `key` and true.
        func pair(_ key: String) -> Data {
            DER.encode(0x30, DER.encode(0x0c, Data(key.utf8)) + DER.encode(0x01, Data([0xff])))
        }
        // A third pair is made as long as it takes for the blob to keep its length, which the reseal wants.
        let key = "b\n/bin/ls: nothing to see"
        let filled = try XCTUnwrap((0 ..< 120).lazy.map { wrapped(DER.encode(0xb0, pair("z") + pair(key) + pair(String(repeating: "!", count: $0)))) }.first { $0.count == bytes.count })
        let forged = try verified(resealed(filled), "forged")
        XCTAssertEqual(forged.lines, [refused("keys out of order, \"b\\n/bin/ls: nothing to see\" after z")])

        let set = try verified(resealed(wrapped(DER.encode(0x31, root.content))), "set")
        XCTAssertEqual(set.lines, [refused("no dictionary after the version")])
        XCTAssertEqual([set.runs, set.decodes], [false, false])

        let dated = try verified(resealed(wrapped(DER.encode(0xb0, valued(DER.encode(0x18, string[1].content))))), "dated")
        XCTAssertEqual(dated.lines, [refused("a GeneralizedTime value")])
        XCTAssertEqual([dated.runs, dated.decodes], [false, false])

        let data = try verified(resealed(wrapped(DER.encode(0xb0, valued(DER.encode(0x04, string[1].content))))), "data")
        XCTAssertEqual(data.lines, [refused("an OCTET STRING value")])
        XCTAssertEqual([data.runs, data.decodes], [false, false])

        let nestedSet = try verified(resealed(wrapped(DER.encode(0xb0, dictionary(0x31)))), "nestedset")
        XCTAssertEqual(nestedSet.lines, [refused("a dictionary tagged 0x31 under a root tagged 0xb0")])
        XCTAssertFalse(nestedSet.runs)

        // The dictionary pair dropped, its bytes zeroed after the root, then after the wrapper: the XML then names
        // what the DER does not.
        let short = DER.encode(0xb0, pairs[0].raw + pairs[1].raw)
        let padding = try XCTUnwrap((0 ..< bytes.count).first { wrapped(short, Data(count: $0)).count == bytes.count })
        let inner = try verified(resealed(wrapped(short, Data(count: padding))), "inner")
        XCTAssertEqual(inner.lines, [refused("bytes after the dictionary within the wrapper")])
        XCTAssertEqual([inner.runs, inner.decodes], [false, false])
        let outer = try verified(resealed(wrapped(short) + Data(count: bytes.count - wrapped(short).count)), "outer")
        XCTAssertEqual(outer.lines, [": the entitlements and their DER form, which AMFI reads, disagree on com.apple.security.fashion.dict", hardening])
        XCTAssertEqual([outer.runs, outer.decodes], [true, true])

        let bare = DER.encode(0x31, dictionary(0x31))
        let versionZero = try verified(resealed(bare + Data(count: bytes.count - bare.count)), "version0")
        XCTAssertEqual(versionZero.lines, [hardening])
        XCTAssertEqual([versionZero.runs, versionZero.decodes], [true, true])
    }

    /**
     Who signed, as `Signer` has it: a certificate outside Apple's chains, which codesign and the kernel take and
     Gatekeeper refuses; a code directory altered after signing; a CMS blob behind a directory flagged ad hoc; and
     entitlements AMFI reserves, under an ad-hoc signature. The certificate and the CMS blob come from the system's
     openssl, over the code directory `codesign -s -` wrote with its ad-hoc flag cleared, in the room `--signature-size`
     left for them.
     */
    func testTheSignerIsNamed() throws {
        let directory = try self.directory("signer")
        let signed = directory / "signed"
        try self.program("x86_64", in: directory).write(to: signed)
        _ = try codesign(["-s", "-", "--signature-size", "12000", signed.path])
        let program = try Data(contentsOf: signed)
        let image = try XCTUnwrap(MachO(File(data: program)))
        let signature = try XCTUnwrap(image.findCodeSignature())
        let superblob = try image.signingData(signature)
        let adhoc = try Data(XCTUnwrap(MachO.component(0, of: superblob))) // reindexed from 0
        let requirements = try Data(XCTUnwrap(MachO.component(2, of: superblob)))
        var directoryBlob = adhoc
        directoryBlob.store((UInt32(bigEndian: adhoc.load(UInt32.self, at: 12)) & ~UInt32(2)).bigEndian, at: 12) // CS_ADHOC out
        let (configuration, key, certificate, content, cms) = (directory / "certificate.cnf", directory / "key.pem", directory / "certificate.pem", directory / "directory.bin", directory / "cms.der")
        try directoryBlob.write(to: content)
        try "[req]\ndistinguished_name = dn\nx509_extensions = ext\nprompt = no\n[dn]\nCN = Fashion Self\nOU = SELFTEAM00\n[ext]\nextendedKeyUsage = codeSigning\nkeyUsage = digitalSignature\nbasicConstraints = CA:FALSE\n".write(to: configuration, atomically: true, encoding: .utf8)
        try XCTSkipUnless(execute("/usr/bin/openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key.path, "-out", certificate.path, "-config", configuration.path, "-days", "30"]), "cannot make a certificate")
        try XCTSkipUnless(execute("/usr/bin/openssl", ["cms", "-sign", "-binary", "-in", content.path, "-signer", certificate.path, "-inkey", key.path, "-outform", "DER", "-out", cms.path]), "cannot sign")
        let signatureBlob = try Data(contentsOf: cms)

        /// The program with a superblob holding `directory` in slot 0, the requirements it seals, and `cms` wrapped.
        func embedded(_ directory: Data, _ cms: Data) -> Data {
            var wrapped = Data()
            [0xfade_0b01, UInt32(8 + cms.count)].forEach { wrapped.appendUInt32BE($0) }
            wrapped += cms
            var blob = Data()
            let (first, second) = (36 + directory.count, 36 + directory.count + requirements.count)
            [0xfade_0cc0, UInt32(second + wrapped.count), 3, 0, 36, 2, UInt32(first), 0x10000, UInt32(second)].forEach { blob.appendUInt32BE($0) }
            blob += directory + requirements + wrapped
            XCTAssertLessThanOrEqual(blob.count, signature.size)
            var signed = program
            signed.replaceSubrange(signature.offset ..< signature.offset + blob.count, with: blob)
            return signed
        }
        XCTAssertEqual(try self.verify(embedded(directoryBlob, signatureBlob), "self-signed", in: directory).lines, [": signed outside Apple's chains by Fashion Self, which Gatekeeper refuses"])
        // Hash mode's verdict is Security's static one: the signature verifies, whoever signed, or does not.
        XCTAssertEqual(try CDHash.hash(fixture: embedded(directoryBlob, signatureBlob)).map(\.invalid), [false])
        XCTAssertEqual(try CDHash.hash(fixture: embedded(directoryBlob, Data())).map(\.invalid), [true], "no CMS blob behind a directory not flagged ad hoc")

        var altered = directoryBlob
        altered[Int(UInt32(bigEndian: adhoc.load(UInt32.self, at: 20)))] ^= 0x20 // the identifier's first byte
        XCTAssertEqual(try self.verify(embedded(altered, signatureBlob), "altered", in: directory).lines, [": the CMS signature does not verify over the sha256 code directory"])
        XCTAssertEqual(try CDHash.hash(fixture: embedded(altered, signatureBlob)).map(\.invalid), [true])

        XCTAssertEqual(try self.verify(embedded(adhoc, signatureBlob), "ad hoc", in: directory).lines, [": a CMS signature behind a code directory flagged ad hoc, which Security ignores"])
        XCTAssertEqual(try CDHash.hash(fixture: embedded(adhoc, signatureBlob)).map(\.invalid), [false])
        // Security takes the CMS blob under its wrapper's magic alone.
        var mismagic = embedded(directoryBlob, signatureBlob)
        let wrapper = try XCTUnwrap(mismagic.range(of: Data([0xfa, 0xde, 0x0b, 0x01])))
        mismagic.store(UInt32(0xfade_0b02).bigEndian, at: wrapper.lowerBound)
        XCTAssertEqual(try self.verify(mismagic, "mismagic", in: directory).lines, [": the CMS blob's magic is 0xfade0b02, not 0xfade0b01, which Security refuses the signature for"])
        XCTAssertEqual(try CDHash.hash(fixture: mismagic).map(\.invalid), [true])
        // Security takes exactly one signer: the same signer twice is an invalid signature to it, where the one is
        // a signature codesign verifies. The rule is macOS 27.2's. Before it, verifySignature asked
        // CMSDecoderCopySignerStatus for signer 0 alone, and codesign verified the pair.
        let doubled = try Self.withSigners(signatureBlob, times: 2)
        XCTAssertEqual(try self.verify(embedded(directoryBlob, doubled), "doubled", in: directory).lines, [": a CMS signature with 2 signers, where Security requires exactly one, an invalid signature to it"])
        if #available(macOS 27.2, *) {
            XCTAssertFalse(try execute("/usr/bin/codesign", ["--verify", (directory / "doubled").path]))
        }
        XCTAssertEqual(try CDHash.hash(fixture: embedded(directoryBlob, doubled)).map(\.invalid), [true])
        XCTAssertTrue(try execute("/usr/bin/codesign", ["--verify", (directory / "self-signed").path]))

        let plist = directory / "entitlements.plist"
        try """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict><key>com.apple.private.fashion</key><true/><key>aps-environment</key><string>production</string><key>com.apple.application-identifier</key><string>SELFTEAM00.fashion</string><key>com.apple.security.application-groups</key><array><string>SELFTEAM00.fashion</string></array></dict></plist>
        """.write(to: plist, atomically: true, encoding: .utf8)
        let entitled = directory / "entitled"
        try self.program("x86_64", in: directory).write(to: entitled)
        _ = try codesign(["-s", "-", "--entitlements", plist.path, entitled.path])
        XCTAssertEqual(try self.verify(Data(contentsOf: entitled), "reserved", in: directory).lines, [": entitled to aps-environment, com.apple.private.fashion, which AMFI reserves to Apple-signed code"])

        // A signer that wrote no hash-agility attributes binds nothing: a SHA-256 directory beside the signed SHA-1
        // one passes Security, as the CMS verifies over the SHA-1 directory.
        let twice = directory / "twice"
        try self.program("x86_64", in: directory).write(to: twice)
        _ = try codesign(["-s", "-", "--signature-size", "12000", "--digest-algorithm=sha1,sha256", twice.path])
        let twiceData = try Data(contentsOf: twice)
        let twiceImage = try XCTUnwrap(MachO(File(data: twiceData)))
        let twiceSignature = try XCTUnwrap(twiceImage.findCodeSignature())
        let twiceSuperblob = try twiceImage.signingData(twiceSignature)
        var directories = try [0, 0x1000].map { try Data(XCTUnwrap(MachO.component($0, of: twiceSuperblob))) }
        for index in directories.indices {
            directories[index].store((UInt32(bigEndian: directories[index].load(UInt32.self, at: 12)) & ~UInt32(2)).bigEndian, at: 12)
        }
        let twiceRequirements = try Data(XCTUnwrap(MachO.component(2, of: twiceSuperblob)))
        try directories[0].write(to: content)
        let cmsTwice = directory / "cms-twice.der"
        try XCTSkipUnless(execute("/usr/bin/openssl", ["cms", "-sign", "-binary", "-in", content.path, "-signer", certificate.path, "-inkey", key.path, "-outform", "DER", "-out", cmsTwice.path]), "cannot sign")
        var wrapped = Data()
        let cmsBytes = try Data(contentsOf: cmsTwice)
        [0xfade_0b01, UInt32(8 + cmsBytes.count)].forEach { wrapped.appendUInt32BE($0) }
        wrapped += cmsBytes
        let blobs: [(slot: UInt32, blob: Data)] = [(0, directories[0]), (2, twiceRequirements), (0x1000, directories[1]), (0x10000, wrapped)]
        var superblob2 = Data()
        var offset = 12 + 8 * blobs.count
        [0xfade_0cc0, UInt32(offset + blobs.reduce(0) { $0 + $1.blob.count }), UInt32(blobs.count)].forEach { superblob2.appendUInt32BE($0) }
        for entry in blobs {
            superblob2.appendUInt32BE(entry.slot); superblob2.appendUInt32BE(UInt32(offset))
            offset += entry.blob.count
        }
        blobs.forEach { superblob2 += $0.blob }
        XCTAssertLessThanOrEqual(superblob2.count, twiceSignature.size)
        var unbound = twiceData
        unbound.replaceSubrange(twiceSignature.offset ..< twiceSignature.offset + superblob2.count, with: superblob2)
        try unbound.write(to: directory / "unbound")
        XCTAssertTrue(try execute("/usr/bin/codesign", ["--verify", (directory / "unbound").path]), "a signature codesign takes")
        XCTAssertEqual(try self.verify(unbound, "unbound", in: directory).lines, [": the sha256 code directory, which Security and the kernel read the signature by, is not the one the CMS signs, the sha1 code directory at slot 0, and the signer binds none to it: anyone may have added it", ": signed outside Apple's chains by Fashion Self, which Gatekeeper refuses"])
    }

    /**
     `hash --verify` and `thinr --verify` leave what `verify` would say of a file in the unified log alone: a finding
     prints no line and counts no error, so a file `verify` has a line for exits as it would without the flag.
     */
    func testVerifyLogsAloneUnderHashAndThinr() throws {
        let directory = try self.directory("logging")
        var program = try self.program("x86_64", in: directory)
        program.store(UInt32(0xdead_beef), at: 28) // the 64-bit header's reserved field
        let odd = directory / "odd"
        try program.write(to: odd)
        XCTAssertEqual(self.verify(odd.path).lines.count, 1)
        XCTAssertEqual(try Hasher.parse([odd.path, "--verify", "--quiet"]).scan(), 0)
        XCTAssertEqual(try Thinner.parse([odd.path, "--verify"]).scan(), 0)
        // --quiet names the file once for its findings, as thinr names it for its artifacts.
        XCTAssertEqual(Verify.lines(for: odd.path, quiet: true, reporter: Reporter(console: Console())).map(\.text), [odd.path])
        XCTAssertEqual(try Verify.parse(["-q", odd.path]).scan(), 0)
    }

    /**
     The scan opens each file once and hands it to the command's work, `ScanOptions.open(_:reporter:work:)`, which
     `hash --verify` and `thinr --verify` verify through the same descriptor after their lines; a path that cannot be
     opened is reported in its place, counted, and never handed on.
     */
    func testScanHandsTheFileItOpenedToTheWork() throws {
        let directory = try self.directory("opened")
        let program = try self.program("x86_64", in: directory)
        let file = directory / "program"
        try program.write(to: file)
        let reporter = Reporter(console: Console())
        let digester = try Digester(Hasher.parse([file.path, "--quiet"]))
        let thinner = try ArtifactWriter(Thinner.parse([file.path]))
        var opened: [File] = []
        XCTAssertEqual(ScanOptions.open(file.path, reporter: reporter) { opened.append($0); return digester.lines(for: $0, reporter: reporter) }.count, 1)
        XCTAssertTrue(ScanOptions.open(file.path, reporter: reporter) { opened.append($0); return thinner.lines(for: $0, reporter: reporter) }.filter(\.diagnostic).isEmpty)
        XCTAssertEqual(opened.map(\.path), [file.path, file.path])
        XCTAssertEqual(opened.map(\.size), [program.count, program.count])
        XCTAssertEqual(reporter.errorCount, 0)
        // What the modes log of the file they were handed, after their lines: a notice each, nothing printed and
        // nothing counted.
        opened.forEach(Verify.log)
        XCTAssertEqual(reporter.errorCount, 0)

        let missing = directory / "missing"
        XCTAssertEqual(ScanOptions.open(missing.path, reporter: reporter) { opened.append($0); return [] }.map(\.text), ["fashion: \(missing.path): No such file or directory"])
        XCTAssertEqual(opened.count, 2, "a path that cannot be opened is reported, not handed on")
        XCTAssertEqual(reporter.errorCount, 1)
    }

    /**
     A universal file as the kernel, dyld and Security read it: an arm64 slice hidden past the table's count, which
     is a slice to `Universal` as to Security, past a count of none too, or with a subtype dyld does not take, or
     with a range that does not hold, two slices of one architecture, a slice whose table entry names another
     architecture than its header, padding that is not zero, a 64-bit universal file, a slice that is itself universal,
     a slice off its page, and one off the alignment its entry declares.
     */
    func testAUniversalFileIsNamed() throws {
        let directory = try self.directory("universal")
        let x86 = try self.program("x86_64", in: directory)
        let arm = try self.program("arm64", in: directory)
        let unsigned = " (arm64): not signed, which the kernel refuses to run as arm64"
        let X86 = (cpuType: CPU_TYPE_X86_64, cpuSubtype: CPU_SUBTYPE_X86_64_ALL, data: x86, align: 12)
        let ARM = (cpuType: CPU_TYPE_ARM64, cpuSubtype: CPU_SUBTYPE_ARM64_ALL, data: arm, align: 14)

        XCTAssertEqual(try self.verify(makeUniversal([X86, ARM]), "fat", in: directory).lines, [unsigned])
        let hidden = makeUniversal([X86, ARM], hideLast: true)
        XCTAssertEqual(try self.verify(hidden, "hidden", in: directory).lines, [": slice arm64 is hidden past the table's 1 entry: dyld and codesign find it, the kernel does not", unsigned])
        guard case let .fat(archs) = try Universal.open(data: hidden) else {
            return XCTFail("a universal file")
        }
        XCTAssertEqual(archs.map(\.name), ["x86_64", "arm64"])
        XCTAssertEqual(archs.map(\.hidden), [false, true])
        XCTAssertEqual(try Universal.fileEnd(data: hidden), hidden.count)
        // A table that counts no entry is a universal file by the arm64 slice hidden past it, to codesign and dyld.
        let alone = makeUniversal([ARM], hideLast: true)
        XCTAssertEqual(try self.verify(alone, "alone", in: directory).lines, [": slice arm64 is hidden past the table's 0 entries: dyld and codesign find it, the kernel does not", unsigned])
        guard case let .fat(only) = try Universal.open(data: alone) else {
            return XCTFail("a universal file")
        }
        XCTAssertEqual(only.map(\.hidden), [true])
        // Hidden with a subtype, which dyld's exact compare of arm64 leaves to codesign alone.
        XCTAssertEqual(try self.verify(makeUniversal([X86, (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E, arm, 14)], hideLast: true), "hiddene", in: directory).lines, [": slice arm64e is hidden past the table's 1 entry: codesign finds it, dyld and the kernel do not", ": slice arm64e by the table is arm64 by its header", " (arm64e): not signed, which the kernel refuses to run as arm64"])
        // A hidden entry that does not lie in the file is no slice to hash mode, its entry and its bytes what the
        // table leaves around the counted slice, and to verify the refusal dyld makes of the file.
        var unheld = hidden
        unheld.store(UInt32(0xffff_ffff).bigEndian, at: 8 + 20 + 12)
        let refused = try self.verify(unheld, "unheld", in: directory)
        XCTAssertEqual(refused.lines, [
            ": 0x8 bytes of padding before slice x86_64 are not zero, the first at 0x1c",
            ": \((unheld.count - 0x1000 - x86.count).hex) bytes past the last slice, x86_64's end at \((0x1000 + x86.count).hex)",
            " (arm64 hidden past the table): Invalid Mach-O: fat architecture range at offset 0x4000 with size 0xffffffff is outside the \(unheld.count.hex)-byte file",
        ])
        XCTAssertEqual(refused.errors, 1)
        guard case let .fat(counted) = try Universal.open(data: unheld) else {
            return XCTFail("a universal file")
        }
        XCTAssertEqual(counted.map(\.name), ["x86_64"])

        XCTAssertEqual(try self.verify(makeUniversal([X86, X86]), "twice", in: directory).lines, [": 2 slices of x86_64, which the kernel refuses"])
        XCTAssertEqual(try self.verify(makeUniversal([X86, (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E, arm, 14)]), "mismatch", in: directory).lines, [": slice arm64e by the table is arm64 by its header", " (arm64e): not signed, which the kernel refuses to run as arm64"])
        XCTAssertEqual(try self.verify(makeUniversal([X86, ARM], gap: 0x44), "gap", in: directory).lines, [
            ": 0xfd0 bytes of padding before slice x86_64 are not zero, the first at 0x30",
            ": \((0x4000 - 0x1000 - x86.count).hex) bytes of padding before slice arm64 are not zero, the first at \((0x1000 + x86.count).hex)",
            unsigned,
        ])
        XCTAssertEqual(try self.verify(makeUniversal([X86, ARM], magic: FAT_MAGIC_64), "fat64", in: directory).lines, [": a 64-bit universal file, which the kernel does not run and codesign signs as a generic file", unsigned])
        XCTAssertEqual(try self.verify(makeUniversal([(CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, makeUniversal([ARM]), 14)]), "nested", in: directory).lines, [": slice arm64 is itself a universal file"])
        // The x86_64 slice padded to end past 0x4000, so the arm64 slice's 4 KiB alignment lands it at 0x5000.
        try XCTSkipUnless(x86.count < 0x3800, "a program larger than the padding")
        XCTAssertEqual(try self.verify(makeUniversal([(CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL, x86 + Data(count: 0x3800 - x86.count), 12), (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, arm, 12)]), "page", in: directory).lines, [
            " (x86_64): \((0x3800 - x86.count).hex) bytes appended past the image's end at \(x86.count.hex)",
            ": slice arm64 at 0x5000 is not page aligned",
            unsigned,
        ])
        var declared = makeUniversal([X86])
        declared.store(UInt32(14).bigEndian, at: 8 + 16)
        XCTAssertEqual(try self.verify(declared, "declared", in: directory).lines, [": slice x86_64 at 0x1000 is not aligned to the 2^14 its entry declares"])
        // armv7k is mapped on 16 KiB pages too: the x86_64 program's header relabeled, laid on a 4 KiB page.
        var v7k = x86
        v7k.store(CPU_TYPE_ARM, at: 4)
        v7k.store(CPU_SUBTYPE_ARM_V7K, at: 8)
        XCTAssertEqual(try self.verify(makeUniversal([(CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V7K, v7k, 12)]), "v7k", in: directory).lines, [": slice armv7k at 0x1000 is not page aligned"])
        XCTAssertEqual(try self.verify(makeUniversal([(CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V7K, v7k, 14)]), "v7k16", in: directory).lines, [])
    }

    /**
     A universal file of more entries than `Universal.open` reads, which hash mode takes for no Mach-O, is named with
     its count when its entries hold, as a crafted one's do and a Java class's, 0xCAFEBABE too, do not.
     */
    func testAUniversalFileOfMoreSlicesThanAreReadIsNamed() throws {
        let directory = try self.directory("oversized")
        let x86 = try (cpuType: CPU_TYPE_X86_64, cpuSubtype: CPU_SUBTYPE_X86_64_ALL, data: self.program("x86_64", in: directory), align: 12)
        XCTAssertEqual(try self.verify(makeUniversal(Array(repeating: x86, count: 16)), "sixteen", in: directory).lines, [": 16 slices of x86_64, which the kernel refuses"])
        XCTAssertEqual(try self.verify(makeUniversal(Array(repeating: x86, count: 17)), "seventeen", in: directory).lines, [": a universal file of 17 slices, more than the 16 read here: the kernel reads as many as fit in its page, 204 or 818, and runs one; the slices are neither hashed nor verified"])
        XCTAssertEqual(try self.verify(Data([0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 0x34]) + Data(count: 1024), "class", in: directory).lines, [])
    }

    /**
     A section laid past 2^64, where its address sits near the top of a segment that maps most of the address space,
     is named rather than tripped over.
     */
    func testASectionLaidPastTheAddressSpaceIsNamed() throws {
        let directory = try self.directory("past")
        var data = self.segment64("__DATA", vmaddr: 0, vmsize: UInt64.max, fileoff: 0x1000, filesize: 0x1000, prot: 3)
        data.store(UInt32(72 + 80), at: 4)
        data.store(UInt32(1), at: 64) // nsects
        data.append(Data("__data".utf8)); data.append(Data(count: 10)); data.append(Data("__DATA".utf8)); data.append(Data(count: 10))
        data.appendUInt64(0xffff_ffff_ffff_f000); data.appendUInt64(0x10) // addr, size
        [UInt32(0x1000), 0, 0, 0, 0, 0, 0, 0].forEach { data.appendUInt32($0) } // offset, align, reloff, nreloc, flags, reserved
        let file = try self.crafted("past", in: directory, size: 0x2000, segments: [("__TEXT", 0x1000, 0x1000, 0, 0x1000, 5)], commands: [data])
        self.assertVerify(file.path, [
            "\(file.path): no external symbol table",
            "\(file.path): segment __DATA's address 0x0 is out of order after __TEXT's 0x1000",
            "\(file.path): segments __DATA and __TEXT overlap in memory",
            "\(file.path): __TEXT has no sections",
            "\(file.path): section __DATA,__data's file offset 0x1000 is not where its address lays it, past 2^64",
            "\(file.path): no LC_MAIN nor LC_UNIXTHREAD for an executable",
            "\(file.path): no LC_UUID",
            "\(file.path): no MH_DYLDLINK: a static executable",
            "\(file.path): no LC_BUILD_VERSION nor LC_VERSION_MIN_* dates it",
            "\(file.path): neither a __LINKEDIT segment nor an LC_SYMTAB ends the image, which codesign's strict validation refuses",
        ])
    }

    /**
     Segments are checked for overlaps in one pass over them, however many a crafted table holds: twenty thousand are
     verified in no time, where every pair would be their count squared.
     */
    func testATableOfThousandsOfSegmentsIsVerifiedInOnePass() throws {
        let directory = try self.directory("thousands")
        let count = 20000
        let segments = (0 ..< count).map { ("", UInt64(0x1_0000_0000 + $0), UInt64(1), UInt64($0), UInt64(1), UInt32(0)) }
        let file = try self.crafted("thousands", in: directory, size: 32 + 72 * count, segments: segments)
        var data = try Data(contentsOf: file)
        data.store(UInt32(MH_PRELOAD), at: 12) // no loader maps it: its segments are held to no page
        try data.write(to: file)
        let start = ContinuousClock.now
        self.assertVerify(file.path, ["\(file.path): no external symbol table", "\(file.path): \(count) segments with an empty name", "\(file.path): no LC_BUILD_VERSION nor LC_VERSION_MIN_* dates it", "\(file.path): neither a __LINKEDIT segment nor an LC_SYMTAB ends the image, which codesign's strict validation refuses"])
        XCTAssertLessThan(ContinuousClock.now - start, .seconds(10), "every pair of segments compared")
    }

    /**
     Segments laid over the same bytes, thousands of them with a section each as a crafted table lays them, have the
     bytes no section covers read once, not once per segment: a 4 MiB file under 4000 such segments would be 16 GiB
     of reads. Gaps laid inside one another are cut into pieces, each read once, and a gap is counted from sums
     over the pieces, with no walk per gap. Each rule names the first few segments it finds and counts the rest,
     so that thousands of segments make dozens of lines. And a segment laid inside another names none of the outer
     one's content as lying between segments.
     */
    func testPaddingIsReadOnceUnderSegmentsOverTheSameBytes() throws {
        let directory = try self.directory("padding-once")
        let count = 4000
        let size = 4 << 20
        var data = Data()
        [MH_MAGIC_64, UInt32(CPU_TYPE_X86_64), UInt32(CPU_SUBTYPE_X86_64_ALL), UInt32(MH_PRELOAD), UInt32(count), UInt32(count * 152), 0, 0].forEach { data.appendUInt32($0) }
        let headerEnd = 32 + count * 152
        for index in 0 ..< count {
            data.appendUInt32(UInt32(LC_SEGMENT_64)); data.appendUInt32(152)
            try data.append(XCTUnwrap("__S\(index)".data(using: .utf8)) + Data(count: 16 - "__S\(index)".utf8.count))
            [UInt64(0x1_0000_0000), UInt64(size), 0, UInt64(size)].forEach { data.appendUInt64($0) } // vmaddr, vmsize, fileoff, filesize
            [UInt32(5), 5, 1, 0].forEach { data.appendUInt32($0) } // maxprot, initprot, nsects, flags
            try data.append(XCTUnwrap("__text".data(using: .utf8)) + Data(count: 10) + XCTUnwrap("__S\(index)".data(using: .utf8)) + Data(count: 16 - "__S\(index)".utf8.count))
            [UInt64(0x1_0000_0000) + UInt64(headerEnd), 1].forEach { data.appendUInt64($0) } // addr, size
            [UInt32(headerEnd), 0, 0, 0, 0x8000_0400, 0, 0, 0].forEach { data.appendUInt32($0) } // offset, align, reloff, nreloc, flags, reserved
        }
        data.append(Data(repeating: 0x41, count: size - data.count))
        let file = directory / "same"
        try data.write(to: file)
        let start = ContinuousClock.now
        let lines = self.verify(file.path).lines
        XCTAssertLessThan(ContinuousClock.now - start, .seconds(10), "every segment's padding read on its own")
        XCTAssertTrue(lines.contains("\(file.path): \((size - headerEnd - 1).hex) bytes of __S0 that no section covers are not zero, the first at \((headerEnd + 1).hex)"))
        // The first few segments are named, the rest counted, by each rule that finds them all.
        XCTAssertTrue(lines.contains("\(file.path): and \(count - 8) more segments with bytes no section covers that are not zero"))
        XCTAssertEqual(lines.count(where: { $0 == "\(file.path): and \(count - 9) more such pairs" }), 2, "overlapping in the file, and in memory")
        XCTAssertLessThan(lines.count, 100)

        // Gaps laid inside one another: 9 segments over the same bytes, each with one section from 64 bytes further
        // to the end, so each one's gap runs from the headers to its section, over every gap before it; a byte
        // that is not zero where each section starts lies in the gap of every segment after it, and is counted
        // there, the first of them the first.
        let staggered = 9
        let top = 32 + staggered * 152
        var stairs = Data()
        [MH_MAGIC_64, UInt32(CPU_TYPE_X86_64), UInt32(CPU_SUBTYPE_X86_64_ALL), UInt32(MH_PRELOAD), UInt32(staggered), UInt32(staggered * 152), 0, 0].forEach { stairs.appendUInt32($0) }
        for index in 0 ..< staggered {
            let start = top + 64 * (index + 1)
            stairs.appendUInt32(UInt32(LC_SEGMENT_64)); stairs.appendUInt32(152)
            try stairs.append(XCTUnwrap("__G\(index)".data(using: .utf8)) + Data(count: 16 - "__G\(index)".utf8.count))
            [UInt64(0x1_0000_0000), 0x10000, 0, 0x10000].forEach { stairs.appendUInt64($0) } // vmaddr, vmsize, fileoff, filesize
            [UInt32(5), 5, 1, 0].forEach { stairs.appendUInt32($0) } // maxprot, initprot, nsects, flags
            try stairs.append(XCTUnwrap("__text".data(using: .utf8)) + Data(count: 10) + XCTUnwrap("__G\(index)".data(using: .utf8)) + Data(count: 16 - "__G\(index)".utf8.count))
            [UInt64(0x1_0000_0000) + UInt64(start), UInt64(0x10000 - start)].forEach { stairs.appendUInt64($0) } // addr, size
            [UInt32(start), 0, 0, 0, 0x8000_0400, 0, 0, 0].forEach { stairs.appendUInt32($0) } // offset, align, reloff, nreloc, flags, reserved
        }
        stairs.append(Data(count: 0x10000 - stairs.count))
        for index in 0 ..< staggered {
            stairs[top + 64 * (index + 1)] = 0x43
        }
        let stairsFile = directory / "staggered"
        try stairs.write(to: stairsFile)
        let stairsLines = self.verify(stairsFile.path).lines
        XCTAssertFalse(stairsLines.contains { $0.contains(" of __G0 that no section covers") }, "nothing but zeros before the first section")
        for index in 1 ..< staggered {
            XCTAssertTrue(stairsLines.contains("\(stairsFile.path): \(index.hex) bytes of __G\(index) that no section covers are not zero, the first at \((top + 64).hex)"), "__G\(index)")
        }

        // __INNER lies inside __TEXT's bytes: what follows it to __DATA is __TEXT's content, not bytes between them.
        let nested = try self.crafted("nested", in: directory, size: 0x4000, segments: [("__TEXT", 0x1000, 0x3000, 0, 0x3000, 5), ("__INNER", 0x4000, 0x100, 0x1000, 0x100, 1), ("__DATA", 0x5000, 0x1000, 0x3000, 0x1000, 3)])
        var filled = try Data(contentsOf: nested)
        filled.replaceSubrange(0x800 ..< 0x3000, with: Data(repeating: 0x42, count: 0x2800))
        filled.store(UInt32(MH_PRELOAD), at: 12)
        try filled.write(to: nested)
        let nestedLines = self.verify(nested.path).lines
        XCTAssertTrue(nestedLines.contains("\(nested.path): segments __TEXT and __INNER overlap in the file"))
        XCTAssertFalse(nestedLines.contains { $0.contains("between") }, "\(nestedLines)")
    }

    /**
     What the image says of itself is quoted when it is not printable ASCII: a dylinker or a dylib named with a
     newline stays on its line, where it would make a line of its own off a terminal.
     */
    func testWhatTheImageSaysStaysOnItsLine() throws {
        let directory = try self.directory("quoted")
        let program = try self.program("x86_64", in: directory)
        var dylinker = program
        let command = try self.command(UInt32(LC_LOAD_DYLINKER), in: program)
        let name = try XCTUnwrap(program.range(of: Data("/usr/lib/dyld".utf8), in: command.data.startIndex ..< command.data.endIndex))
        dylinker.replaceSubrange(name, with: "/usr/lib/dy\nd".utf8)
        XCTAssertEqual(try self.verify(dylinker, "dylinker", in: directory).lines, [": LC_LOAD_DYLINKER names \"/usr/lib/dy\\nd\", not /usr/lib/dyld"])
        var id = Data()
        let install = Data("/tmp/evil\n.dylib".utf8) + Data(count: 8)
        [UInt32(LC_ID_DYLIB), UInt32(24 + install.count), 24, 0, 0x10000, 0x10000].forEach { id.appendUInt32($0) }
        id.append(install)
        XCTAssertEqual(try self.verify(self.appending(id, to: program), "id", in: directory).lines, [": LC_ID_DYLIB \"/tmp/evil\\n.dylib\" in an MH_EXECUTE"])
    }

    /**
     Security verifies the CMS blob over the first code directory, slot 0, and reads the ad-hoc flag from the best of
     them, the kernel's choice: with two directories that disagree on the flag, the CMS blob is ignored behind a best
     directory flagged ad hoc though slot 0 is not, and verified behind one that is not though slot 0 is.
     */
    func testTheAdHocFlagIsReadFromTheDirectoryTheKernelTakes() throws {
        let directory = try self.directory("best")
        let signed = directory / "signed"
        try self.program("x86_64", in: directory).write(to: signed)
        _ = try codesign(["-s", "-", "--digest-algorithm=sha1,sha256", "--signature-size", "12000", signed.path])
        let program = try Data(contentsOf: signed)
        let image = try XCTUnwrap(MachO(File(data: program)))
        let signature = try XCTUnwrap(image.findCodeSignature())
        let superblob = try image.signingData(signature)
        let sha1 = try Data(XCTUnwrap(MachO.component(0, of: superblob)))
        let sha256 = try Data(XCTUnwrap(MachO.component(0x1000, of: superblob)))
        let requirements = try Data(XCTUnwrap(MachO.component(2, of: superblob)))
        XCTAssertEqual([sha1[37], sha256[37]], [1, 2], "SHA-1 in slot 0, SHA-256 in the first alternate slot")
        func cleared(_ blob: Data) -> Data {
            var blob = blob
            blob.store((UInt32(bigEndian: blob.load(UInt32.self, at: 12)) & ~UInt32(2)).bigEndian, at: 12) // CS_ADHOC out
            return blob
        }

        let (configuration, key, certificate) = (directory / "certificate.cnf", directory / "key.pem", directory / "certificate.pem")
        try "[req]\ndistinguished_name = dn\nx509_extensions = ext\nprompt = no\n[dn]\nCN = Fashion Self\n[ext]\nextendedKeyUsage = codeSigning\nkeyUsage = digitalSignature\nbasicConstraints = CA:FALSE\n".write(to: configuration, atomically: true, encoding: .utf8)
        try XCTSkipUnless(execute("/usr/bin/openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key.path, "-out", certificate.path, "-config", configuration.path, "-days", "30"]), "cannot make a certificate")
        /// A CMS blob, wrapped as the signature holds it, signed over `content` by the certificate.
        func cms(over content: Data, _ name: String) throws -> Data {
            let (input, output) = (directory / "\(name).bin", directory / "\(name).der")
            try content.write(to: input)
            try XCTSkipUnless(execute("/usr/bin/openssl", ["cms", "-sign", "-binary", "-in", input.path, "-signer", certificate.path, "-inkey", key.path, "-outform", "DER", "-out", output.path]), "cannot sign")
            let cms = try Data(contentsOf: output)
            var wrapped = Data()
            [0xfade_0b01, UInt32(8 + cms.count)].forEach { wrapped.appendUInt32BE($0) }
            return wrapped + cms
        }
        /// The program with a superblob of `blobs`, each in its slot, in the room the signature left.
        func embedded(_ blobs: [(slot: UInt32, blob: Data)]) -> Data {
            var blob = Data()
            var offset = 12 + 8 * blobs.count
            [0xfade_0cc0, UInt32(offset + blobs.reduce(0) { $0 + $1.blob.count }), UInt32(blobs.count)].forEach { blob.appendUInt32BE($0) }
            for entry in blobs {
                blob.appendUInt32BE(entry.slot); blob.appendUInt32BE(UInt32(offset))
                offset += entry.blob.count
            }
            blobs.forEach { blob += $0.blob }
            XCTAssertLessThanOrEqual(blob.count, signature.size)
            var signed = program
            signed.replaceSubrange(signature.offset ..< signature.offset + blob.count, with: blob)
            return signed
        }

        let ignored = try embedded([(0, cleared(sha1)), (2, requirements), (0x1000, sha256), (0x10000, cms(over: cleared(sha1), "ignored"))])
        XCTAssertEqual(try self.verify(ignored, "ignored", in: directory).lines, [": a CMS signature behind a code directory flagged ad hoc, which Security ignores"])
        let refused = try embedded([(0, sha1), (2, requirements), (0x1000, cleared(sha256)), (0x10000, cms(over: sha1, "refused"))])
        XCTAssertEqual(try self.verify(refused, "refused", in: directory).lines, [": the sha256 code directory, which Security and the kernel read the signature by, is not the one the CMS signs, the sha1 code directory at slot 0, and the signer binds none to it: anyone may have added it", ": signed outside Apple's chains by Fashion Self, which Gatekeeper refuses"])
    }

    /**
     A universal file whose magic is in the other byte order, its table big-endian as ever, is one to Security,
     which takes the magic either way, and to nothing else: `codesign -dv` reads `/bin/ls` so changed, `lipo`
     calls it no Mach-O, and the kernel and dyld take the big-endian magic alone. It is read here as Security
     reads it, and named.
     */
    func testAUniversalMagicInTheOtherByteOrderIsNamed() throws {
        let directory = try self.directory("swapped-magic")
        var data = try Data(contentsOf: URL(fileURLWithPath: "/bin/ls"))
        try XCTSkipUnless(Array(data.prefix(4)) == [0xca, 0xfe, 0xba, 0xbe], "/bin/ls is not universal")
        data.replaceSubrange(0 ..< 4, with: [0xbe, 0xba, 0xfe, 0xca])
        let file = directory / "ls"
        try data.write(to: file)

        XCTAssertTrue(try execute("/usr/bin/codesign", ["-dv", file.path]), "codesign reads it")
        XCTAssertFalse(try execute("/usr/bin/lipo", ["-archs", file.path]), "lipo does not")
        self.assertVerify(file.path, ["\(file.path): a universal file whose magic is byte-swapped, which codesign reads all the same: the kernel, dyld and lipo take it for no Mach-O"])
    }

    /**
     A CMS blob with no bytes does not decode, rather than trip over its missing address.
     */
    func testAnEmptyCMSBlobDoesNotDecode() {
        XCTAssertThrowsError(try Signer(cms: Data(), over: Data())) { error in
            if case .undecodable? = error as? Signer.Failure {} else {
                XCTFail("\(error)")
            }
        }
    }

    /**
     A CMS blob with a length past its bytes does not decode, and before Security's decoder sees it: `/bin/ls`'s
     signature, DER throughout, rewrapped in an indefinite-length outer SEQUENCE as Security's own encoder writes
     one, which leaves the decoder no length to check the first OID's against, then that OID's length byte made
     long-form so that the OID's own bytes read as a length of 680 MiB. The decoder allocates what the length says
     and fills it, 857 MB resident for a 4 KiB blob, as the signer fuzz harness found; the reader refuses the blob
     first, and the process grows by nothing.
     */
    func testACMSBlobWithALengthPastItsBytesDoesNotDecode() throws {
        let (directory, cms) = try Self.signature(of: "/bin/ls")
        var reader = DER.Reader(cms)
        let contentInfo = try XCTUnwrap(reader.next())
        var indefinite = Data([0x30, 0x80]) + contentInfo.content + Data([0, 0])
        XCTAssertEqual(Array(indefinite[2 ..< 4]), [0x06, 0x09])
        XCTAssertNoThrow(try Signer(cms: indefinite, over: directory))
        indefinite[3] = 0x84
        let resident = residentBytes()
        XCTAssertThrowsError(try Signer(cms: indefinite, over: directory)) { error in
            XCTAssertEqual(error as? Signer.Failure, .malformed("tag 0x06 at 0x2 declares 713443462 bytes, \(indefinite.count - 8) left"))
        }
        XCTAssertLessThan(residentBytes() - resident, 64 << 20, "the decoder was handed the length")
    }

    /**
     The reader reads tags and lengths as Security's decoder does, so that it refuses nothing the decoder takes: a
     tag in the high-tag-number form, its number in seven-bit bytes; a length in more bytes than it needs, leading
     zeros first; and refuses as it does a tag number past 57 bits and a length past 55, each said with its offset.
     */
    func testTheReaderReadsTagsAndLengthsAsSecuritysDecoderDoes() throws {
        let tagged = try XCTUnwrap(DER.elements(of: Data([0x1f, 0x81, 0x00, 0x01, 0x41])))
        XCTAssertEqual(tagged.map(\.tag), [0x1f])
        XCTAssertEqual(tagged.map { Array($0.content) }, [[0x41]])
        let padded = try XCTUnwrap(DER.elements(of: Data([0x04, 0x85, 0x00, 0x00, 0x00, 0x00, 0x01, 0x41])))
        XCTAssertEqual(padded.map { Array($0.content) }, [[0x41]])
        var tag = DER.Reader(Data([0x1f] + [UInt8](repeating: 0xff, count: 9) + [0x7f]))
        XCTAssertNil(tag.next())
        XCTAssertEqual(tag.fault, "the tag at 0x0 past 57 bits")
        var length = DER.Reader(Data([0x04, 0x88] + [UInt8](repeating: 0xff, count: 8)))
        XCTAssertNil(length.next())
        XCTAssertEqual(length.fault, "the length at 0x0 past 55 bits")
    }

    /**
     One fault is looked for in a CMS blob before Security's decoder is handed it: a length the decoder does not
     check that declares more than the bytes left. The decoder checks a length against the first definite length
     around the element. So it checks none of the message itself, nor of an element under indefinite lengths all
     the way up, however deep. The fault reported is the first in the order the decoder reads.

     None of these is a fault: a length past a definite length around it, its parent's or one further out, which
     the decoder refuses itself; bytes cut short and forms it does not take, which it refuses too; and what
     follows the message, which it never reads. The message is handed over without what follows it.

     An indefinite length ends at two zero bytes, and at no other empty element of tag 0, which is read on as an
     element: its length is one more the decoder may take at its word.
     */
    func testOnlyALengthTheDecoderTakesAtItsWordIsAFault() {
        let oid: [UInt8] = [0x06, 0x84, 0x2a, 0x86, 0x48, 0x86]
        XCTAssertEqual(DER.fault(in: Data([0x30, 0x80] + oid + [0x00, 0x00])), "tag 0x06 at 0x2 declares 713443462 bytes, 2 left")
        XCTAssertEqual(DER.fault(in: Data([0x30, 0x84, 0x7f, 0xff, 0xff, 0xff, 0x06, 0x01, 0x2a])), "tag 0x30 at 0x0 declares 2147483647 bytes, 3 left")
        // Under indefinite lengths all the way up, however deep.
        XCTAssertEqual(DER.fault(in: Data([0x30, 0x80, 0xa0, 0x80] + oid + [0x00, 0x00, 0x00, 0x00])), "tag 0x06 at 0x4 declares 713443462 bytes, 4 left")
        // A tag of 0 that is not the two zero bytes of an end is an element, its length taken at its word.
        XCTAssertEqual(DER.fault(in: Data([0x30, 0x80, 0x00, 0x84, 0x20, 0x00, 0x00, 0x00])), "tag 0x00 at 0x2 declares 536870912 bytes, 0 left")

        // Under an indefinite length inside a definite one: the decoder checks it against the definite one, and
        // refuses.
        XCTAssertNil(DER.fault(in: Data([0x30, 0x0a, 0xa0, 0x80] + oid + [0x00, 0x00])))
        XCTAssertNil(DER.fault(in: Data([0x30, 0x80, 0x30, 0x08, 0xa0, 0x80] + oid + [0x04])))

        XCTAssertNil(DER.fault(in: Data([0x30, 0x80, 0x04, 0x01, 0x41, 0x00, 0x00])))
        // Past a definite parent's length: the decoder checks it, and refuses.
        XCTAssertNil(DER.fault(in: Data([0x30, 0x03, 0x04, 0x7f, 0x41])))
        XCTAssertNil(DER.fault(in: Data([0x30, 0x08] + oid + [0x00, 0x00])))
        // Cut short, or a form the decoder refuses, before any length it would take at its word.
        XCTAssertNil(DER.fault(in: Data([0x30, 0x80, 0x04])))
        XCTAssertNil(DER.fault(in: Data([0x30, 0x80, 0x1f] + [UInt8](repeating: 0xff, count: 9) + [0x7f] + oid)))
        XCTAssertNil(DER.fault(in: Data([0x1f] + [UInt8](repeating: 0xff, count: 9) + [0x7f])))
        // What follows the message is not read, whatever it says.
        let message = Data([0x30, 0x80, 0x04, 0x01, 0x41, 0x00, 0x00])
        XCTAssertNil(DER.fault(in: message + Data([0x41, 0x41, 0x41])))
        XCTAssertNil(DER.fault(in: message + Data(oid)))
        XCTAssertEqual(DER.message(of: message + Data([0x41, 0x41, 0x41])), message)
        XCTAssertEqual(DER.message(of: Data([0x30, 0x80, 0x04])), Data([0x30, 0x80, 0x04]))

        // The message ends at two zero bytes, not at an empty element of tag 0 written otherwise.
        for element in [[0x00, 0x80, 0x00, 0x00], [0x00, 0x81, 0x00]] as [[UInt8]] {
            let nested = Data([0x30, 0x80] + element + [0x00, 0x00])
            XCTAssertNil(DER.fault(in: nested))
            XCTAssertEqual(DER.message(of: nested + Data([0x41])), nested)
        }
    }

    /**
     Security's decoder checks a length against the first definite length around the element, and takes at its
     word one that no definite length encloses. `/bin/ls`'s `x86_64` message is DER. Given indefinite lengths for
     its two outer elements, as Security's own encoder writes them, it decodes and verifies as it did. CMSDecoder
     is asked directly of each form made from it:

     - an end-of-contents is two zero bytes: with any other element of tag 0 in its place, the decoder refuses the
       message, and so does fashion;
     - a SignedData that claims 512 MiB under an indefinite `[0]` inside a definite message is checked against the
       message's length: no fault, and the decoder, handed it, refuses it;
     - the same under an indefinite message is a length taken at its word: a fault, and the decoder is not handed
       it.
     */
    func testALengthIsCheckedAgainstTheFirstDefiniteLengthAroundIt() throws {
        let program = try self.lsX86()
        let image = try XCTUnwrap(MachO(File(data: program)))
        let superblob = try Data(image.signingData(XCTUnwrap(image.findCodeSignature())))
        let code = try Data(XCTUnwrap(MachO.component(0, of: superblob)))
        let cms = try Data(XCTUnwrap(MachO.component(0x10000, of: superblob)).dropFirst(8))

        // The message: a SEQUENCE of the content type's OID and the SignedData under [0], their lengths definite.
        let laidOut = cms.count > 19 && Array(cms.prefix(2)) == [0x30, 0x82] && Array(cms[4 ..< 6]) == [0x06, 0x09] && Array(cms[15 ..< 17]) == [0xa0, 0x82]
        try XCTSkipUnless(laidOut, "/bin/ls's CMS is not laid out as expected")
        let oid = Data(cms[4 ..< 15])
        let signed = Data(cms[19...])
        let end = Data([0x00, 0x00])

        /// Whether Security's decoder takes `message`, asked directly.
        func decodes(_ message: Data) -> Bool {
            var created: CMSDecoder?
            guard CMSDecoderCreate(&created) == errSecSuccess, let decoder = created else {
                return false
            }
            let updated = message.withUnsafeBytes { $0.baseAddress.map { CMSDecoderUpdateMessage(decoder, $0, message.count) } ?? errSecParam }
            return updated == errSecSuccess && CMSDecoderFinalizeMessage(decoder) == errSecSuccess
        }

        let indefinite = Data([0x30, 0x80]) + oid + Data([0xa0, 0x80]) + signed + end + end
        XCTAssertTrue(decodes(cms))
        XCTAssertTrue(decodes(indefinite))
        XCTAssertNil(DER.fault(in: indefinite))
        XCTAssertNoThrow(try Signer(cms: indefinite, over: code, evaluatingChain: false))

        // Either end written as another element of tag 0: the last one, the message's, then the [0]'s.
        for other in [[0x00, 0x7f], [0x00, 0x80, 0x00, 0x00], [0x00, 0x81, 0x00], [0x00, 0x84, 0x7f, 0xff, 0xff, 0xff]] as [[UInt8]] {
            for message in [Data(indefinite.dropLast(2)) + Data(other), Data(indefinite.dropLast(4)) + Data(other) + end] {
                XCTAssertFalse(decodes(message), "\(other)")
                XCTAssertThrowsError(try Signer(cms: message, over: code, evaluatingChain: false), "\(other)")
            }
        }

        // A SignedData of 512 MiB under an indefinite [0], inside a definite message, then inside an indefinite one.
        let huge = Data([0xa0, 0x80, 0x30, 0x84, 0x20, 0x00, 0x00, 0x00])
        let checked = Data([0x30, UInt8(oid.count + huge.count)]) + oid + huge
        XCTAssertNil(DER.fault(in: checked))
        XCTAssertFalse(decodes(checked))
        XCTAssertThrowsError(try Signer(cms: checked, over: code, evaluatingChain: false)) {
            XCTAssertEqual($0 as? Signer.Failure, .undecodable)
        }
        let unchecked = Data([0x30, 0x80]) + oid + huge
        XCTAssertThrowsError(try Signer(cms: unchecked, over: code, evaluatingChain: false)) {
            XCTAssertEqual($0 as? Signer.Failure, .malformed("tag 0x30 at 0xf declares 536870912 bytes, 0 left"))
        }
    }

    /**
     Past the lengths its decoder does not check, a CMS blob is Security's to judge, as codesign has it judged.
     `/bin/ls`'s `x86_64` signature holds in three changed forms:

     - with a byte after the message;
     - with three;
     - with the root certificate it carries bent: an OID in its issuer's name cut to no bytes, so that what
       follows reads past the sequence around it. The decoder keeps a certificate's bytes as it finds them and
       reads no elements there.

     Each is valid to `codesign --verify`, bears no INVALID in hash mode, and brings no line from verify.
     */
    func testACMSBlobIsSecuritysToJudgePastTheLengthsItTakesAtItsWord() throws {
        let directory = try self.directory("cms-lenient")
        let program = try self.lsX86()
        let image = try XCTUnwrap(MachO(File(data: program)))
        let signature = try XCTUnwrap(image.findCodeSignature())
        let superblob = try Data(image.signingData(signature))
        let blobs = Self.blobs(of: superblob)
        let code = try Data(XCTUnwrap(MachO.component(0, of: superblob)))
        let cms = try Data(XCTUnwrap(MachO.component(0x10000, of: superblob)).dropFirst(8))

        /// The slice signed by `cms` in place of its own, the other blobs as they were.
        func signed(by cms: Data) -> Data {
            var wrapper = Data()
            [0xfade_0b01, UInt32(8 + cms.count)].forEach { wrapper.appendUInt32BE($0) }
            wrapper += cms
            return Self.embedding(blobs.map { $0.slot == 0x10000 ? ($0.slot, wrapper) : $0 }, in: program, at: signature)
        }

        // The root certificate the message carries, the first attribute type of its issuer's name, an OID of three
        // bytes, given a length of none: its bytes then read as an element past the sequence that holds them.
        let root = try XCTUnwrap(Signer(cms: cms, over: code).chain.last.map { SecCertificateCopyData($0) as Data })
        let type = try XCTUnwrap(cms.range(of: Data([0x06, 0x03, 0x55, 0x04]), in: XCTUnwrap(cms.range(of: root))))
        var bent = cms
        bent[type.lowerBound + 1] = 0

        for (name, blob) in [("zero", cms + Data([0])), ("junk", cms + Data("AAA".utf8)), ("certificate", bent)] {
            XCTAssertNil(DER.fault(in: blob), name)
            XCTAssertNoThrow(try Signer(cms: blob, over: code, evaluatingChain: false), name)
            let file = directory / name
            try signed(by: blob).write(to: file)
            XCTAssertTrue(try codesign(["--verify", "--verbose=4", file.path]).contains("valid on disk"), name)
            XCTAssertEqual(try CDHash.hash(path: file.path).map(\.invalid), [false], name)
            self.assertVerify(file.path, [])
        }
    }

    /**
     DER nested a level every two bytes, a megabyte of unclosed indefinite-length sequences for the CMS reader and
     arrays within arrays for the entitlements decoder, is refused rather than recursed into: each level is a stack
     frame, and a worker thread has 512 KiB of them.
     */
    func testDeeplyNestedDERIsRefused() {
        let sequences = Data((0 ..< 1 << 20).map { $0 % 2 == 0 ? 0x30 : 0x80 })
        var arrays = Data([0x30, 0x00])
        for _ in 0 ..< 20000 {
            arrays = DER.encode(0x30, arrays)
        }
        let plist = DER.encode(0x70, Data([0x02, 0x01, 0x01]) + DER.encode(0xb0, DER.encode(0x30, DER.encode(0x0c, Data("deep".utf8)) + arrays)))
        let read = self.expectation(description: "read on a worker's stack")
        let worker = Thread {
            var reader = DER.Reader(sequences)
            XCTAssertNil(reader.next())
            XCTAssertNil(Signer.signatureAndToken(in: sequences))
            do {
                _ = try DEREntitlements.decode(plist)
                XCTFail("decoded")
            } catch {
                XCTAssertEqual((error as? DEREntitlements.Refusal)?.what, "values nested past 12 levels")
            }
            read.fulfill()
        }
        worker.stackSize = 512 << 10
        worker.start()
        self.wait(for: [read], timeout: 60)
    }

    /**
     Two code directories of one hash type are refused as Security refuses them, an invalid signature
     (`errSecCSSignatureInvalid`): red and counted under verify, and under hash mode's cdhash.
     */
    func testTwoCodeDirectoriesOfOneHashTypeAreRefused() throws {
        let directory = try self.directory("twice-sha256")
        let signed = directory / "signed"
        try self.program("x86_64", in: directory).write(to: signed)
        _ = try codesign(["-s", "-", "--signature-size", "12000", signed.path])
        let program = try Data(contentsOf: signed)
        let image = try XCTUnwrap(MachO(File(data: program)))
        let signature = try XCTUnwrap(image.findCodeSignature())
        let superblob = try image.signingData(signature)
        let sha256 = try Data(XCTUnwrap(MachO.component(0, of: superblob)))
        let requirements = try Data(XCTUnwrap(MachO.component(2, of: superblob)))
        let blobs: [(slot: UInt32, blob: Data)] = [(0, sha256), (2, requirements), (0x1000, sha256)]
        var blob = Data()
        var offset = 12 + 8 * blobs.count
        [0xfade_0cc0, UInt32(offset + blobs.reduce(0) { $0 + $1.blob.count }), UInt32(blobs.count)].forEach { blob.appendUInt32BE($0) }
        for entry in blobs {
            blob.appendUInt32BE(entry.slot); blob.appendUInt32BE(UInt32(offset))
            offset += entry.blob.count
        }
        blobs.forEach { blob += $0.blob }
        var twice = program
        twice.replaceSubrange(signature.offset ..< signature.offset + blob.count, with: blob)
        let refusal = "Invalid Mach-O: two sha256 code directories, which Security refuses as an invalid signature"
        let verified = try self.verify(twice, "twice", in: directory)
        XCTAssertEqual(verified.lines, [": \(refusal)"])
        XCTAssertEqual(verified.errors, 1)
        let file = directory / "twice"
        let (status, errors) = try runFashion(["--algo", "cdhash", file.path])
        XCTAssertEqual(status, 2)
        XCTAssertEqual(errors, ["fashion: \(file.path): \(refusal)"])
    }

    /**
     The signer's hash-agility attributes bind every code directory to the CMS signature: the cdhashes plist and the
     v2 attribute, as codesign writes them and Security reads them. A CMS built here over the SHA-1 directory of a
     two-directory signature, with the attributes naming both, is valid to codesign, whose only word is then the
     self-signed chain; the same CMS over a SHA-256 directory changed since, which its attributes no longer name, is
     an invalid signature to codesign, and is named so here. Apple's own platform signatures carry no attributes.
     */
    func testTheHashAgilityBindsEveryDirectory() throws {
        let directory = try self.directory("agility")
        let signed = directory / "signed"
        try self.program("x86_64", in: directory).write(to: signed)
        _ = try codesign(["-s", "-", "--signature-size", "12000", "--digest-algorithm=sha1,sha256", signed.path])
        let program = try Data(contentsOf: signed)
        let image = try XCTUnwrap(MachO(File(data: program)))
        let signature = try XCTUnwrap(image.findCodeSignature())
        let superblob = try image.signingData(signature)
        var directories = try [0, 0x1000].map { try Data(XCTUnwrap(MachO.component($0, of: superblob))) }
        for index in directories.indices {
            directories[index].store((UInt32(bigEndian: directories[index].load(UInt32.self, at: 12)) & ~UInt32(2)).bigEndian, at: 12)
        }
        XCTAssertEqual(directories.map { $0[37] }, [1, 2], "SHA-1 at slot 0, SHA-256 the alternate")
        let requirements = try Data(XCTUnwrap(MachO.component(2, of: superblob)))

        let (certificate, key) = try Self.identity("Fashion Self", in: directory)
        /// The hash-agility attributes binding `bound`: the cdhashes plist and the v2 attribute.
        func binding(_ bound: [(type: HashType, cdhash: Data)]) -> Data {
            let plist = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict><key>cdhashes</key><array>" + bound.map { "<data>\($0.cdhash.prefix(20).base64EncodedString())</data>" }.joined() + "</array></dict></plist>\n"
            let v2 = bound.map { DER.encode(0x30, Self.oid($0.type == .sha1 ? [0x2b, 0x0e, 0x03, 0x02, 0x1a] : [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]) + DER.encode(0x04, $0.cdhash)) }.reduce(Data(), +)
            return Self.attribute([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x09, 0x01], DER.encode(0x04, Data(plist.utf8))) + Self.attribute([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x09, 0x02], v2)
        }
        /// `program` signed with `sha1` at slot 0, `sha256` the alternate, and `cms` wrapped.
        func embedded(_ sha1: Data, _ sha256: Data, _ cms: Data) -> Data {
            var wrapped = Data()
            [0xfade_0b01, UInt32(8 + cms.count)].forEach { wrapped.appendUInt32BE($0) }
            wrapped += cms
            let blobs: [(slot: UInt32, blob: Data)] = [(0, sha1), (2, requirements), (0x1000, sha256), (0x10000, wrapped)]
            var blob = Data()
            var offset = 12 + 8 * blobs.count
            [0xfade_0cc0, UInt32(offset + blobs.reduce(0) { $0 + $1.blob.count }), UInt32(blobs.count)].forEach { blob.appendUInt32BE($0) }
            for entry in blobs {
                blob.appendUInt32BE(entry.slot); blob.appendUInt32BE(UInt32(offset))
                offset += entry.blob.count
            }
            blobs.forEach { blob += $0.blob }
            XCTAssertLessThanOrEqual(blob.count, signature.size)
            var signed = program
            signed.replaceSubrange(signature.offset ..< signature.offset + blob.count, with: blob)
            return signed
        }
        let (sha1, sha256) = (directories[0], directories[1])
        let bound = try Self.cms(over: sha1, certificate: certificate, key: key, attributes: binding([(.sha1, Data(Insecure.SHA1.hash(data: sha1))), (.sha256, Data(SHA256.hash(data: sha256)))]), in: directory, "bound")
        let agility = Signer.hashAgility(in: bound)
        XCTAssertEqual(agility.cdhashes, [Data(Insecure.SHA1.hash(data: sha1)).prefix(20), Data(SHA256.hash(data: sha256)).prefix(20)])
        XCTAssertEqual(agility.v2, [.sha1: Data(Insecure.SHA1.hash(data: sha1)), .sha256: Data(SHA256.hash(data: sha256))])
        let fine = embedded(sha1, sha256, bound)
        try fine.write(to: directory / "fine")
        XCTAssertTrue(try execute("/usr/bin/codesign", ["--verify", (directory / "fine").path]), "a signature codesign takes")
        XCTAssertEqual(try self.verify(fine, "fine", in: directory).lines, [": signed outside Apple's chains by Fashion Self, which Gatekeeper refuses"])

        var changed = sha256
        changed[40] ^= 1 // spare2, which nothing but the cdhash depends on
        let unbound = embedded(sha1, changed, bound)
        try unbound.write(to: directory / "unbound")
        XCTAssertFalse(try execute("/usr/bin/codesign", ["--verify", (directory / "unbound").path]), "an invalid signature to codesign")
        XCTAssertEqual(try self.verify(unbound, "unbound", in: directory).lines, [": the CMS signature does not bind the code directories as Security requires: its cdhashes plist lists other code directories than the signature holds, an invalid signature to it"])
    }

    /**
     The CMS signs the directory at slot 0 and binds the others by the signer's hash-agility attributes. A signer
     that wrote none binds nothing, and Apple's own platform signatures carry none.

     A SHA-384 directory is made here over `/bin/ls`'s `x86_64` code and added beside the SHA-256 one Apple
     signed. It outranks it, so Security and the kernel read the signature by it: codesign says valid on disk, and
     hash mode lists its cdhash first with no INVALID. verify names it as the directory nothing binds, which
     anyone may have added.
     */
    func testABestDirectoryNothingBindsIsNamed() throws {
        let directory = try self.directory("unbound-best")
        let program = try self.lsX86()
        let image = try XCTUnwrap(MachO(File(data: program)))
        let signature = try XCTUnwrap(image.findCodeSignature())
        let superblob = try Data(image.signingData(signature))
        var blobs = Self.blobs(of: superblob)
        let signed = try Data(XCTUnwrap(MachO.component(0, of: superblob)))
        XCTAssertEqual(signed[37], 2, "SHA-256 at slot 0")
        XCTAssertNil(MachO.component(0x1000, of: superblob), "no alternate")

        // The same header and identifier, no special slot, a SHA-384 slot per page of the code.
        let hashOffset = Int(UInt32(bigEndian: signed.load(UInt32.self, at: 16)))
        let special = Int(UInt32(bigEndian: signed.load(UInt32.self, at: 24)))
        var added = Data(signed.prefix(hashOffset - 32 * special))
        let page = 1 << Int(signed[39])
        for start in stride(from: 0, to: signature.offset, by: page) {
            added += Data(SHA384.hash(data: program[start ..< min(start + page, signature.offset)]))
        }
        added.store(UInt32(added.count).bigEndian, at: 4)
        added.store(UInt32(hashOffset - 32 * special).bigEndian, at: 16)
        added.store(UInt32(0).bigEndian, at: 24)
        added[36] = 48
        added[37] = 4

        blobs.insert((0x1000, added), at: blobs.count - 1)
        XCTAssertEqual(blobs.last?.slot, 0x10000, "the CMS blob last")
        let data = Self.embedding(blobs, in: program, at: signature)
        let file = directory / "ls"
        try data.write(to: file)

        XCTAssertTrue(try codesign(["--verify", "--verbose=4", file.path]).contains("valid on disk"))
        let results = try CDHash.hash(path: file.path)
        XCTAssertEqual(results.map(\.type), ["sha384", "sha256"])
        XCTAssertEqual(results.map(\.invalid), [false, false])
        self.assertVerify(file.path, [
            "\(file.path): the requirements blob is not sealed by the sha384 code directory",
            "\(file.path): the sha384 code directory, which Security and the kernel read the signature by, is not the one the CMS signs, the sha256 code directory at slot 0, and the signer binds none to it: anyone may have added it",
        ])
    }

    /**
     A directory of truncated SHA-256 page hashes is bound under SHA-256's name: Security names a directory in the
     v2 attribute by its digest algorithm's OID (`SECOidTagForAlgorithm`), and the truncation is of the page
     hashes, not of the algorithm.

     A CMS is built here over such a directory. With a v2 attribute naming SHA-256 and the directory's cdhash of
     20 bytes, it is valid to codesign, whose only word is then the self-signed chain, and bears no INVALID here.
     With the 32 bytes of the whole digest, it is an invalid signature to both.
     */
    func testATruncatedSHA256DirectoryIsBoundUnderSHA256sName() throws {
        let directory = try self.directory("agility-truncated")
        let signed = directory / "signed"
        try self.program("x86_64", in: directory).write(to: signed)
        _ = try codesign(["-s", "-", "--signature-size", "12000", "--digest-algorithm=sha256T", signed.path])
        let program = try Data(contentsOf: signed)
        let image = try XCTUnwrap(MachO(File(data: program)))
        let signature = try XCTUnwrap(image.findCodeSignature())
        let superblob = try image.signingData(signature)
        var truncated = try Data(XCTUnwrap(MachO.component(0, of: superblob)))
        XCTAssertEqual(truncated[37], 3, "truncated SHA-256")
        truncated.store((UInt32(bigEndian: truncated.load(UInt32.self, at: 12)) & ~UInt32(2)).bigEndian, at: 12)
        let requirements = try Data(XCTUnwrap(MachO.component(2, of: superblob)))
        let (certificate, key) = try Self.identity("Fashion Self", in: directory)
        let digest = Data(SHA256.hash(data: truncated))

        for (name, cdhash, bound) in [("whole", digest, false), ("cut", Data(digest.prefix(20)), true)] {
            let plist = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict><key>cdhashes</key><array><data>\(digest.prefix(20).base64EncodedString())</data></array></dict></plist>\n"
            let v2 = DER.encode(0x30, Self.oid([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]) + DER.encode(0x04, cdhash))
            let attributes = Self.attribute([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x09, 0x01], DER.encode(0x04, Data(plist.utf8))) + Self.attribute([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x09, 0x02], v2)
            let cms = try Self.cms(over: truncated, certificate: certificate, key: key, attributes: attributes, in: directory, name)
            let file = Self.embedding(truncated, requirements, cms, in: program, at: signature)
            let path = directory / name
            try file.write(to: path)
            XCTAssertEqual(try execute("/usr/bin/codesign", ["--verify", path.path]), bound, "\(name): codesign --verify")
            XCTAssertEqual(try CDHash.hash(path: path.path).map(\.invalid), [!bound], name)
            XCTAssertEqual(self.verify(path.path).lines, ["\(path.path): " + (bound ? "signed outside Apple's chains by Fashion Self, which Gatekeeper refuses" : "the CMS signature does not bind the code directories as Security requires: its hash agility names other code directories than the signature holds, an invalid signature to it")], name)
        }
    }

    /**
     Security cuts the pages of every code directory by one directory's geometry, the lowest hash type's, and checks
     each directory's slots at those pages: a SHA-1 directory covering two whole pages beside a SHA-256 one covering
     three, the third slot of which is wrong, is valid to codesign, which never cuts a third page, where the third
     page hashed to nothing over the SHA-256 directory's own geometry here. The disagreement is named.
     */
    func testThePagesAreCutByOneDirectoryForAll() throws {
        let directory = try self.directory("geometry")
        let signed = directory / "signed"
        try self.program("x86_64", in: directory).write(to: signed)
        _ = try codesign(["-s", "-", "--digest-algorithm=sha1,sha256", signed.path])
        let program = try Data(contentsOf: signed)
        let image = try XCTUnwrap(MachO(File(data: program)))
        let signature = try XCTUnwrap(image.findCodeSignature())
        let superblob = try image.signingData(signature)
        let sha1 = try XCTUnwrap(MachO.component(0, of: superblob))
        let sha256 = try XCTUnwrap(MachO.component(0x1000, of: superblob))
        XCTAssertEqual([sha1[sha1.startIndex + 37], sha256[sha256.startIndex + 37]], [1, 2], "SHA-1 at slot 0, SHA-256 the alternate")
        try XCTSkipUnless(UInt32(bigEndian: sha1.load(UInt32.self, at: 28)) == 3, "a program of three pages")
        var paged = program
        paged.store(UInt32(2).bigEndian, at: signature.offset + sha1.startIndex + 28) // nCodeSlots
        paged.store(UInt32(0x2000).bigEndian, at: signature.offset + sha1.startIndex + 32) // codeLimit
        let hashOffset = Int(UInt32(bigEndian: sha256.load(UInt32.self, at: 16)))
        paged[signature.offset + sha256.startIndex + hashOffset + 2 * 32] ^= 0xff
        let file = directory / "paged"
        try paged.write(to: file)
        try XCTSkipUnless(execute("/usr/bin/codesign", ["--verify", "--strict", file.path]), "codesign refuses the file Security takes")
        self.assertVerify(file.path, [
            "\(file.path): the sha1 code directory covers 0x2000 bytes, 0x110 short of the signature at \(signature.offset.hex): the rest is unsigned",
            "\(file.path): the sha256 code directory cuts \(signature.offset.hex) bytes of code into pages of 0x1000, where the sha1 code directory cuts 0x2000 into 0x1000: Security checks every directory by the latter, the kernel by the directory it ranks first",
        ])
    }

    /**
     The signature's lines, each from an entitled ad hoc signature taken apart and put back with one thing wrong: a
     code directory not flagged ad hoc with no CMS signature behind it, as ldid signs; the requirements blob's
     special slot left zero; the entitlements and their DER form sealed by the directory but missing from the
     signature; a DER form that does not decode, which AMFI refuses; a code limit past the image; a scattered
     directory; a page size the kernel does not take.
     */
    func testTheSignatureLinesAreNamed() throws {
        let directory = try self.directory("signature-lines")
        let plist = directory / "entitlements.plist"
        try Data("""
        <?xml version="1.0" encoding="UTF-8"?>
        <plist version="1.0"><dict><key>com.apple.security.get-task-allow</key><true/></dict></plist>
        """.utf8).write(to: plist)
        let signed = directory / "signed"
        try self.program("x86_64", in: directory).write(to: signed)
        _ = try codesign(["-s", "-", "--signature-size", "12000", "--entitlements", plist.path, signed.path])
        let program = try Data(contentsOf: signed)
        let image = try XCTUnwrap(MachO(File(data: program)))
        let signature = try XCTUnwrap(image.findCodeSignature())
        let superblob = try image.signingData(signature)
        let (cd, requirements, entitlements, der) = try (Data(XCTUnwrap(MachO.component(0, of: superblob))), Data(XCTUnwrap(MachO.component(2, of: superblob))), Data(XCTUnwrap(MachO.component(5, of: superblob))), Data(XCTUnwrap(MachO.component(7, of: superblob))))
        let baseline = [": entitled to opt out of hardening: com.apple.security.get-task-allow"]
        XCTAssertEqual(try self.verify(program, "baseline", in: directory).lines, baseline)
        /// `program` with a signature of `blobs`.
        func embedded(_ blobs: [(slot: UInt32, blob: Data?)]) -> Data {
            let blob = Self.superblob(blobs)
            var signed = program
            signed.replaceSubrange(signature.offset ..< signature.offset + blob.count, with: blob)
            return signed
        }
        /// `cd` with `value` stored big-endian at `offset`.
        func edited<T: FixedWidthInteger>(_ value: T, at offset: Int) -> Data {
            var edited = cd
            edited.store(value.bigEndian, at: offset)
            return edited
        }
        let hashOffset = Int(UInt32(bigEndian: cd.load(UInt32.self, at: 16)))
        let nCodeSlots = Int(UInt32(bigEndian: cd.load(UInt32.self, at: 28)))
        /// `cd` covering `codeLimit` in pages of 2^`pageSizeLog`, its code slots, which end the blob, as many as
        /// Security wants of it, the new ones zero.
        func reshaped(codeLimit: Int, pageSizeLog: UInt8 = 12) -> Data {
            let slots = ((codeLimit - 1) >> Int(pageSizeLog)) + 1
            var edited = cd.prefix(hashOffset + 32 * min(slots, nCodeSlots)) + Data(count: 32 * max(0, slots - nCodeSlots))
            edited.store(UInt32(edited.count).bigEndian, at: 4)
            edited.store(UInt32(slots).bigEndian, at: 28)
            edited.store(UInt32(codeLimit).bigEndian, at: 32)
            edited[39] = pageSizeLog
            return edited
        }
        /// `cd` with a scatter vector at its end, one run of its pages from the start, then the zero entry.
        var scattered = cd
        scattered.store(UInt32(cd.count).bigEndian, at: 44)
        scattered.appendUInt32BE(UInt32(nCodeSlots)); scattered.appendUInt32BE(0); scattered.appendUInt64(0); scattered.appendUInt64(0)
        scattered.append(Data(count: 24))
        scattered.store(UInt32(scattered.count).bigEndian, at: 4)
        var unsealed = cd
        unsealed.replaceSubrange(hashOffset - 64 ..< hashOffset - 32, with: Data(count: 32))
        var undecodable = der
        undecodable.replaceSubrange(8 ..< der.count, with: Data(repeating: 0xff, count: der.count - 8))
        let type = "the sha256 code directory"
        for (name, blobs, expected) in [
            ("ldid", [(0, edited(UInt32(bigEndian: cd.load(UInt32.self, at: 12)) & ~UInt32(2), at: 12)), (2, requirements), (5, entitlements), (7, der)], baseline + [": no CMS signature behind a code directory not flagged ad hoc"]),
            ("unsealed", [(0, unsealed), (2, requirements), (5, entitlements), (7, der)], [": the requirements blob is not sealed by \(type)"] + baseline),
            ("missing", [(0, cd), (2, requirements)], [": \(type) seals the entitlements blob, which the signature does not hold", ": \(type) seals the DER entitlements blob, which the signature does not hold"]),
            ("undecodable", [(0, cd), (2, requirements), (5, entitlements), (7, undecodable)], [": the DER entitlements blob does not hash to its slot in \(type)", ": DER entitlements holding no element to read, which AMFI refuses the code for"]),
            ("past", [(0, reshaped(codeLimit: program.count + 0x100)), (2, requirements), (5, entitlements), (7, der)], [": \(type) covers \((program.count + 0x100).hex) bytes, past the image's \(program.count.hex)"] + baseline),
            ("scattered", [(0, scattered), (2, requirements), (5, entitlements), (7, der)], [": \(type) is scattered, which Security does not read: its slots are checked in order"] + baseline),
            ("pagesize", [(0, reshaped(codeLimit: Int(cd.load(UInt32.self, at: 32).bigEndian), pageSizeLog: 13)), (2, requirements), (5, entitlements), (7, der)], [": page 0 of the code does not hash to \(type)", ": \(type)'s page size, 2^13, is neither the 4 KiB nor the 16 KiB the kernel takes"] + baseline),
        ] as [(String, [(slot: UInt32, blob: Data?)], [String])] {
            XCTAssertEqual(try self.verify(embedded(blobs), name, in: directory).lines, expected, name)
        }
    }

    /**
     Security verifies a signature over the signed attributes as it encodes them again, not as the bytes have
     them. So a message may be written in any form its decoder takes, and the signature still verifies. Two such
     forms kept the signer's hash-agility attributes, which Security enforces, from being read here:

     - a tag in the high-tag-number form where one byte would do: `3f 10` for a SEQUENCE's `30`;
     - an OCTET STRING in pieces: `24 ..` around its substrings, which are strings again.

     Three signatures are made over a truncated SHA-256 directory, as the test before this one makes them: one
     bound right, one whose v2 attribute names another cdhash, one whose cdhashes plist lists another. Each is
     written again in each form, and `codesign --verify` is asked:

     - a form the decoder takes leaves the verdict as it was: valid for the right binding, invalid for a wrong one;
     - a change inside the v2 attribute's value, which the signature covers as it is written, is invalid whatever
       the binding, and so is a string made of anything but strings.

     Hash mode's INVALID is codesign's verdict for every one of them.
     */
    func testTheSignersAttributesAreReadInEveryFormTheDecoderTakes() throws {
        // The reader's part: a tag by its number, however written, and a string's bytes, in one piece or more.
        var padded = DER.Reader(Data([0x3f, 0x80, 0x10, 0x00]))
        let sequence = try XCTUnwrap(padded.next())
        XCTAssertEqual([sequence.tag, sequence.identifier], [0x30, 0x3f])
        var high = DER.Reader(Data([0xbf, 0x1f, 0x00]))
        XCTAssertEqual(high.next()?.tag, 0xbf)
        // A number that fills the decoder's 64 bits is no number under 31, and the tag is its first byte: the tag
        // the signer fuzz harness wrote, then its shortest form.
        var filled = DER.Reader(Data([0x3f, 0x80, 0x81, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x88, 0x37, 0x00]))
        XCTAssertEqual(filled.next()?.tag, 0x3f)
        var shortest = DER.Reader(Data([0x1f, 0x81] + [UInt8](repeating: 0x80, count: 8) + [0x00, 0x00]))
        XCTAssertEqual(shortest.next()?.tag, 0x1f)
        /// The bytes of the OCTET STRING that `bytes` encode.
        func octets(_ bytes: [UInt8]) -> Data? {
            var reader = DER.Reader(Data(bytes))
            return reader.next().flatMap(DER.octets(of:))
        }
        XCTAssertEqual(octets([0x04, 0x03, 0x61, 0x62, 0x63]), Data("abc".utf8))
        XCTAssertEqual(octets([0x24, 0x07, 0x04, 0x01, 0x61, 0x04, 0x02, 0x62, 0x63]), Data("abc".utf8))
        XCTAssertEqual(octets([0x24, 0x80, 0x3f, 0x04, 0x04, 0x1f, 0x04, 0x01, 0x61, 0x04, 0x02, 0x62, 0x63, 0x00, 0x00]), Data("abc".utf8))
        XCTAssertEqual(octets([0x24, 0x00]), Data())
        XCTAssertNil(octets([0x24, 0x03, 0x0c, 0x01, 0x61]))
        XCTAssertNil(octets([0x0c, 0x01, 0x61]))

        let directory = try self.directory("agility-forms")
        let signed = directory / "signed"
        try self.program("x86_64", in: directory).write(to: signed)
        _ = try codesign(["-s", "-", "--signature-size", "12000", "--digest-algorithm=sha256T", signed.path])
        let program = try Data(contentsOf: signed)
        let image = try XCTUnwrap(MachO(File(data: program)))
        let signature = try XCTUnwrap(image.findCodeSignature())
        let superblob = try image.signingData(signature)
        var truncated = try Data(XCTUnwrap(MachO.component(0, of: superblob)))
        truncated.store((UInt32(bigEndian: truncated.load(UInt32.self, at: 12)) & ~UInt32(2)).bigEndian, at: 12)
        let requirements = try Data(XCTUnwrap(MachO.component(2, of: superblob)))
        let (certificate, key) = try Self.identity("Fashion Self", in: directory)
        let cdhash = Data(SHA256.hash(data: truncated).prefix(20))
        var another = cdhash
        another[0] ^= 0xff

        /// `der` with the element at `path`, an index among the elements at each level, written again by
        /// `rewrite`, and the elements around it encoded again to hold it.
        func written(_ der: Data, at path: [Int], _ rewrite: (DER.Element) -> Data) throws -> Data {
            var reader = DER.Reader(der)
            let element = try XCTUnwrap(reader.next())
            guard let index = path.first else {
                return rewrite(element)
            }
            var children = try XCTUnwrap(DER.elements(of: element.content)).map { Data($0.raw) }
            children[index] = try written(children[index], at: Array(path.dropFirst()), rewrite)
            return DER.encode(element.tag, children.reduce(Data(), +))
        }
        /// The element with `tag`, its number apart, in place of its one byte.
        func long(_ tag: [UInt8]) -> (DER.Element) -> Data {
            { Data(tag) + Data($0.raw.dropFirst()) }
        }
        /// The string constructed, around itself.
        func constructed(_ element: DER.Element) -> Data {
            DER.encode(0x24, Data(element.raw))
        }
        /// The string constructed, around its two halves.
        func halves(_ element: DER.Element) -> Data {
            let content = Data(element.content)
            return DER.encode(0x24, DER.encode(0x04, content.prefix(content.count / 2)) + DER.encode(0x04, content.suffix(content.count - content.count / 2)))
        }

        for (name, listed, named, bound) in [("bound", cdhash, cdhash, true), ("v2-other", cdhash, another, false), ("plist-other", another, cdhash, false)] {
            let plist = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict><key>cdhashes</key><array><data>\(listed.base64EncodedString())</data></array></dict></plist>\n"
            let v2 = DER.encode(0x30, Self.oid([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]) + DER.encode(0x04, named))
            let attributes = Self.attribute([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x09, 0x01], DER.encode(0x04, Data(plist.utf8))) + Self.attribute([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x09, 0x02], v2)
            let cms = try Self.cms(over: truncated, certificate: certificate, key: key, attributes: attributes, in: directory, name)

            // Where the message keeps its parts: the signers last in the SignedData, then the first signer's
            // signed attributes, its signature, and the two attributes among the signed ones.
            var reader = DER.Reader(cms)
            let parts = try XCTUnwrap(DER.elements(of: XCTUnwrap(reader.next()).content))
            let fields = try XCTUnwrap(DER.elements(of: XCTUnwrap(DER.elements(of: parts[1].content)?.first).content))
            let signer = [1, 0, fields.count - 1, 0]
            let signerFields = try XCTUnwrap(DER.elements(of: XCTUnwrap(DER.elements(of: XCTUnwrap(fields.last).content)?.first).content))
            let signedAttributes = try signer + [XCTUnwrap(signerFields.firstIndex { $0.tag == 0xa0 })]
            let signatureField = try signer + [XCTUnwrap(signerFields.lastIndex { $0.tag == 0x04 })]
            let signedOnes = try XCTUnwrap(DER.elements(of: XCTUnwrap(signerFields.first { $0.tag == 0xa0 }).content))
            /// The attribute whose type ends in `last`, among the signed ones.
            func attribute(_ last: UInt8) throws -> [Int] {
                try signedAttributes + [XCTUnwrap(signedOnes.firstIndex { DER.elements(of: $0.content)?.first?.content.last == last && DER.elements(of: $0.content)?.first?.content.count == 9 && DER.elements(of: $0.content)?.first?.content.starts(with: [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x09]) == true })]
            }
            let (listing, naming) = try (attribute(1), attribute(2))

            // Each form, where it is written, and whether Security's decoder takes it with the signature holding.
            let forms: [(name: String, path: [Int], rewrite: (DER.Element) -> Data, taken: Bool)] = [
                ("as it is", [], { Data($0.raw) }, true),
                ("message 3f 10", [], long([0x3f, 0x10]), true),
                ("message 3f 80 10", [], long([0x3f, 0x80, 0x10]), true),
                ("content bf 00", [1], long([0xbf, 0x00]), true),
                ("SignedData 3f 10", [1, 0], long([0x3f, 0x10]), true),
                ("signers 3f 11", Array(signer.dropLast()), long([0x3f, 0x11]), true),
                ("signer 3f 10", signer, long([0x3f, 0x10]), true),
                ("signed attributes bf 00", signedAttributes, long([0xbf, 0x00]), true),
                ("v2 attribute 3f 10", naming, long([0x3f, 0x10]), true),
                ("v2 type 1f 06", naming + [0], long([0x1f, 0x06]), true),
                ("v2 values 3f 11", naming + [1], long([0x3f, 0x11]), true),
                ("plist values 3f 11", listing + [1], long([0x3f, 0x11]), true),
                ("plist 1f 04", listing + [1, 0], long([0x1f, 0x04]), true),
                ("plist constructed", listing + [1, 0], constructed, true),
                ("plist in halves", listing + [1, 0], halves, true),
                ("plist constructed twice", listing + [1, 0], { DER.encode(0x24, constructed($0)) }, true),
                ("plist constructed, indefinite", listing + [1, 0], { Data([0x24, 0x80]) + Data($0.raw) + Data([0x00, 0x00]) }, true),
                ("plist constructed 3f 04", listing + [1, 0], { Data([0x3f, 0x04]) + constructed($0).dropFirst() }, true),
                ("plist constructed of 1f 04", listing + [1, 0], { DER.encode(0x24, long([0x1f, 0x04])($0)) }, true),
                ("signature constructed", signatureField, constructed, true),
                ("signature in halves", signatureField, halves, true),
                ("signature 1f 04", signatureField, long([0x1f, 0x04]), true),
                // Inside the v2 attribute's value, the bytes are signed as they are written.
                ("v2 value 3f 10", naming + [1, 0], long([0x3f, 0x10]), false),
                ("v2 cdhash 1f 04", naming + [1, 0, 1], long([0x1f, 0x04]), false),
                ("v2 cdhash constructed", naming + [1, 0, 1], constructed, false),
                // A string is made of strings of its type, and of nothing else.
                ("plist constructed of a UTF8String", listing + [1, 0], { DER.encode(0x24, DER.encode(0x0c, Data($0.content))) }, false),
                ("plist constructed of a string and a NULL", listing + [1, 0], { DER.encode(0x24, Data($0.raw) + DER.encode(0x05, Data())) }, false),
                ("plist constructed of nothing", listing + [1, 0], { _ in DER.encode(0x24, Data()) }, false),
            ]
            for form in forms {
                let file = try Self.embedding(truncated, requirements, written(cms, at: form.path, form.rewrite), in: program, at: signature)
                let path = directory / "\(name)-\(form.name.replacingOccurrences(of: " ", with: "-"))"
                try file.write(to: path)
                let verifies = try execute("/usr/bin/codesign", ["--verify", path.path])
                XCTAssertEqual(verifies, bound && form.taken, "\(name), \(form.name): codesign --verify")
                XCTAssertEqual(try CDHash.hash(path: path.path).map(\.invalid), [!verifies], "\(name), \(form.name)")
            }
        }
    }

    /**
     Hash mode's INVALID is the verdict of Security's static validation, which judges a signature by its best
     directory, as `codesign --verify` has it for each file here, made from an ad hoc signature taken apart:

     - a special slot the directory seals wants its blob there and hashing to it, up to the library constraint's,
       slot 11: a launch constraint changed or missing is INVALID, one unsealed or sealed right is not, and a slot
       past the last Security visits, 12, is not read;
     - a slot sealed over what lies under a wrapper, 6, is hashed over that and not over the blob;
     - the top directory's blob, slot 4, must lie under a wrapper, sealed or not;
     - the signature slot's must too, behind a directory flagged ad hoc as behind any;
     - the code limit must be the signature's offset, not past it;
     - the pages are cut by an `int` shifted by the directory's exponent, which counts modulo 32: one slot over
       all the code holds under an exponent of 31 or 63, pages past any limit, and not under 44, pages of 4 KiB;
     - a scatter vector is not read: the slots are checked in order, sound or changed;
     - the image must end where its bytes do, as strict validation has it: bytes appended are INVALID, and not
       with --exact, which hashes the image without them;
     - an alternate's own seals are never read: a wrong one beside a sound best directory is no INVALID, and a
       wrong one in the best is, on every line.

     verify names each in a line: the slot that does not seal its blob, by what it seals, and for an alternate that
     Security does not read it; the blob that does not lie under its wrapper; the limit strict validation refuses.
     */
    func testINVALIDIsSecuritysVerdictOnTheBestDirectory() throws {
        let directory = try self.directory("static-verdict")
        let signed = directory / "signed"
        try self.program("x86_64", in: directory).write(to: signed)
        _ = try codesign(["-s", "-", "--signature-size", "12000", signed.path])
        let program = try Data(contentsOf: signed)
        let image = try XCTUnwrap(MachO(File(data: program)))
        let signature = try XCTUnwrap(image.findCodeSignature())
        let superblob = try image.signingData(signature)
        let sha256 = try Data(XCTUnwrap(MachO.component(0, of: superblob)))
        let requirements = try Data(XCTUnwrap(MachO.component(2, of: superblob)))

        /// A blob of `magic` over `payload`.
        func blob(_ magic: UInt32, _ payload: String = "") -> Data {
            var blob = Data()
            [magic, UInt32(8 + payload.utf8.count)].forEach { blob.appendUInt32BE($0) }
            return blob + Data(payload.utf8)
        }

        /// `directory`, a SHA-256 one, with each of `slots` sealed over its bytes, special slots added as needed.
        func sealing(_ directory: Data, _ slots: [Int: Data]) -> Data {
            var directory = directory
            let hashOffset = Int(UInt32(bigEndian: directory.load(UInt32.self, at: 16)))
            let had = Int(UInt32(bigEndian: directory.load(UInt32.self, at: 24)))
            let added = max(0, (slots.keys.max() ?? 0) - had)
            directory.insert(contentsOf: Data(count: 32 * added), at: hashOffset - 32 * had)
            directory.store(UInt32(directory.count).bigEndian, at: 4)
            directory.store(UInt32(hashOffset + 32 * added).bigEndian, at: 16)
            directory.store(UInt32(had + added).bigEndian, at: 24)
            for (slot, bytes) in slots {
                let at = hashOffset + 32 * added - 32 * slot
                directory.replaceSubrange(at ..< at + 32, with: Data(SHA256.hash(data: bytes)))
            }
            return directory
        }

        /// `program` with a signature of `blobs`, each at its slot, placed in order.
        func embedded(_ blobs: [(slot: UInt32, blob: Data?)], in program: Data = program, at signature: MachO.Span = signature) -> Data {
            Self.embedding(blobs, in: program, at: signature)
        }

        let wrapper = blob(0xfade_0b01)
        let constraint = blob(0xfade_8181, "constraint")
        let wrapped = blob(0xfade_0b01, "wrapped")

        // The code limit past the signature, over the superblob's header and index, the last page hashed to there.
        let past = signature.offset + 36
        try XCTSkipUnless((past - 1) >> 12 == (signature.offset - 1) >> 12, "the limit would take a page more")
        var further = sha256
        further.store(UInt32(past).bigEndian, at: 32)
        let slots = Int(UInt32(bigEndian: sha256.load(UInt32.self, at: 28)))
        let last = Int(UInt32(bigEndian: sha256.load(UInt32.self, at: 16))) + 32 * (slots - 1)
        let page = ((signature.offset - 1) >> 12) << 12
        let head = Self.superblob([(0, further), (2, requirements), (0x10000, wrapper)]).prefix(36)
        further.replaceSubrange(last ..< last + 32, with: Data(SHA256.hash(data: program[page ..< signature.offset] + head)))

        let hashOffset = Int(UInt32(bigEndian: sha256.load(UInt32.self, at: 16)))
        /// `sha256` paged by 2^`exponent`, with the one slot that many bytes a page asks for, over all the code.
        func paged(_ exponent: UInt8) -> Data {
            var directory = Data(sha256.prefix(hashOffset + 32))
            directory[39] = exponent
            directory.store(UInt32(1).bigEndian, at: 28)
            directory.store(UInt32(directory.count).bigEndian, at: 4)
            directory.replaceSubrange(hashOffset ..< hashOffset + 32, with: Data(SHA256.hash(data: program[..<signature.offset])))
            return directory
        }

        /// `directory` with a scatter vector at its end, one run of its pages from the start, then the zero entry.
        func scattered(_ directory: Data) -> Data {
            var scattered = directory
            scattered.store(UInt32(directory.count).bigEndian, at: 44)
            scattered.appendUInt32BE(UInt32(slots)); scattered.appendUInt32BE(0); scattered.appendUInt64(0); scattered.appendUInt64(0)
            scattered.append(Data(count: 24))
            scattered.store(UInt32(scattered.count).bigEndian, at: 4)
            return scattered
        }

        var changed = sha256
        changed[hashOffset + 32] ^= 0xff

        let type = "the sha256 code directory"
        var cases: [(name: String, file: Data, invalid: Bool, lines: [String]?)] = [
            ("page-44", embedded([(0, paged(44)), (2, requirements), (0x10000, wrapper)]), true, nil),
            ("page-31", embedded([(0, paged(31)), (2, requirements), (0x10000, wrapper)]), false, nil),
            ("page-63", embedded([(0, paged(63)), (2, requirements), (0x10000, wrapper)]), false, nil),
            ("scattered", embedded([(0, scattered(sha256)), (2, requirements), (0x10000, wrapper)]), false, nil),
            ("scattered-changed", embedded([(0, scattered(changed)), (2, requirements), (0x10000, wrapper)]), true, nil),
            ("sound", embedded([(0, sha256), (2, requirements), (0x10000, wrapper)]), false, []),
            ("constraint", embedded([(0, sealing(sha256, [8: constraint])), (2, requirements), (8, constraint), (0x10000, wrapper)]), false, []),
            ("constraint-changed", embedded([(0, sealing(sha256, [8: blob(0xfade_8181, "another")])), (2, requirements), (8, constraint), (0x10000, wrapper)]), true, [": the launch constraint on the process does not hash to its slot in \(type)"]),
            ("constraint-missing", embedded([(0, sealing(sha256, [8: constraint])), (2, requirements), (0x10000, wrapper)]), true, [": \(type) seals the launch constraint on the process, which the signature does not hold"]),
            ("constraint-unsealed", embedded([(0, sha256), (2, requirements), (8, constraint), (0x10000, wrapper)]), false, [": the launch constraint on the process is not sealed by \(type)"]),
            ("library-missing", embedded([(0, sealing(sha256, [11: constraint])), (2, requirements), (0x10000, wrapper)]), true, [": \(type) seals the library constraint, which the signature does not hold"]),
            ("twelve-missing", embedded([(0, sealing(sha256, [12: constraint])), (2, requirements), (0x10000, wrapper)]), false, []),
            ("under-wrapper", embedded([(0, sealing(sha256, [6: Data("wrapped".utf8)])), (2, requirements), (6, wrapped), (0x10000, wrapper)]), false, []),
            ("over-wrapper", embedded([(0, sealing(sha256, [6: wrapped])), (2, requirements), (6, wrapped), (0x10000, wrapper)]), true, [": the blob the file's kind keeps at slot 6 does not hash to its slot in \(type)"]),
            ("top-unwrapped", embedded([(0, sha256), (2, requirements), (4, requirements), (0x10000, wrapper)]), true, [": the top directory does not lie under a wrapper, which Security refuses the signature for"]),
            ("signature-unwrapped", embedded([(0, sha256), (2, requirements), (0x10000, blob(0xfade_0b02))]), true, [": the CMS blob's magic is 0xfade0b02, not 0xfade0b01, which Security refuses the signature for"]),
            ("limit-past", embedded([(0, further), (2, requirements), (0x10000, wrapper)]), true, [": \(type) covers \(past.hex) bytes, past the signature at \(signature.offset.hex), which strict validation refuses the signature for"]),
        ]

        // Two directories, SHA-256 the best: the requirements' seal wrong in one, then in the other.
        let twice = directory / "twice"
        try self.program("x86_64", in: directory).write(to: twice)
        _ = try codesign(["-s", "-", "--signature-size", "12000", "--digest-algorithm=sha1,sha256", twice.path])
        let both = try Data(contentsOf: twice)
        let pair = try XCTUnwrap(MachO(File(data: both)))
        let pairSignature = try XCTUnwrap(pair.findCodeSignature())
        let pairBlob = try pair.signingData(pairSignature)
        let first = try Data(XCTUnwrap(MachO.component(0, of: pairBlob)))
        let second = try Data(XCTUnwrap(MachO.component(0x1000, of: pairBlob)))
        XCTAssertEqual([first[37], second[37]], [1, 2], "SHA-1 at slot 0, SHA-256 its alternate")
        /// `directory` with the first byte of its requirements' seal changed.
        func unsealed(_ directory: Data) -> Data {
            var directory = directory
            directory[Int(UInt32(bigEndian: directory.load(UInt32.self, at: 16))) - 2 * Int(directory[36])] ^= 0xff
            return directory
        }
        cases += [
            ("alternate-seal", embedded([(0, unsealed(first)), (2, requirements), (0x1000, second), (0x10000, wrapper)], in: both, at: pairSignature), false, [": the requirements blob does not hash to its slot in the sha1 code directory, which Security does not read: it judges the signature by the sha256 one"]),
            ("best-seal", embedded([(0, first), (2, requirements), (0x1000, unsealed(second)), (0x10000, wrapper)], in: both, at: pairSignature), true, [": the requirements blob does not hash to its slot in \(type)"]),
        ]

        cases.append(("appended", embedded([(0, sha256), (2, requirements), (0x10000, wrapper)]) + Data("appended".utf8), true, nil))

        for (name, data, invalid, lines) in cases {
            let file = directory / name
            try data.write(to: file)
            let results = try CDHash.hash(path: file.path)
            XCTAssertEqual(results.map(\.invalid), results.map { _ in invalid }, name)
            XCTAssertEqual(results.map(\.strictOnly), results.map { _ in name == "appended" }, name)
            XCTAssertEqual((try? codesign(["--verify", file.path])) == nil, invalid, "\(name): codesign --verify")
            // What verify says of it, where this test is about the line.
            if let lines {
                XCTAssertEqual(self.verify(file.path).lines.map { $0.replacingOccurrences(of: file.path, with: "") }, lines, name)
            }
        }
        let appended = directory / "appended"
        XCTAssertEqual(try CDHash.hash(path: appended.path, exact: true).map(\.invalid), [false])
    }

    /**
     The index as the kernel walks it, where Security stops at the first alternate missing:

     - a code directory whose identifier offset is 0, or whose magic is not a directory's, which Security loads
       and the kernel refuses the signature for;
     - a directory past a gap in the alternates, which Security never loads and the kernel counts, two of one hash
       type then;
     - an entry at offset 0;
     - slot 0 entered three times, which the kernel counts as three;
     - a constraint slot entered twice, or holding another magic than a launch constraint's;
     - a hash type entered twice, which the kernel refuses only when the second meets the first as its best so
       far, as it ranks them in the order of the index;
     - a directory shorter than the fields the kernel reads.
     */
    func testTheIndexAsTheKernelWalksItIsNamed() throws {
        let directory = try self.directory("index")
        let signed = directory / "signed"
        try self.program("x86_64", in: directory).write(to: signed)
        _ = try codesign(["-s", "-", "--signature-size", "12000", signed.path])
        let program = try Data(contentsOf: signed)
        let image = try XCTUnwrap(MachO(File(data: program)))
        let signature = try XCTUnwrap(image.findCodeSignature())
        let superblob = try image.signingData(signature)
        let sha256 = try Data(XCTUnwrap(MachO.component(0, of: superblob)))
        let requirements = try Data(XCTUnwrap(MachO.component(2, of: superblob)))
        /// `program` with a signature of `blobs`, each at its slot, placed in order; a nil blob is an entry at offset 0.
        func embedded(_ blobs: [(slot: UInt32, blob: Data?)]) -> Data {
            let blob = Self.superblob(blobs)
            var signed = program
            signed.replaceSubrange(signature.offset ..< signature.offset + blob.count, with: blob)
            return signed
        }
        var unnamed = sha256
        unnamed.store(UInt32(0).bigEndian, at: 20)
        XCTAssertEqual(try self.verify(embedded([(0, unnamed), (2, requirements)]), "unnamed", in: directory).lines, [": the code directory the index places at slot 0x0 is one the kernel refuses the signature for: its identifier offset is 0"])
        var mismagic = sha256
        mismagic.store(UInt32(0xfade_0c03).bigEndian, at: 0)
        XCTAssertEqual(try self.verify(embedded([(0, mismagic), (2, requirements)]), "mismagic", in: directory).lines, [": the code directory the index places at slot 0x0 is one the kernel refuses the signature for: its magic is 0xfade0c03, not 0xfade0c02"])
        XCTAssertEqual(try self.verify(embedded([(0, sha256), (2, requirements), (0x1001, sha256)]), "gap", in: directory).lines, [
            ": the code directory the index places at slot 0x1001 lies past a gap in the alternates: Security never loads it, the kernel validates it and may read the signature by it",
            ": 2 code directories of hash type sha256 in the index, which the kernel refuses the signature for",
        ])
        XCTAssertEqual(try self.verify(embedded([(0, sha256), (2, requirements), (0x1000, nil)]), "zero", in: directory).lines, [": the code directory the index places at slot 0x1000 at offset 0, the superblob's own header, which the kernel refuses the signature for"])
        // Slot 0 three times over: Security reads the first, the kernel counts three of one hash type, said once.
        XCTAssertEqual(try self.verify(embedded([(0, sha256), (0, sha256), (0, sha256), (2, requirements)]), "thrice", in: directory).lines, [": 3 code directories of hash type sha256 in the index, which the kernel refuses the signature for"])
        // A constraint slot entered twice, and a constraint under another magic than a launch constraint's: the
        // kernel refuses the signature for either; the first entry's blob is what Security would read, unsealed here.
        /// A blob of `magic` over `payload`.
        func blob(_ magic: UInt32, _ payload: String) -> Data {
            var blob = Data()
            [magic, UInt32(8 + payload.utf8.count)].forEach { blob.appendUInt32BE($0) }
            return blob + Data(payload.utf8)
        }
        let unsealed = ": the launch constraint on the process is not sealed by the sha256 code directory"
        XCTAssertEqual(try self.verify(embedded([(0, sha256), (2, requirements), (8, blob(0xfade_8181, "one")), (8, blob(0xfade_8181, "two"))]), "constraints", in: directory).lines, [": 2 entries for slot 8 in the index, which the kernel refuses the signature for", unsealed])
        XCTAssertEqual(try self.verify(embedded([(0, sha256), (2, requirements), (8, blob(0x1234_5678, "one"))]), "constraint-magic", in: directory).lines, [": the magic of the launch constraint on the process is 0x12345678, not 0xfade8181, which the kernel refuses the signature for", unsealed])

        // A hash type entered twice is refused when the second meets the first as the kernel's best so far, and
        // taken when a stronger one came between or before. Here: SHA-1 at slot 0 and SHA-256 its alternate, then
        // one of them again, past a gap, where Security loads none, or before the other in the index.
        let twice = directory / "twice"
        try self.program("x86_64", in: directory).write(to: twice)
        _ = try codesign(["-s", "-", "--signature-size", "12000", "--digest-algorithm=sha1,sha256", twice.path])
        let both = try Data(contentsOf: twice)
        let pair = try XCTUnwrap(MachO(File(data: both)))
        let pairSignature = try XCTUnwrap(pair.findCodeSignature())
        let pairBlob = try pair.signingData(pairSignature)
        let weak = try Data(XCTUnwrap(MachO.component(0, of: pairBlob)))
        let strong = try Data(XCTUnwrap(MachO.component(0x1000, of: pairBlob)))
        XCTAssertEqual([weak[37], strong[37]], [1, 2], "SHA-1 at slot 0, SHA-256 its alternate")
        /// The two-directory program with a signature of `blobs`, each at its slot, placed in order.
        func ranked(_ blobs: [(slot: UInt32, blob: Data?)]) -> Data {
            Self.embedding(blobs, in: both, at: pairSignature)
        }
        let gap = ": the code directory the index places at slot 0x1002 lies past a gap in the alternates: Security never loads it, the kernel validates it and may read the signature by it"
        XCTAssertEqual(try self.verify(ranked([(0, weak), (2, requirements), (0x1000, strong), (0x1002, weak)]), "weak-after", in: directory).lines, [gap, ": 2 code directories of hash type sha1 in the index, which the kernel takes: a stronger one is entered before the second"])
        XCTAssertEqual(try self.verify(ranked([(0, weak), (2, requirements), (0x1000, strong), (0x1002, strong)]), "strong-after", in: directory).lines, [gap, ": 2 code directories of hash type sha256 in the index, which the kernel refuses the signature for"])
        XCTAssertEqual(try self.verify(ranked([(0, weak), (0x1002, weak), (2, requirements), (0x1000, strong)]), "weak-before", in: directory).lines, [gap, ": 2 code directories of hash type sha1 in the index, which the kernel refuses the signature for"])

        // A directory shorter than the fields the kernel reads, by the length it declares.
        var short = Data(sha256.prefix(0x40))
        short.store(UInt32(0x40).bigEndian, at: 4)
        XCTAssertEqual(try self.verify(embedded([(0, sha256), (2, requirements), (0x1001, short)]), "short", in: directory).lines, [": the code directory the index places at slot 0x1001 is one the kernel refuses the signature for: it is 0x40 bytes, shorter than the 0x70 the kernel reads"])
    }

    /**
     A load command shorter than its structure is named, where it fed no rule: an `LC_SEGMENT_64` without room for its
     header, after `__LINKEDIT` where the parser stops checking, and an `LC_BUILD_VERSION` without room for its tool
     count, which does not make the image undated.
     */
    func testACommandShorterThanItsStructureIsNamed() throws {
        let directory = try self.directory("short-commands")
        var segment = Data()
        segment.appendUInt32(UInt32(LC_SEGMENT_64)); segment.appendUInt32(48); try segment.append(XCTUnwrap("__DATA".data(using: .utf8)) + Data(count: 10)); segment.append(Data(count: 24))
        var build = Data()
        build.appendUInt32(UInt32(LC_BUILD_VERSION)); build.appendUInt32(16); build.appendUInt32(UInt32(PLATFORM_MACOS)); build.appendUInt32(0x000e_0000)
        let file = try self.crafted("short", in: directory, size: 0x2000, segments: [("__TEXT", 0x1000, 0x1000, 0, 0x1000, 5), ("__LINKEDIT", 0x2000, 0x1000, 0x1000, 0x1000, 1)], commands: [segment, build])
        self.assertVerify(file.path, [
            "\(file.path): load command #2, LC_SEGMENT_64, is 0x30 bytes, not its structure's 0x48, which dyld refuses",
            "\(file.path): load command #3, LC_BUILD_VERSION, is 0x10 bytes, not its structure's 0x18, which dyld refuses",
            "\(file.path): no external symbol table",
            "\(file.path): __TEXT has no sections",
            "\(file.path): no LC_MAIN nor LC_UNIXTHREAD for an executable",
            "\(file.path): no LC_UUID",
            "\(file.path): no MH_DYLDLINK: a static executable",
        ])
    }

    /**
     Security's `validateStructure` ends the image at the first `__LINKEDIT` or `LC_SYMTAB`: an image with neither is
     "invalid structure" to it, which codesign refuses under its default strict validation, signing and verifying
     alike.
     */
    func testAnImageNothingEndsIsNamed() throws {
        let directory = try self.directory("structure")
        let file = try self.crafted("structure", in: directory, size: 0x1000, segments: [("__TEXT", 0x1000, 0x1000, 0, 0x1000, 5)])
        XCTAssertTrue(self.verify(file.path).lines.contains("\(file.path): neither a __LINKEDIT segment nor an LC_SYMTAB ends the image, which codesign's strict validation refuses"))
        XCTAssertFalse(try execute("/usr/bin/codesign", ["-s", "-", file.path]))
    }

    /**
     dyld takes the last segment named `__LINKEDIT`, so an empty decoy before the real one silences none of the
     `__LINKEDIT` rules: a symbol table outside the last one is named, where the first, empty, said nothing of it.
     */
    func testADecoyLinkeditSilencesNothing() throws {
        let directory = try self.directory("decoy")
        var symtab = Data()
        [UInt32(LC_SYMTAB), 24, 0x800, 1, 0x1800, 0x10].forEach { symtab.appendUInt32($0) }
        let file = try self.crafted("decoy", in: directory, size: 0x2000, segments: [("__TEXT", 0x1000, 0x1000, 0, 0x1000, 5), ("__LINKEDIT", 0x3000, 0, 0x2000, 0, 1), ("__LINKEDIT", 0x2000, 0x1000, 0x1000, 0x1000, 1)], commands: [symtab])
        let lines = self.verify(file.path).lines
        XCTAssertTrue(lines.contains("\(file.path): 2 segments named __LINKEDIT"), lines.joined(separator: "\n"))
        XCTAssertTrue(lines.contains("\(file.path): the symbol table at 0x800 with size 0x10 lies outside __LINKEDIT"), lines.joined(separator: "\n"))
    }

    /**
     The padding the linker leaves before a section, up to its alignment, is no payload; a section's align field is
     the image's own, so the exemption stops at a page: a megabyte of bytes before a section aligned to 2^20 is named.
     */
    func testAnAlignFieldHidesNoPayload() throws {
        let directory = try self.directory("align")
        var segment = Data()
        [UInt32(LC_SEGMENT_64), 72 + 80].forEach { segment.appendUInt32($0) }
        segment.append(Data("__TEXT".utf8)); segment.append(Data(count: 10))
        [UInt64(0x1000), 0x101000, 0, 0x101000].forEach { segment.appendUInt64($0) }
        [UInt32(5), 5, 1, 0].forEach { segment.appendUInt32($0) }
        segment.append(Data("__text".utf8)); segment.append(Data(count: 10))
        segment.append(Data("__TEXT".utf8)); segment.append(Data(count: 10))
        [UInt64(0x101000), 0x10].forEach { segment.appendUInt64($0) }
        [UInt32(0x100000), 20, 0, 0, 0x8000_0400, 0, 0, 0].forEach { segment.appendUInt32($0) } // offset, align 2^20, reloff, nreloc, flags, reserved
        let file = try self.crafted("align", in: directory, size: 0x101000, segments: [], commands: [segment])
        var data = try Data(contentsOf: file)
        data.replaceSubrange(0x1000 ..< 0x100000, with: Data(repeating: 0x41, count: 0xff000))
        try data.write(to: file)
        XCTAssertTrue(self.verify(file.path).lines.contains("\(file.path): 0xff000 bytes of __TEXT that no section covers are not zero, the first at 0x1000"))
    }

    /**
     The sections' lines name a few sections and count the rest, as the table's lines do: twelve sections laid outside
     their segment name eight and count the other four, where a crafted table of a million would be six lines each.
     */
    func testTheSectionLinesAreCounted() throws {
        let directory = try self.directory("sections")
        let count = 12
        var segment = Data()
        [UInt32(LC_SEGMENT_64), UInt32(72 + count * 80)].forEach { segment.appendUInt32($0) }
        segment.append(Data("__TEXT".utf8)); segment.append(Data(count: 10))
        [UInt64(0x1000), 0x1000, 0, 0x1000].forEach { segment.appendUInt64($0) }
        [UInt32(5), 5, UInt32(count), 0].forEach { segment.appendUInt32($0) }
        for index in 0 ..< count {
            let name = Data("__s\(index)".utf8)
            segment.append(name); segment.append(Data(count: 16 - name.count))
            segment.append(Data("__TEXT".utf8)); segment.append(Data(count: 10))
            [UInt64(0x5000_0000) + UInt64(index) * 0x10, 0x10].forEach { segment.appendUInt64($0) }
            [UInt32(0x100 + index * 0x10), 0, 0, 0, 0, 0, 0, 0].forEach { segment.appendUInt32($0) } // offset, align, reloff, nreloc, flags, reserved
        }
        let file = try self.crafted("sections", in: directory, size: 0x1000, segments: [], commands: [segment])
        self.assertVerify(file.path, ["\(file.path): no external symbol table"] + (0 ..< 8).map { "\(file.path): section __TEXT,__s\($0)'s address range \((0x5000_0000 + $0 * 0x10).hex)...\((0x5000_0010 + $0 * 0x10).hex) lies outside its segment's 0x1000...0x2000" } + [
            "\(file.path): and 4 more lines on 4 more sections or pair of them",
            "\(file.path): no LC_MAIN nor LC_UNIXTHREAD for an executable",
            "\(file.path): no LC_UUID",
            "\(file.path): no MH_DYLDLINK: a static executable",
            "\(file.path): no LC_BUILD_VERSION nor LC_VERSION_MIN_* dates it",
            "\(file.path): neither a __LINKEDIT segment nor an LC_SYMTAB ends the image, which codesign's strict validation refuses",
        ])
    }

    /**
     The table's lines name a few commands and count the rest: a crafted table of ten odd-sized commands, sized other
     than their structure, names eight of each and counts the others, where a line each would be millions. Hidden
     from the loaders, the ten are named by the hiding line alone: no loader reads them, so none of their rules apply.
     */
    func testTheTableLinesAreCounted() throws {
        let directory = try self.directory("counted")
        var odd = Data()
        odd.appendUInt32(UInt32(LC_UUID)); odd.appendUInt32(28); odd.append(Data(count: 20))
        let file = try self.crafted("counted", in: directory, size: 0x1000, segments: [("__TEXT", 0x1000, 0x1000, 0, 0x1000, 5)], commands: Array(repeating: odd, count: 10))
        let rest = [
            "\(file.path): no external symbol table",
            "\(file.path): __TEXT has no sections",
            "\(file.path): no LC_MAIN nor LC_UNIXTHREAD for an executable",
            "\(file.path): no MH_DYLDLINK: a static executable",
            "\(file.path): no LC_BUILD_VERSION nor LC_VERSION_MIN_* dates it",
            "\(file.path): neither a __LINKEDIT segment nor an LC_SYMTAB ends the image, which codesign's strict validation refuses",
        ]
        self.assertVerify(file.path, (1 ... 8).map { "\(file.path): load command #\($0), LC_UUID, has a size 0x1c that is not a multiple of 8" } + [
            "\(file.path): and 2 more load commands with a size that is not a multiple of 8",
        ] + (1 ... 8).map { "\(file.path): load command #\($0), LC_UUID, is 0x1c bytes, not its structure's 0x18, which dyld refuses" } + [
            "\(file.path): and 2 more load commands sized other than their structure",
            "\(file.path): 10 LC_UUID commands",
        ] + rest)

        var data = try Data(contentsOf: file)
        data.store(UInt32(1), at: 16) // ncmds: the segment alone
        try data.write(to: file)
        self.assertVerify(file.path, [
            "\(file.path): ncmds 1 hides the last 10 commands of 11 from the loaders: \(Array(repeating: "LC_UUID", count: 8).joined(separator: ", "))…",
        ] + rest)
    }

    /// The DER of an OID from its bytes.
    private static func oid(_ bytes: [UInt8]) -> Data {
        DER.encode(0x06, Data(bytes))
    }

    /// A CMS attribute of `type` holding `values`: a SEQUENCE of the OID and a SET.
    private static func attribute(_ type: [UInt8], _ values: Data) -> Data {
        DER.encode(0x30, self.oid(type) + DER.encode(0x31, values))
    }

    /// A self-signed code-signing certificate `name`d, made with openssl in `directory` for `days`: its DER, and the
    /// key's path. Skips the test when openssl cannot.
    private static func identity(_ name: String, in directory: URL, days: Int = 30) throws -> (certificate: Data, key: URL) {
        let (configuration, key, pem, der) = (directory / "\(name).cnf", directory / "\(name).key", directory / "\(name).pem", directory / "\(name).der")
        try "[req]\ndistinguished_name = dn\nx509_extensions = ext\nprompt = no\n[dn]\nCN = \(name)\n[ext]\nextendedKeyUsage = codeSigning\nkeyUsage = digitalSignature\nbasicConstraints = CA:FALSE\n".write(to: configuration, atomically: true, encoding: .utf8)
        try XCTSkipUnless(execute("/usr/bin/openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key.path, "-out", pem.path, "-config", configuration.path, "-days", String(days)]), "cannot make a certificate")
        try XCTSkipUnless(execute("/usr/bin/openssl", ["x509", "-in", pem.path, "-outform", "DER", "-out", der.path]), "cannot convert a certificate")
        return try (Data(contentsOf: der), key)
    }

    /**
     A CMS signature over `content` by `certificate` with `key`, laid out as codesign's: the signed attributes are the
     content type, `signingTime` when given, the message digest and `attributes`, which openssl signs under SHA-256
     with RSA, in `directory` as `name`; the certificate rides along.
     */
    private static func cms(over content: Data, certificate: Data, key: URL, signingTime: Date? = nil, attributes: Data = Data(), in directory: URL, _ name: String) throws -> Data {
        // The issuer and serial, from the certificate: a version, the serial, the algorithm, the issuer.
        var reader = DER.Reader(certificate)
        let tbs = try XCTUnwrap(DER.elements(of: XCTUnwrap(DER.elements(of: XCTUnwrap(reader.next()).content)?.first).content))
        let (serial, issuer) = (tbs[1].raw, tbs[3].raw)
        let sha256 = self.oid([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01])
        var signed = self.attribute([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03], self.oid([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01]))
        if let signingTime {
            let formatter = DateFormatter()
            formatter.locale = Locale(identifier: "en_US_POSIX")
            formatter.timeZone = TimeZone(identifier: "UTC")
            formatter.dateFormat = "yyMMddHHmmss'Z'"
            signed += self.attribute([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x05], DER.encode(0x17, Data(formatter.string(from: signingTime).utf8)))
        }
        signed += self.attribute([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04], DER.encode(0x04, Data(SHA256.hash(data: content)))) + attributes
        let (toSign, signatureFile) = (directory / "\(name).attrs", directory / "\(name).sig")
        try DER.encode(0x31, signed).write(to: toSign)
        try XCTSkipUnless(execute("/usr/bin/openssl", ["dgst", "-sha256", "-sign", key.path, "-out", signatureFile.path, toSign.path]), "cannot sign")
        let rsa = DER.encode(0x30, self.oid([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]) + DER.encode(0x05, Data()))
        let signerInfo = try DER.encode(0x30, DER.encode(0x02, Data([1])) + DER.encode(0x30, issuer + serial) + DER.encode(0x30, sha256 + DER.encode(0x05, Data())) + DER.encode(0xa0, signed) + rsa + DER.encode(0x04, Data(contentsOf: signatureFile)))
        let signedData = DER.encode(0x30, DER.encode(0x02, Data([1])) + DER.encode(0x31, DER.encode(0x30, sha256 + DER.encode(0x05, Data()))) + DER.encode(0x30, self.oid([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01])) + DER.encode(0xa0, certificate) + DER.encode(0x31, signerInfo))
        return DER.encode(0x30, self.oid([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02]) + DER.encode(0xa0, signedData))
    }

    /// `cms` with its signer's SignerInfo `times` over, the enclosing lengths rewritten.
    private static func withSigners(_ cms: Data, times: Int) throws -> Data {
        var reader = DER.Reader(cms)
        let contentInfo = try XCTUnwrap(reader.next())
        let outer = try XCTUnwrap(DER.elements(of: contentInfo.content))
        let signedData = try XCTUnwrap(DER.elements(of: outer[1].content)?.first)
        var fields = try XCTUnwrap(DER.elements(of: signedData.content))
        let signerInfo = try XCTUnwrap(DER.elements(of: XCTUnwrap(fields.popLast()).content)?.first)
        let rewritten = DER.encode(0x31, Array(repeating: signerInfo.raw, count: times).reduce(Data(), +))
        return DER.encode(0x30, outer[0].raw + DER.encode(0xa0, DER.encode(0x30, fields.map(\.raw).reduce(Data(), +) + rewritten)))
    }

    /// `program` with its signature replaced by a superblob holding `directory` in slot 0, `requirements` in slot 2
    /// and `cms` wrapped in slot 0x10000, in the room `signature` has.
    private static func embedding(_ directory: Data, _ requirements: Data, _ cms: Data, in program: Data, at signature: MachO.Span) -> Data {
        var wrapped = Data()
        [0xfade_0b01, UInt32(8 + cms.count)].forEach { wrapped.appendUInt32BE($0) }
        wrapped += cms
        var blob = Data()
        let (first, second) = (36 + directory.count, 36 + directory.count + requirements.count)
        [0xfade_0cc0, UInt32(second + wrapped.count), 3, 0, 36, 2, UInt32(first), 0x10000, UInt32(second)].forEach { blob.appendUInt32BE($0) }
        blob += directory + requirements + wrapped
        XCTAssertLessThanOrEqual(blob.count, signature.size)
        var signed = program
        signed.replaceSubrange(signature.offset ..< signature.offset + blob.count, with: blob)
        return signed
    }

    /// A superblob of `blobs`, each at its slot, placed in order; a nil blob is an entry at offset 0.
    private static func superblob(_ blobs: [(slot: UInt32, blob: Data?)]) -> Data {
        var blob = Data()
        var offset = 12 + 8 * blobs.count
        [0xfade_0cc0, UInt32(offset + blobs.reduce(0) { $0 + ($1.blob?.count ?? 0) }), UInt32(blobs.count)].forEach { blob.appendUInt32BE($0) }
        for entry in blobs {
            blob.appendUInt32BE(entry.slot); blob.appendUInt32BE(entry.blob == nil ? 0 : UInt32(offset))
            offset += entry.blob?.count ?? 0
        }
        blobs.forEach { blob += $0.blob ?? Data() }
        return blob
    }

    /// The blobs of `superblob` as its index places them, in the order of its entries: what `superblob(_:)` takes.
    private static func blobs(of superblob: Data) -> [(slot: UInt32, blob: Data?)] {
        /// The big-endian word at `offset` of the superblob.
        func word(_ offset: Int) -> Int {
            Int(UInt32(bigEndian: superblob.load(UInt32.self, at: offset)))
        }
        return (0 ..< word(8)).map { entry in
            let offset = word(12 + 8 * entry + 4)
            return (UInt32(word(12 + 8 * entry)), Data(superblob[offset ..< offset + word(offset + 4)]))
        }
    }

    /// `program` with its signature replaced by a superblob of `blobs`, in the room `signature` has.
    private static func embedding(_ blobs: [(slot: UInt32, blob: Data?)], in program: Data, at signature: MachO.Span) -> Data {
        let blob = self.superblob(blobs)
        XCTAssertLessThanOrEqual(blob.count, signature.size)
        var signed = program
        signed.replaceSubrange(signature.offset ..< signature.offset + blob.count, with: blob)
        return signed
    }

    /// The first slice's code directory and CMS signature of the signed file at `path`.
    private static func signature(of path: String) throws -> (directory: Data, cms: Data) {
        let file = try File(path: path)
        let image: MachO = switch try Universal.open(file) {
        case let .fat(archs): try XCTUnwrap(MachO(file, offset: XCTUnwrap(archs.first).offset, length: XCTUnwrap(archs.first).length))
        case let .thin(image): image
        case .notMachO: throw XCTSkip("\(path) is not Mach-O")
        }
        let superblob = try image.signingData(XCTUnwrap(image.findCodeSignature()))
        return try (Data(XCTUnwrap(MachO.component(0, of: superblob))), Data(XCTUnwrap(MachO.component(0x10000, of: superblob)).dropFirst(8)))
    }

    /// `cms` with `token` as its signer's `id-aa-timeStampToken` unsigned attribute, the enclosing lengths rewritten.
    private static func timestamped(_ cms: Data, with token: Data) throws -> Data {
        func parts(_ data: Data) throws -> [DER.Element] {
            try XCTUnwrap(DER.elements(of: data))
        }
        var reader = DER.Reader(cms)
        let contentInfo = try XCTUnwrap(reader.next())
        let outer = try parts(contentInfo.content)
        let signedData = try XCTUnwrap(parts(outer[1].content).first)
        var fields = try parts(signedData.content)
        let signerInfos = try XCTUnwrap(fields.popLast())
        let signerInfo = try XCTUnwrap(parts(signerInfos.content).first)
        let attribute = DER.encode(0x30, DER.encode(0x06, Data([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x0e])) + DER.encode(0x31, token))
        let rewritten = DER.encode(0x31, DER.encode(0x30, signerInfo.content + DER.encode(0xa1, attribute)))
        return DER.encode(0x30, outer[0].raw + DER.encode(0xa0, DER.encode(0x30, fields.map(\.raw).reduce(Data(), +) + rewritten)))
    }

    /**
     Expiry as Security tolerates it: a chain expired, or not yet valid, at the date the signer claims is tried again
     with expiry allowed and passes, as codesign passes it, unless the directory's flags carry `CS_ENFORCE_EXPIRATION`,
     codesign -o expires, which refuses it; the flag refuses nothing of a chain valid at that date.
     */
    func testExpiryIsToleratedAsSecurityTolerates() throws {
        let directory = try self.directory("expiry")
        let signed = directory / "signed"
        try self.program("x86_64", in: directory).write(to: signed)
        _ = try codesign(["-s", "-", "--signature-size", "12000", signed.path])
        let program = try Data(contentsOf: signed)
        let image = try XCTUnwrap(MachO(File(data: program)))
        let signature = try XCTUnwrap(image.findCodeSignature())
        let superblob = try image.signingData(signature)
        var directoryBlob = try Data(XCTUnwrap(MachO.component(0, of: superblob)))
        directoryBlob.store((UInt32(bigEndian: directoryBlob.load(UInt32.self, at: 12)) & ~UInt32(2)).bigEndian, at: 12) // CS_ADHOC out
        let requirements = try Data(XCTUnwrap(MachO.component(2, of: superblob)))
        let (certificate, key) = try Self.identity("Fashion Self", in: directory, days: 30)
        let gatekeeper = ": signed outside Apple's chains by Fashion Self, which Gatekeeper refuses"
        for (name, claimed) in [("expired", Date(timeIntervalSinceNow: 60 * 86400)), ("early", Date(timeIntervalSinceNow: -60 * 86400))] {
            let cms = try Self.cms(over: directoryBlob, certificate: certificate, key: key, signingTime: claimed, in: directory, name)
            XCTAssertEqual(try self.verify(Self.embedding(directoryBlob, requirements, cms, in: program, at: signature), name, in: directory).lines, [gatekeeper], name)
            XCTAssertTrue(try execute("/usr/bin/codesign", ["--verify", (directory / name).path]), name)
        }

        var enforcing = directoryBlob
        enforcing.store((UInt32(bigEndian: enforcing.load(UInt32.self, at: 12)) | 0x400).bigEndian, at: 12)
        let enforced = try Self.cms(over: enforcing, certificate: certificate, key: key, signingTime: Date(timeIntervalSinceNow: 60 * 86400), in: directory, "enforced")
        XCTAssertEqual(try self.verify(Self.embedding(enforcing, requirements, enforced, in: program, at: signature), "enforced", in: directory).lines, [": the signer's certificate chain does not hold at the date it claims: \"“Fashion Self” certificate is expired\", which the code directory's CS_ENFORCE_EXPIRATION flag refuses where Security tolerates it"])
        XCTAssertFalse(try execute("/usr/bin/codesign", ["--verify", (directory / "enforced").path]))
        let current = try Self.cms(over: enforcing, certificate: certificate, key: key, signingTime: Date(), in: directory, "current")
        XCTAssertEqual(try self.verify(Self.embedding(enforcing, requirements, current, in: program, at: signature), "current", in: directory).lines, [gatekeeper])
        XCTAssertTrue(try execute("/usr/bin/codesign", ["--verify", (directory / "current").path]))
    }

    /**
     A secure timestamp is read from the signer's token and verified here, with no network: the token's imprint must
     be the signature's digest, and its chain must build to the system's anchors, or to the ones given. A token a
     timestamp authority of the test's own signed, with openssl, verifies under its certificate as the anchor, with its
     date, and not under the system's; one taken over other bytes does not. Security's decoder verifies a token
     against the system's anchors as part of the signature, so one from the test's authority spliced behind Apple's
     own signature is an invalid signature to it.
     */
    func testASecureTimestampIsVerifiedOffline() throws {
        let directory = try self.directory("timestamp")
        let openssl = "/usr/bin/openssl"
        let (signerKey, signerCertificate, tsaKey, tsaCertificate) = (directory / "signer.key", directory / "signer.pem", directory / "tsa.key", directory / "tsa.pem")
        let signerConfiguration = directory / "signer.cnf"
        try "[req]\ndistinguished_name = dn\nx509_extensions = ext\nprompt = no\n[dn]\nCN = Fashion Self\n[ext]\nextendedKeyUsage = codeSigning\nkeyUsage = digitalSignature\nbasicConstraints = CA:FALSE\n".write(to: signerConfiguration, atomically: true, encoding: .utf8)
        let tsaConfiguration = directory / "tsa.cnf"
        try """
        [req]
        distinguished_name = dn
        x509_extensions = ext
        prompt = no
        [dn]
        CN = Fashion Timestamps
        [ext]
        extendedKeyUsage = critical,timeStamping
        keyUsage = digitalSignature
        basicConstraints = CA:FALSE
        [tsa]
        default_tsa = stamps
        [stamps]
        dir = \(directory.path)
        serial = $dir/serial
        signer_cert = $dir/tsa.pem
        signer_key = $dir/tsa.key
        default_policy = 1.2.3.4
        other_policies = 1.2.3.4
        digests = sha256
        accuracy = secs:1
        ordering = no
        tsa_name = no
        ess_cert_id_chain = no

        """.write(to: tsaConfiguration, atomically: true, encoding: .utf8)
        try "01\n".write(to: directory / "serial", atomically: true, encoding: .utf8)
        try XCTSkipUnless(execute(openssl, ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", signerKey.path, "-out", signerCertificate.path, "-config", signerConfiguration.path, "-days", "30"]), "cannot make a certificate")
        try XCTSkipUnless(execute(openssl, ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", tsaKey.path, "-out", tsaCertificate.path, "-config", tsaConfiguration.path, "-days", "30"]), "cannot make a certificate")
        try XCTSkipUnless(execute(openssl, ["x509", "-in", tsaCertificate.path, "-outform", "DER", "-out", (directory / "tsa.der").path]), "cannot convert a certificate")
        let authority = try XCTUnwrap(SecCertificateCreateWithData(nil, Data(contentsOf: directory / "tsa.der") as CFData))

        let (content, cmsFile) = (directory / "content.bin", directory / "cms.der")
        try Data("the code directory".utf8).write(to: content)
        try XCTSkipUnless(execute(openssl, ["cms", "-sign", "-binary", "-in", content.path, "-signer", signerCertificate.path, "-inkey", signerKey.path, "-outform", "DER", "-out", cmsFile.path]), "cannot sign")
        let cms = try Data(contentsOf: cmsFile)
        XCTAssertNil(Signer.timestamp(in: cms), "no token yet")

        /// A token over `data`, from the test's authority, with its certificate in it.
        func token(over data: Data, _ name: String) throws -> Data {
            let (input, query, reply, token) = (directory / "\(name).bin", directory / "\(name).tsq", directory / "\(name).tsr", directory / "\(name).tst")
            try data.write(to: input)
            try XCTSkipUnless(execute(openssl, ["ts", "-query", "-data", input.path, "-sha256", "-no_nonce", "-cert", "-out", query.path]), "cannot ask for a timestamp")
            try XCTSkipUnless(execute(openssl, ["ts", "-reply", "-queryfile", query.path, "-config", tsaConfiguration.path, "-out", reply.path]), "cannot timestamp")
            try XCTSkipUnless(execute(openssl, ["ts", "-reply", "-in", reply.path, "-token_out", "-out", token.path]), "cannot take the token out")
            return try Data(contentsOf: token)
        }
        let signature = try XCTUnwrap(Signer.signature(in: cms))
        let stamped = try Self.timestamped(cms, with: token(over: signature, "signature"))
        saveFixture(stamped)
        XCTAssertNotNil(Signer.signatureAndToken(in: stamped))
        XCTAssertNil(Signer.timestamp(in: stamped), "the authority is no anchor of the system's")
        let date = try XCTUnwrap(Signer.timestamp(in: stamped, anchors: [authority])).date
        XCTAssertLessThan(abs(date.timeIntervalSinceNow), 600)
        let other = try Self.timestamped(cms, with: token(over: Data("other bytes".utf8), "other"))
        XCTAssertNil(Signer.timestamp(in: other, anchors: [authority]), "a token over other bytes")

        // Security's decoder verifies the token too, against the system's anchors: behind Apple's own signature on
        // ls, a token from the test's authority is an invalid signature to it, before any rule on the token's chain.
        let ls = try Self.signature(of: "/bin/ls")
        XCTAssertEqual(try Signer(cms: ls.cms, over: ls.directory).kind, .apple)
        let appleStamped = try Self.timestamped(ls.cms, with: token(over: XCTUnwrap(Signer.signature(in: ls.cms)), "apple"))
        XCTAssertThrowsError(try Signer(cms: appleStamped, over: ls.directory)) { error in
            XCTAssertEqual(error as? Signer.Failure, .invalidSignature)
        }
    }
}
