@testable import fashion
import MachO
import XCTest

/**
 `verify` names what is odd about a Mach-O, one line each, and nothing about one with nothing to say.
 */
private extension Data {
    /// `value` stored little-endian at `offset`, over the bytes there.
    mutating func store<T: FixedWidthInteger>(_ value: T, at offset: Int) {
        Swift.withUnsafeBytes(of: value.littleEndian) { self.replaceSubrange(offset ..< offset + MemoryLayout<T>.size, with: $0) }
    }

    /// The little-endian integer at `offset`.
    func load<T: FixedWidthInteger>(_: T.Type, at offset: Int) -> T {
        T(littleEndian: self.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: offset, as: T.self) })
    }
}

final class VerifierTests: XCTestCase {
    private func directory(_ name: String) throws -> URL {
        let url = URL(fileURLWithPath: ".build/tests/VerifierTests/\(name)")
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
     Segments out of order in the file and in memory, as a crafted image lays them, an executable with no entry point
     and no version command: each is a line, in the order the headers are read.
     */
    func testACraftedImageHasItsOddsNamed() throws {
        let directory = try self.directory("crafted")
        let file = try self.crafted("crafted", in: directory, size: 0x1110, segments: [("__DATA", 0x2000, 0x1000, 0x1000, 0x100, 3), ("__TEXT", 0x1000, 0x1000, 0, 0x1000, 5), ("__LINKEDIT", 0x3000, 0x1000, 0x1100, 0x10, 1)])
        self.assertVerify(file.path, [
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
            "\(file.path): filetype unknown(3740925954), which no loader knows",
            "\(file.path): no LC_BUILD_VERSION nor LC_VERSION_MIN_* dates it",
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
            "\(file.path): segment __DATA's address 0xffffffffffffffff and vmsize 0x2 wrap around the address space",
            "\(file.path): __TEXT has no sections",
            "\(file.path): no LC_MAIN nor LC_UNIXTHREAD for an executable",
            "\(file.path): no LC_UUID",
            "\(file.path): no MH_DYLDLINK: a static executable",
            "\(file.path): no LC_BUILD_VERSION nor LC_VERSION_MIN_* dates it",
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
     signature that came out, where `unsign` restores it as the linker or `strip` left it and leaves no such trace.
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
        XCTAssertEqual(Unsigner.lines(for: signed.path, write: false, reporter: Reporter(console: Console())).map(\.text), [signed.path + "_unsigned"])
        self.assertVerify(signed.path + "_unsigned", [])
    }

    /**
     A file UPX packed is named for it, by a modified UPX with its marker, and signed after packing as such, the
     signature hiding what UPX left from a look at the file as it is.
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

    /// An `LC_UNIXTHREAD` command with `x86_64`'s thread state, its rip at `rip`; `flavor` and `count` as given otherwise.
    private func unixthread(rip: UInt64, flavor: UInt32 = 4, count: UInt32 = 42) -> Data {
        var command = Data()
        command.appendUInt32(UInt32(LC_UNIXTHREAD))
        command.appendUInt32(16 + 42 * 4)
        command.appendUInt32(flavor)
        command.appendUInt32(count)
        for register in 0 ..< 21 {
            command.appendUInt64(register == 16 ? rip : 0)
        }
        return command
    }

    /**
     The table as the loaders walk it: `ncmds` short of the commands the table holds names the commands hidden from
     the loaders, one more than it holds is named too, as is a command size that is not a multiple of 4, a 32-bit
     `LC_SEGMENT` in a 64-bit image, the reserved field holding anything, a command the loaders take once twice,
     `LC_DYSYMTAB` without `LC_SYMTAB`, and `LC_MAIN` beside `LC_UNIXTHREAD`.
     */
    func testTheTableAsTheLoadersWalkItIsNamed() throws {
        let directory = try self.directory("table")
        let program = try self.program("x86_64", in: directory)
        let commands = try XCTUnwrap(MachO(File(data: program))).loadCommands

        var short = program
        short.store(UInt32(commands.count - 1), at: 16)
        XCTAssertEqual(try self.verify(short, "short", in: directory).lines, try [": ncmds \(commands.count - 1) hides the last 1 command of \(commands.count) from the loaders: \(XCTUnwrap(commands.last).name)"])
        var long = program
        long.store(UInt32(commands.count + 1), at: 16)
        XCTAssertEqual(try self.verify(long, "long", in: directory).lines, [": ncmds \(commands.count + 1) exceeds the \(commands.count) commands the table holds"])

        var odd = program
        let last = try XCTUnwrap(commands.last)
        odd.store(UInt32(last.data.count + 2), at: last.data.startIndex + 4)
        try odd.store(UInt32(XCTUnwrap(MachO(File(data: program))).sizeofcmds + 2), at: 20)
        XCTAssertEqual(try self.verify(odd, "odd", in: directory).lines, [": load command #\(commands.count - 1), \(last.name), has a size \((last.data.count + 2).hex) that is not a multiple of 8"])

        var segment32 = Data()
        segment32.appendUInt32(UInt32(LC_SEGMENT)); segment32.appendUInt32(56); segment32.append(Data(count: 48))
        var reserved = self.appending(segment32, to: program)
        reserved.store(UInt32(0xdead_beef), at: 28)
        XCTAssertEqual(try self.verify(reserved, "reserved", in: directory).lines, [
            ": LC_SEGMENT in a 64-bit image",
            ": the header's reserved field holds 0xdeadbeef",
            ": segment 's command size 0x38 does not hold its 0 sections",
            ": a segment with an empty name",
            ": __LINKEDIT is not the last segment",
        ])

        let symtab = try self.command(UInt32(LC_SYMTAB), in: program)
        let twice = try self.verify(self.appending(symtab.data, to: program), "twice", in: directory).lines
        XCTAssertEqual(twice.first, ": 2 LC_SYMTAB commands")
        XCTAssertTrue(twice.contains(": the symbol table and the symbol table overlap in __LINKEDIT"))
        var without = program
        without.store(UInt32(0x7f), at: symtab.data.startIndex)
        XCTAssertEqual(try self.verify(without, "without", in: directory).lines.first, ": LC_DYSYMTAB without LC_SYMTAB")

        let text = try self.section("__TEXT", "__text", in: program)
        let both = self.appending(self.unixthread(rip: program.load(UInt64.self, at: text + 32)), to: program)
        XCTAssertEqual(try self.verify(both, "both", in: directory).lines, [": LC_MAIN and LC_UNIXTHREAD both"])
    }

    /**
     Segments and sections as dyld's `validSegments` reads them, and as a disassembler does: a segment's name with
     bytes after its NUL, a section's name that is not ASCII, a section's file offset not where its address lays it,
     which overlaps the next and leaves bytes no section covers, a section's address range outside its segment, which
     leaves the entry in no section, a segment both writable and executable, two segments of one name, a segment's
     file offset off the page, `__TEXT` with room past its file size, and a segment flagged Apple-protected.
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
        XCTAssertEqual(try self.verify(protected, "protected", in: directory).lines, [": segment __TEXT is Apple-protected (SG_PROTECTED_VERSION_1): the kernel decrypts it past its first 0x3000 bytes as it maps it"])
    }

    /**
     Sections as the live dyld's `Header::validSections` reads them: an address not aligned to the align field, a
     section with content but no file offset, two sections sharing addresses.
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
    }

    /**
     The entry point as dyld's `validMain` finds it: `LC_MAIN`'s `entryoff` in a segment that is not executable,
     `LC_UNIXTHREAD`'s pc there, a thread state that is not the architecture's, an entry in no section of `__TEXT`,
     and one in a section of it that holds no code, where a stub section does.
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
     executable, encryption, an executable not position independent, with a flat namespace and an executable stack,
     a static one, and one the kernel refuses for want of `MH_PIE` on arm64.
     */
    func testWhatTheImageLinksIsNamed() throws {
        let directory = try self.directory("links")
        let program = try self.program("x86_64", in: directory)

        var uuid = program
        try uuid.store(UInt32(0x7f), at: self.command(UInt32(LC_UUID), in: program).data.startIndex)
        XCTAssertEqual(try self.verify(uuid, "uuid", in: directory).lines, [": no LC_UUID"])

        var dylinker = program
        let command = try self.command(UInt32(LC_LOAD_DYLINKER), in: program)
        let name = try XCTUnwrap(program.range(of: Data("/usr/lib/dyld".utf8), in: command.data.startIndex ..< command.data.endIndex))
        dylinker.replaceSubrange(name, with: "/usr/lib/dylX".utf8)
        XCTAssertEqual(try self.verify(dylinker, "dylinker", in: directory).lines, [": LC_LOAD_DYLINKER names /usr/lib/dylX, not /usr/lib/dyld"])

        var environment = Data()
        let variable = Data("DYLD_INSERT_LIBRARIES=/tmp/evil.dylib".utf8) + Data(count: 7)
        environment.appendUInt32(UInt32(LC_DYLD_ENVIRONMENT)); environment.appendUInt32(UInt32(12 + variable.count)); environment.appendUInt32(12); environment.append(variable)
        XCTAssertEqual(try self.verify(self.appending(environment, to: program), "environment", in: directory).lines, [": LC_DYLD_ENVIRONMENT sets DYLD_INSERT_LIBRARIES=/tmp/evil.dylib"])

        var unterminated = program
        let dylib = try self.command(UInt32(LC_LOAD_DYLIB), in: program)
        let offset = Int(program.load(UInt32.self, at: dylib.data.startIndex + 8))
        unterminated.replaceSubrange(dylib.data.startIndex + offset ..< dylib.data.endIndex, with: Data(repeating: UInt8(ascii: "x"), count: dylib.data.count - offset))
        XCTAssertEqual(try self.verify(unterminated, "unterminated", in: directory).lines, [": LC_LOAD_DYLIB's name is not terminated inside the command", ": links no dylib"])

        var id = Data()
        let install = Data("/tmp/evil.dylib".utf8) + Data(count: 1)
        [UInt32(LC_ID_DYLIB), UInt32(24 + install.count), 24, 0, 0x10000, 0x10000].forEach { id.appendUInt32($0) }
        id.append(install)
        XCTAssertEqual(try self.verify(self.appending(id, to: program), "id", in: directory).lines, [": LC_ID_DYLIB /tmp/evil.dylib in an MH_EXECUTE"])

        var encryption = Data()
        [UInt32(LC_ENCRYPTION_INFO_64), 24, 0x1000, 0x1000, 1, 0].forEach { encryption.appendUInt32($0) }
        XCTAssertEqual(try self.verify(self.appending(encryption, to: program), "encrypted", in: directory).lines, [": encrypted: cryptid 1 over 0x1000 bytes at 0x1000"])

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

        var modified = program
        let section = try self.section("__TEXT", "__text", in: program)
        modified[Int(program.load(UInt32.self, at: section + 48)) + 4] ^= 0xff
        XCTAssertEqual(try self.verify(modified, "modified", in: directory).lines, [": page 0 of the code does not hash to the sha256 code directory"])

        // The code directory: slot 0 of the superblob LC_CODE_SIGNATURE points at.
        let signature = try XCTUnwrap(image.findCodeSignature())
        let directoryOffset = signature.offset + Int(UInt32(bigEndian: program.load(UInt32.self, at: signature.offset + 16)))
        var short = program
        let page = 1 << Int(program[directoryOffset + 39])
        let slots = Int(UInt32(bigEndian: program.load(UInt32.self, at: directoryOffset + 28)))
        short.store(UInt32((slots - 1) * page).bigEndian, at: directoryOffset + 32)
        short.store(UInt32(slots - 1).bigEndian, at: directoryOffset + 28)
        XCTAssertEqual(try self.verify(short, "short", in: directory).lines, [": the sha256 code directory covers \(((slots - 1) * page).hex) bytes, \((signature.offset - (slots - 1) * page).hex) short of the signature at \(signature.offset.hex): the rest is unsigned"])

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
        XCTAssertEqual(try self.verify(weakened, "weakened", in: directory).lines, [": entitled to opt out of hardening: com.apple.security.cs.disable-library-validation, com.apple.security.get-task-allow"])
        var tampered = weakened
        let flag = try XCTUnwrap(weakened.range(of: Data("<true/>".utf8)))
        tampered.replaceSubrange(flag, with: "<trux/>".utf8)
        XCTAssertEqual(try self.verify(tampered, "tampered", in: directory).lines, [": the entitlements blob does not hash to its slot in the sha256 code directory", ": entitlements that do not parse as a plist"])
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

        var altered = directoryBlob
        altered[Int(UInt32(bigEndian: adhoc.load(UInt32.self, at: 20)))] ^= 0x20 // the identifier's first byte
        XCTAssertEqual(try self.verify(embedded(altered, signatureBlob), "altered", in: directory).lines, [": the CMS signature does not verify over the sha256 code directory"])

        XCTAssertEqual(try self.verify(embedded(adhoc, signatureBlob), "ad hoc", in: directory).lines, [": a CMS signature behind a code directory flagged ad hoc, which Security ignores"])

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
    }

    /**
     A universal file as the kernel, dyld and Security read it: an arm64 slice hidden past the table's count, which
     is a slice to `Universal` as to Security, two slices of one architecture, a slice whose table entry names another
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
            "\(file.path): segment __DATA's address 0x0 is out of order after __TEXT's 0x1000",
            "\(file.path): segments __DATA and __TEXT overlap in memory",
            "\(file.path): __TEXT has no sections",
            "\(file.path): section __DATA,__data's file offset 0x1000 is not where its address lays it, past 2^64",
            "\(file.path): no LC_MAIN nor LC_UNIXTHREAD for an executable",
            "\(file.path): no LC_UUID",
            "\(file.path): no MH_DYLDLINK: a static executable",
            "\(file.path): no LC_BUILD_VERSION nor LC_VERSION_MIN_* dates it",
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
        self.assertVerify(file.path, ["\(file.path): \(count) segments with an empty name", "\(file.path): no LC_BUILD_VERSION nor LC_VERSION_MIN_* dates it"])
        XCTAssertLessThan(ContinuousClock.now - start, .seconds(10), "every pair of segments compared")
    }
}
