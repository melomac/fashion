import CryptoKit
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
     signature that came out, where `unsign` restores it as the linker or `strip` left it and leaves no such trace;
     nothing is named of a stripped image whose linker is unknown, whose `strip` may have rounded it so itself.
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

        // A stripped image built for macOS 10.13 records no linker, since ld writes LC_VERSION_MIN_MACOSX for it, and
        // this toolchain's strip rounds __LINKEDIT's vmsize to 16 KiB itself: no signature came out of it.
        let old = try compile("old", in: directory, ["-arch", "x86_64", "-mmacosx-version-min=10.13"])
        try XCTSkipUnless(execute("/usr/bin/xcrun", ["strip", old.path]), "cannot run strip")
        let stripped = try XCTUnwrap(MachO(File(path: old.path)))
        XCTAssertNil(stripped.linkerVersion)
        XCTAssertNil(stripped.linkeditSizeRounding)
        self.assertVerify(old.path, [])
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
        // A pack header that does not hold, its checksum wrong, is named as unpack refuses it.
        var broken = try Data(contentsOf: packed)
        let header = try XCTUnwrap(broken.ranges(of: Data("UPX!".utf8)).last).lowerBound
        broken[header + 31] ^= 0xff
        let corrupt = directory / "corrupt"
        try broken.write(to: corrupt)
        XCTAssertTrue(self.verify(corrupt.path).lines.contains("\(corrupt.path): Invalid UPX data: header corrupted 3: a pack header that does not hold, which unpack refuses"))
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
        self.unixthread(states: [(flavor, count, rip)])
    }

    /// An `LC_UNIXTHREAD` command of `states` in turn, each a flavor, a count of words and a pc at `x86_64`'s rip,
    /// register 16, when the state has the words for it.
    private func unixthread(states: [(flavor: UInt32, count: UInt32, pc: UInt64)]) -> Data {
        var command = Data()
        command.appendUInt32(UInt32(LC_UNIXTHREAD))
        command.appendUInt32(UInt32(8 + states.reduce(0) { $0 + 8 + Int($1.count) * 4 }))
        for state in states {
            command.appendUInt32(state.flavor)
            command.appendUInt32(state.count)
            var registers = Data(count: Int(state.count) * 4)
            if registers.count >= 136 {
                registers.replaceSubrange(128 ..< 136, with: withUnsafeBytes(of: state.pc.littleEndian) { Data($0) })
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
        var long = program
        long.store(UInt32(commands.count + 1), at: 16)
        XCTAssertEqual(try self.verify(long, "long", in: directory).lines, [": ncmds \(commands.count + 1) exceeds the \(commands.count) commands the table holds"])
        // dyld counts LC_DYLD_INFO_ONLY with LC_DYLD_INFO: one of each is two to it.
        var info = Data()
        info.appendUInt32(UInt32(LC_DYLD_INFO)); info.appendUInt32(48); info.append(Data(count: 40))
        var only = info
        only.store(LC_DYLD_INFO_ONLY, at: 0)
        XCTAssertTrue(try self.verify(self.appending(info + only, to: program), "aliased", in: directory).lines.contains(": LC_DYLD_INFO beside LC_DYLD_INFO_ONLY, which dyld counts as two LC_DYLD_INFO commands"))
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
        XCTAssertEqual(try self.verify(protected, "protected", in: directory).lines, [": segment __TEXT is Apple-protected (SG_PROTECTED_VERSION_1): the kernel decrypts it past its first 0x3000 bytes as it maps it"])

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
     `LC_UNIXTHREAD`'s pc there, a thread state that is not the architecture's, a first state dyld does not read, an
     entry in no section of `__TEXT`, and one in a section of it that holds no code, where a stub section does.
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
        // The full state, the segment registers after the others, is x86_64's too to the kernel, the pc at the same
        // register; dyld reads the thread state alone, and finds no entry in a command that begins with the full one.
        let dyld = ": LC_UNIXTHREAD's first thread state, flavor 23 of 50 words, is not the one dyld reads, flavor 4 of 42: the kernel enters by it, dyld finds no entry"
        XCTAssertEqual(try self.verify(self.appending(self.unixthread(rip: data.vmaddr, flavor: 23, count: 50), to: thread), "full", in: directory).lines, [dyld, ": LC_UNIXTHREAD's pc \(data.vmaddr.hex) lies in __DATA_CONST, which is not executable"])
        let code = try program.load(UInt64.self, at: self.section("__TEXT", "__text", in: program) + 32)
        XCTAssertEqual(try self.verify(self.appending(self.unixthread(rip: code, flavor: 23, count: 50), to: thread), "fullcode", in: directory).lines, [dyld])
        XCTAssertEqual(try self.verify(self.appending(self.unixthread(states: [(4, 42, data.vmaddr), (23, 50, code)]), to: thread), "fullsecond", in: directory).lines, [": LC_UNIXTHREAD holds 2 thread states: the kernel enters by the last, dyld reads the first"])
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
        // A name starting inside the command's fixed fields, 24 bytes for a dylib command, which dyld refuses.
        var early = program
        early.store(UInt32(16), at: dylib.data.startIndex + 8)
        XCTAssertEqual(try self.verify(early, "early", in: directory).lines, [": LC_LOAD_DYLIB's name starts 0x10 bytes in, inside the command's 0x18 fixed bytes, which dyld refuses", ": links no dylib"])

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
        let hardening = ": entitled to opt out of hardening: com.apple.security.cs.disable-library-validation, com.apple.security.get-task-allow"
        XCTAssertEqual(try self.verify(weakened, "weakened", in: directory).lines, [hardening])
        // The XML broken, the DER form, which codesign wrote beside it, still says what the code is entitled to.
        var tampered = weakened
        let flag = try XCTUnwrap(weakened.range(of: Data("<true/>".utf8)))
        tampered.replaceSubrange(flag, with: "<trux/>".utf8)
        XCTAssertEqual(try self.verify(tampered, "tampered", in: directory).lines, [": the entitlements blob does not hash to its slot in the sha256 code directory", ": entitlements that do not parse as a plist", hardening])

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
        // Security takes the CMS blob under its wrapper's magic alone.
        var mismagic = embedded(directoryBlob, signatureBlob)
        let wrapper = try XCTUnwrap(mismagic.range(of: Data([0xfa, 0xde, 0x0b, 0x01])))
        mismagic.store(UInt32(0xfade_0b02).bigEndian, at: wrapper.lowerBound)
        XCTAssertEqual(try self.verify(mismagic, "mismagic", in: directory).lines, [": the CMS blob's magic is 0xfade0b02, not 0xfade0b01, which Security refuses the signature for"])

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
        XCTAssertEqual(try self.verify(unbound, "unbound", in: directory).lines, [": signed outside Apple's chains by Fashion Self, which Gatekeeper refuses"])
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

    /**
     Segments laid over the same bytes, thousands of them with a section each as a crafted table lays them, have the
     bytes no section covers read once, not once per segment: a 4 MiB file under 4000 such segments would be 16 GiB
     of reads. And a segment laid inside another names none of the outer one's content as lying between segments.
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
        XCTAssertTrue(lines.contains("\(file.path): \((size - headerEnd - 1).hex) bytes of __S\(count - 1) that no section covers are not zero, the first at \((headerEnd + 1).hex)"))

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
        XCTAssertEqual(try self.verify(refused, "refused", in: directory).lines, [": signed outside Apple's chains by Fashion Self, which Gatekeeper refuses"])
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
        let plist = DER.encode(0x70, Data([0x02, 0x01, 0x01]) + arrays)
        let read = self.expectation(description: "read on a worker's stack")
        let worker = Thread {
            var reader = DER.Reader(sequences)
            XCTAssertNil(reader.next())
            XCTAssertNil(Signer.signatureAndToken(in: sequences))
            XCTAssertNil(DEREntitlements.decode(plist))
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

        let (configuration, key, pem, der) = (directory / "certificate.cnf", directory / "key.pem", directory / "certificate.pem", directory / "certificate.der")
        try "[req]\ndistinguished_name = dn\nx509_extensions = ext\nprompt = no\n[dn]\nCN = Fashion Self\n[ext]\nextendedKeyUsage = codeSigning\nkeyUsage = digitalSignature\nbasicConstraints = CA:FALSE\n".write(to: configuration, atomically: true, encoding: .utf8)
        try XCTSkipUnless(execute("/usr/bin/openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key.path, "-out", pem.path, "-config", configuration.path, "-days", "30"]), "cannot make a certificate")
        try XCTSkipUnless(execute("/usr/bin/openssl", ["x509", "-in", pem.path, "-outform", "DER", "-out", der.path]), "cannot convert a certificate")
        let certificate = try Data(contentsOf: der)
        // The issuer and serial, from the certificate: a version, the serial, the algorithm, the issuer.
        var reader = DER.Reader(certificate)
        let tbs = try XCTUnwrap(DER.elements(of: XCTUnwrap(DER.elements(of: XCTUnwrap(reader.next()).content)?.first).content))
        let (serial, issuer) = (tbs[1].raw, tbs[3].raw)

        /// A CMS signature over `content` by the certificate, binding `bound` through both hash-agility attributes.
        func cms(over content: Data, binding bound: [(type: HashType, cdhash: Data)], _ name: String) throws -> Data {
            func oid(_ bytes: [UInt8]) -> Data {
                DER.encode(0x06, Data(bytes))
            }
            func attribute(_ type: [UInt8], _ values: Data) -> Data {
                DER.encode(0x30, oid(type) + DER.encode(0x31, values))
            }
            let sha256 = oid([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01])
            let plist = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict><key>cdhashes</key><array>" + bound.map { "<data>\($0.cdhash.prefix(20).base64EncodedString())</data>" }.joined() + "</array></dict></plist>\n"
            let v2 = bound.map { DER.encode(0x30, oid($0.type == .sha1 ? [0x2b, 0x0e, 0x03, 0x02, 0x1a] : [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]) + DER.encode(0x04, $0.cdhash)) }.reduce(Data(), +)
            let attributes = attribute([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03], oid([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01]))
                + attribute([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04], DER.encode(0x04, Data(SHA256.hash(data: content))))
                + attribute([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x09, 0x01], DER.encode(0x04, Data(plist.utf8)))
                + attribute([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x09, 0x02], v2)
            let (toSign, signatureFile) = (directory / "\(name).attrs", directory / "\(name).sig")
            try DER.encode(0x31, attributes).write(to: toSign)
            try XCTSkipUnless(execute("/usr/bin/openssl", ["dgst", "-sha256", "-sign", key.path, "-out", signatureFile.path, toSign.path]), "cannot sign")
            let rsa = DER.encode(0x30, oid([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]) + DER.encode(0x05, Data()))
            let signerInfo = try DER.encode(0x30, DER.encode(0x02, Data([1])) + DER.encode(0x30, issuer + serial) + DER.encode(0x30, sha256 + DER.encode(0x05, Data())) + DER.encode(0xa0, attributes) + rsa + DER.encode(0x04, Data(contentsOf: signatureFile)))
            let signedData = DER.encode(0x30, DER.encode(0x02, Data([1])) + DER.encode(0x31, DER.encode(0x30, sha256 + DER.encode(0x05, Data()))) + DER.encode(0x30, oid([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01])) + DER.encode(0xa0, certificate) + DER.encode(0x31, signerInfo))
            return DER.encode(0x30, oid([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02]) + DER.encode(0xa0, signedData))
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
        let bound = try cms(over: sha1, binding: [(.sha1, Data(Insecure.SHA1.hash(data: sha1))), (.sha256, Data(SHA256.hash(data: sha256)))], "bound")
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
     The index as the kernel walks it, where Security stops at the first alternate missing: a code directory whose
     identifier offset is 0, or whose magic is not a directory's, which Security loads and the kernel refuses the
     signature for; a directory past a gap in the alternates, which Security never loads and the kernel counts, two
     of one hash type then; and an entry at offset 0.
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
            var blob = Data()
            var offset = 12 + 8 * blobs.count
            [0xfade_0cc0, UInt32(offset + blobs.reduce(0) { $0 + ($1.blob?.count ?? 0) }), UInt32(blobs.count)].forEach { blob.appendUInt32BE($0) }
            for entry in blobs {
                blob.appendUInt32BE(entry.slot); blob.appendUInt32BE(entry.blob == nil ? 0 : UInt32(offset))
                offset += entry.blob?.count ?? 0
            }
            blobs.forEach { blob += $0.blob ?? Data() }
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
            "\(file.path): __TEXT has no sections",
            "\(file.path): no LC_MAIN nor LC_UNIXTHREAD for an executable",
            "\(file.path): no LC_UUID",
            "\(file.path): no MH_DYLDLINK: a static executable",
        ])
    }

    /**
     The table's lines name a few commands and count the rest: a crafted table of ten odd-sized commands, hidden from
     the loaders too and sized other than their structure, names eight of each and counts the others, where a line
     each would be millions.
     */
    func testTheTableLinesAreCounted() throws {
        let directory = try self.directory("counted")
        var odd = Data()
        odd.appendUInt32(UInt32(LC_UUID)); odd.appendUInt32(28); odd.append(Data(count: 20))
        let file = try self.crafted("counted", in: directory, size: 0x1000, segments: [("__TEXT", 0x1000, 0x1000, 0, 0x1000, 5)], commands: Array(repeating: odd, count: 10))
        var data = try Data(contentsOf: file)
        data.store(UInt32(1), at: 16) // ncmds: the segment alone
        try data.write(to: file)
        self.assertVerify(file.path, [
            "\(file.path): ncmds 1 hides the last 10 commands of 11 from the loaders: \(Array(repeating: "LC_UUID", count: 8).joined(separator: ", "))…",
        ] + (1 ... 8).map { "\(file.path): load command #\($0), LC_UUID, has a size 0x1c that is not a multiple of 8" } + [
            "\(file.path): and 2 more load commands with a size that is not a multiple of 8",
        ] + (1 ... 8).map { "\(file.path): load command #\($0), LC_UUID, is 0x1c bytes, not its structure's 0x18, which dyld refuses" } + [
            "\(file.path): and 2 more load commands sized other than their structure",
            "\(file.path): 10 LC_UUID commands",
            "\(file.path): __TEXT has no sections",
            "\(file.path): no LC_MAIN nor LC_UNIXTHREAD for an executable",
            "\(file.path): no MH_DYLDLINK: a static executable",
            "\(file.path): no LC_BUILD_VERSION nor LC_VERSION_MIN_* dates it",
        ])
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
     A secure timestamp is read from the signer's token and verified here, with no network: the token's imprint must
     be the signature's digest, and its chain must build to the system's anchors, or to the ones given. A token a
     timestamp authority of the test's own signed, with openssl, verifies under its certificate as the anchor, with its
     date, and not under the system's; one taken over other bytes does not.
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
        let date = try XCTUnwrap(Signer.timestamp(in: stamped, anchors: [authority]))
        XCTAssertLessThan(abs(date.timeIntervalSinceNow), 600)
        let other = try Self.timestamped(cms, with: token(over: Data("other bytes".utf8), "other"))
        XCTAssertNil(Signer.timestamp(in: other, anchors: [authority]), "a token over other bytes")
    }
}
