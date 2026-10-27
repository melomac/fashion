@testable import fashion
import MachO
import XCTest

/**
 `verify` names what is odd about a Mach-O, one line each, and nothing about one with nothing to say.
 */
final class VerifierTests: XCTestCase {
    private func directory(_ name: String) throws -> URL {
        let url = URL(fileURLWithPath: ".build/tests/VerifierTests/\(name)")
        try? FileManager.default.removeItem(at: url)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    /// What `verify` says of `path`, and the errors it counted.
    private func verify(_ path: String) -> (lines: [String], errors: Int) {
        let reporter = Reporter(console: Console())
        return (Verifier.lines(for: path, reporter: reporter).map(\.text), reporter.errorCount)
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
        return try Universal.sliceData(fileData: data, arch: arch)
    }

    /**
     Apple's own binaries, universal and thin, have nothing to say, nor has a program as the toolchain links, strips
     and signs it, nor a file that is not Mach-O.
     */
    func testSoundFilesSayNothing() throws {
        let directory = try self.directory("sound")
        let built = try compile("built", in: directory, ["-arch", "arm64"])
        self.assertVerify("/bin/ls", [])
        self.assertVerify(built.path, [])
        try XCTSkipUnless(execute("/usr/bin/xcrun", ["strip", built.path]), "cannot run strip")
        self.assertVerify(built.path, [])
        _ = try codesign(["-f", "-s", "-", built.path])
        self.assertVerify(built.path, [])
        try Data("not a Mach-O".utf8).write(to: directory / "text")
        self.assertVerify((directory / "text").path, [])
    }

    /**
     A crafted `x86_64` executable of `size` bytes in `directory`, its load commands the `segments` given as name, vmaddr,
     vmsize, fileoff, filesize and protection.
     */
    private func crafted(_ name: String, in directory: URL, size: Int, segments: [(String, UInt64, UInt64, UInt64, UInt64, UInt32)]) throws -> URL {
        var data = Data()
        data.appendUInt32(MH_MAGIC_64)
        data.appendInt32(CPU_TYPE_X86_64)
        data.appendInt32(0)
        data.appendUInt32(UInt32(MH_EXECUTE))
        data.appendUInt32(UInt32(segments.count)) // ncmds
        data.appendUInt32(UInt32(segments.count * 72)) // sizeofcmds
        data.appendUInt32(0)
        data.appendUInt32(0)
        for (name, vmaddr, vmsize, fileoff, filesize, prot) in segments {
            data.appendUInt32(UInt32(LC_SEGMENT_64))
            data.appendUInt32(72)
            data.append(Data(name.utf8)); data.append(Data(repeating: 0, count: 16 - name.utf8.count))
            data.appendUInt64(vmaddr); data.appendUInt64(vmsize); data.appendUInt64(fileoff); data.appendUInt64(filesize)
            data.appendUInt32(prot); data.appendUInt32(prot); data.appendUInt32(0); data.appendUInt32(0) // maxprot, initprot, nsects, flags
        }
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
            "\(file.path): no LC_MAIN nor LC_UNIXTHREAD for an executable",
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
            "\(file.path): no LC_MAIN nor LC_UNIXTHREAD for an executable",
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
        let lines = Verifier.lines(for: file.path, reporter: reporter)
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
        self.assertVerify(fat.path, ["\(fat.path): 0xa bytes past the last slice, arm64's end at \(size.hex)"])
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
        XCTAssertEqual(Unsigner.lines(for: signed.path, exact: false, write: false, reporter: Reporter(console: Console())).map(\.text), [signed.path + "_unsigned"])
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
        let lines = Verifier.lines(for: file.path, reporter: reporter)
        XCTAssertEqual(lines.map(\.tint), [.malformed])
        XCTAssertTrue(try XCTUnwrap(lines.first).text.hasPrefix("fashion: \(file.path): Invalid Mach-O: segment __LINKEDIT at offset"))
        XCTAssertEqual(reporter.errorCount, 1)
    }
}
