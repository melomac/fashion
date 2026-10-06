@testable import fashion
import MachO
import XCTest

final class MachOTests: XCTestCase {
    func testArchNameARM64() {
        XCTAssertEqual(Universal.archName(cpuType: CPU_TYPE_ARM64, cpuSubtype: 0), "arm64")
    }

    func testArchNameARM64E() {
        XCTAssertEqual(Universal.archName(cpuType: CPU_TYPE_ARM64, cpuSubtype: CPU_SUBTYPE_ARM64E), "arm64e")
    }

    /**
     `CPU_SUBTYPE_ARM64E_X1` (12): the third slice of macOS 27 system binaries, `arm64e.x1` to codesign.
     */
    func testArchNameARM64EX1() {
        XCTAssertEqual(Universal.archName(cpuType: CPU_TYPE_ARM64, cpuSubtype: 12), "arm64e.x1")
    }

    /**
     An arm64 subtype neither the OS nor the fallback table knows is labelled like lipo does, never folded
     into `arm64`: codesign resolves --arch arm64 to some other arm64-family slice without complaint.
     */
    func testArchNameUnknownARM64SubtypeIsVisible() {
        XCTAssertEqual(Universal.archName(cpuType: CPU_TYPE_ARM64, cpuSubtype: 99), "unknown(16777228,99)")
    }

    func testArchNameX86_64() {
        XCTAssertEqual(Universal.archName(cpuType: CPU_TYPE_X86_64, cpuSubtype: 3), "x86_64")
    }

    func testArchNameX86_64H() {
        // CPU_SUBTYPE_X86_64_H (8): a Haswell slice is its own architecture to codesign, not a second `x86_64`.
        XCTAssertEqual(Universal.archName(cpuType: CPU_TYPE_X86_64, cpuSubtype: CPU_SUBTYPE_X86_64_H), "x86_64h")
    }

    func testArchNameARM64_32() {
        XCTAssertEqual(Universal.archName(cpuType: CPU_TYPE_ARM64_32, cpuSubtype: CPU_SUBTYPE_ARM64_32_V8), "arm64_32")
    }

    func testArchNameI386() {
        XCTAssertEqual(Universal.archName(cpuType: CPU_TYPE_I386, cpuSubtype: 0), "i386")
    }

    func testArchNameARM() {
        XCTAssertEqual(Universal.archName(cpuType: CPU_TYPE_ARM, cpuSubtype: 0), "arm")
    }

    func testArchNamePPC() {
        XCTAssertEqual(Universal.archName(cpuType: CPU_TYPE_POWERPC, cpuSubtype: 0), "ppc")
    }

    func testArchNamePPC64() {
        XCTAssertEqual(Universal.archName(cpuType: CPU_TYPE_POWERPC64, cpuSubtype: 0), "ppc64")
    }

    func testArchNameMasksCapabilityBits() {
        let subtypeWithCaps = CPU_SUBTYPE_ARM64E | cpu_subtype_t(bitPattern: 0x8000_0000)
        XCTAssertEqual(Universal.archName(cpuType: CPU_TYPE_ARM64, cpuSubtype: subtypeWithCaps), "arm64e")

        // Shipping arm64e.x1 slices carry the same versioned-ABI flag: cpusubtype 0x8000000c.
        XCTAssertEqual(Universal.archName(cpuType: CPU_TYPE_ARM64, cpuSubtype: cpu_subtype_t(bitPattern: 0x8000_000c)), "arm64e.x1")
    }

    func testArchNameUnknownCPU() {
        XCTAssertEqual(Universal.archName(cpuType: 9999, cpuSubtype: 0), "unknown(9999,0)")
    }

    /**
     Slice names must be the ones codesign uses (`--arch`), so that a new subtype such as arm64e.x1 is not reported
     under its base architecture.

     codesign is the oracle rather than `lipo`: it ships with the OS,while Xcode's lipo may predate the OS and print
     `unknown(16777228,12)` for a slice it has never seen.
     */
    func testArchNamesMatchCodesign() throws {
        let path = "/bin/ls"
        let names: [String] = switch try Universal.open(path: path) {
        case let .fat(archs): archs.map { Universal.archName(cpuType: $0.cpuType, cpuSubtype: $0.cpuSubtype) }
        case let .thin(slice): [Universal.archName(cpuType: slice.cpuType, cpuSubtype: slice.cpuSubtype)]
        case .notMachO: []
        }
        try XCTSkipIf(names.isEmpty, "\(path) is not a Mach-O")

        let archs = try codesignArchs(path) // outside XCTUnwrap, so a skip from the helper stays a skip
        let expected = try XCTUnwrap(archs, "codesign printed no Format line for \(path)")
        XCTAssertEqual(Set(names), expected)
    }

    // MARK: - Synthetic Mach-O 64-bit (native endian)

    private func makeThin64(cpuType: cpu_type_t = CPU_TYPE_ARM64, cpuSubtype: cpu_subtype_t = 0) -> Data {
        var data = Data()
        data.appendUInt32(MH_MAGIC_64)
        data.appendInt32(cpuType)
        data.appendInt32(cpuSubtype)
        data.appendUInt32(2) // filetype = MH_EXECUTE
        data.appendUInt32(1) // ncmds
        data.appendUInt32(24) // sizeofcmds (LC_SYMTAB = 24 bytes)
        data.appendUInt32(0) // flags
        data.appendUInt32(0) // reserved
        // LC_SYMTAB: cmd, cmdsize, symoff, nsyms, stroff, strsize
        data.appendUInt32(UInt32(LC_SYMTAB))
        data.appendUInt32(24) // cmdsize
        data.appendUInt32(56) // symoff (right after header+commands)
        data.appendUInt32(0) // nsyms
        data.appendUInt32(56) // stroff
        data.appendUInt32(0) // strsize
        return data
    }

    private func makeThin64Swapped(cpuType: cpu_type_t = CPU_TYPE_ARM64, cpuSubtype: cpu_subtype_t = 0) -> Data {
        var data = Data()
        data.appendUInt32(MH_CIGAM_64)
        data.appendInt32(cpuType.byteSwapped)
        data.appendInt32(cpuSubtype.byteSwapped)
        data.appendUInt32(UInt32(2).byteSwapped)
        data.appendUInt32(UInt32(1).byteSwapped) // ncmds
        data.appendUInt32(UInt32(24).byteSwapped) // sizeofcmds
        data.appendUInt32(0)
        data.appendUInt32(0)
        // LC_SYMTAB swapped
        data.appendUInt32(UInt32(LC_SYMTAB).byteSwapped)
        data.appendUInt32(UInt32(24).byteSwapped)
        data.appendUInt32(UInt32(56).byteSwapped)
        data.appendUInt32(0)
        data.appendUInt32(UInt32(56).byteSwapped)
        data.appendUInt32(0)
        return data
    }

    private func makeThin32(cpuType: cpu_type_t = CPU_TYPE_I386, cpuSubtype: cpu_subtype_t = 0) -> Data {
        var data = Data()
        data.appendUInt32(MH_MAGIC)
        data.appendInt32(cpuType)
        data.appendInt32(cpuSubtype)
        data.appendUInt32(2) // filetype
        data.appendUInt32(1) // ncmds
        data.appendUInt32(16) // sizeofcmds: Security refuses a table too short for a command
        data.appendUInt32(0) // flags
        data.appendUInt32(UInt32(LC_SOURCE_VERSION))
        data.appendUInt32(16) // cmdsize
        data.appendUInt64(0) // version
        return data
    }

    private func makeThin32Swapped(cpuType: cpu_type_t = CPU_TYPE_I386, cpuSubtype: cpu_subtype_t = 0) -> Data {
        var data = Data()
        data.appendUInt32(MH_CIGAM)
        data.appendInt32(cpuType.byteSwapped)
        data.appendInt32(cpuSubtype.byteSwapped)
        data.appendUInt32(UInt32(2).byteSwapped)
        data.appendUInt32(UInt32(1).byteSwapped) // ncmds
        data.appendUInt32(UInt32(16).byteSwapped) // sizeofcmds
        data.appendUInt32(0) // flags
        data.appendUInt32(UInt32(LC_SOURCE_VERSION).byteSwapped)
        data.appendUInt32(UInt32(16).byteSwapped) // cmdsize
        data.appendUInt64(0) // version
        return data
    }

    private func makeFat() -> Data {
        let sliceData = self.makeThin64()
        var data = Data()
        data.appendUInt32BE(FAT_MAGIC)
        data.appendUInt32BE(1) // 1 arch
        data.appendInt32BE(CPU_TYPE_ARM64)
        data.appendInt32BE(0) // cpusubtype
        data.appendUInt32BE(UInt32(1024)) // offset (page-aligned)
        data.appendUInt32BE(UInt32(sliceData.count)) // size
        data.appendUInt32BE(12) // align (2^12 = 4096)
        let currentSize = data.count
        data.append(Data(repeating: 0, count: 1024 - currentSize))
        data.append(sliceData)
        return data
    }

    /**
     A universal static library: a 32-bit fat header over two `ar` archive slices.
     */
    private func makeFatArchive() -> Data {
        let archive = Data("!<arch>\n".utf8) + Data(repeating: 0x20, count: 24)
        var data = Data()
        data.appendUInt32BE(FAT_MAGIC)
        data.appendUInt32BE(2)
        for (index, cpuType) in [CPU_TYPE_ARM64, CPU_TYPE_X86_64].enumerated() {
            data.appendInt32BE(cpuType)
            data.appendInt32BE(0)
            data.appendUInt32BE(UInt32(48 + index * archive.count)) // offset, right after the 48-byte table
            data.appendUInt32BE(UInt32(archive.count))
            data.appendUInt32BE(0)
        }
        data.append(archive)
        data.append(archive)
        return data
    }

    private func makeFat64() -> Data {
        let sliceData = self.makeThin64()
        var data = Data()
        data.appendUInt32BE(FAT_MAGIC_64)
        data.appendUInt32BE(1) // 1 arch
        data.appendInt32BE(CPU_TYPE_ARM64)
        data.appendInt32BE(0) // cpusubtype
        data.appendUInt64BE(UInt64(4096)) // offset (page-aligned)
        data.appendUInt64BE(UInt64(sliceData.count)) // size
        data.appendUInt32BE(14) // align (2^14 = 16384)
        data.appendUInt32BE(0) // reserved
        let currentSize = data.count
        data.append(Data(repeating: 0, count: 4096 - currentSize))
        data.append(sliceData)
        return data
    }

    // MARK: - Open tests

    func testOpenNotMachO() throws {
        let data = Data("Hello, World!".utf8)

        if case .notMachO = try Universal.open(data: data) {
            // pass
        } else {
            XCTFail("Expected notMachO")
        }
    }

    func testOpenEmptyData() throws {
        let data = Data()

        if case .notMachO = try Universal.open(data: data) {
            // pass
        } else {
            XCTFail("Expected notMachO for empty data")
        }
    }

    func testOpenThin64() throws {
        let data = self.makeThin64(cpuType: CPU_TYPE_ARM64, cpuSubtype: CPU_SUBTYPE_ARM64E)

        if case let .thin(slice) = try Universal.open(data: data) {
            XCTAssertEqual(slice.cpuType, CPU_TYPE_ARM64)
            XCTAssertEqual(slice.cpuSubtype, CPU_SUBTYPE_ARM64E)
        } else {
            XCTFail("Expected thin for MH_MAGIC_64")
        }
    }

    func testOpenThin64Swapped() throws {
        let data = self.makeThin64Swapped(cpuType: CPU_TYPE_X86_64, cpuSubtype: 3)

        if case let .thin(slice) = try Universal.open(data: data) {
            XCTAssertEqual(slice.cpuType, CPU_TYPE_X86_64)
            XCTAssertEqual(slice.cpuSubtype, 3)
        } else {
            XCTFail("Expected thin for MH_CIGAM_64")
        }
    }

    func testOpenThin32() throws {
        let data = self.makeThin32(cpuType: CPU_TYPE_I386)

        if case let .thin(slice) = try Universal.open(data: data) {
            XCTAssertEqual(slice.cpuType, CPU_TYPE_I386)
        } else {
            XCTFail("Expected thin for MH_MAGIC")
        }
    }

    func testOpenThin32Swapped() throws {
        let data = self.makeThin32Swapped(cpuType: CPU_TYPE_ARM)

        if case let .thin(slice) = try Universal.open(data: data) {
            XCTAssertEqual(slice.cpuType, CPU_TYPE_ARM)
        } else {
            XCTFail("Expected thin for MH_CIGAM")
        }
    }

    func testOpenFat() throws {
        let data = self.makeFat()

        if case let .fat(archs) = try Universal.open(data: data) {
            XCTAssertEqual(archs.count, 1)
            XCTAssertEqual(archs[0].cpuType, CPU_TYPE_ARM64)
        } else {
            XCTFail("Expected fat binary")
        }
    }

    func testOpenFat64() throws {
        let data = self.makeFat64()

        if case let .fat(archs) = try Universal.open(data: data) {
            XCTAssertEqual(archs.count, 1)
            XCTAssertEqual(archs[0].cpuType, CPU_TYPE_ARM64)
            XCTAssertEqual(archs[0].offset, 4096)
            let slice = Universal.sliceData(fileData: data, arch: archs[0])
            XCTAssertEqual(slice.count, Int(archs[0].size))
        } else {
            XCTFail("Expected fat64 binary")
        }
    }

    func testOpenRejectsTruncatedFatTable() throws {
        var data = Data()
        data.appendUInt32BE(FAT_MAGIC)
        data.appendUInt32BE(2)
        data.appendInt32BE(CPU_TYPE_ARM64)
        data.appendInt32BE(0)
        data.appendUInt32BE(4096)
        data.appendUInt32BE(64)
        data.appendUInt32BE(12)

        XCTAssertThrowsError(try Universal.open(data: data)) { error in
            XCTAssertEqual(error as? ParserError, .invalidFatArchitectureTable(count: 2, fileSize: 28))
        }
    }

    func testOpenAcceptsUniversalArchive() throws {
        // `lipo -create` also builds universal static libraries, whose slices are `ar` archives rather
        // than Mach-O. The container must open, and the Mach-O-only hashes must simply yield nothing.
        var data = self.makeFatArchive()
        if case let .fat(archs) = try Universal.open(data: data) {
            XCTAssertEqual(archs.map { Universal.archName(cpuType: $0.cpuType, cpuSubtype: $0.cpuSubtype) }, ["arm64", "x86_64"])
        } else {
            XCTFail("Expected a universal archive to open as fat")
        }

        let clean = data.count
        data.append(Data(repeating: 0x41, count: 100))
        XCTAssertEqual(try Universal.fileEnd(data: data), clean)

        let url = FileManager.default.temporaryDirectory / "fashion-fat-archive-\(UUID()).a"
        try data.write(to: url)
        defer {
            try? FileManager.default.removeItem(at: url)
        }

        XCTAssertTrue(try CDHash.hash(path: url.path()).isEmpty)
        XCTAssertTrue(try SymHash.compute(File(path: url.path()), algorithm: .md5, separator: ",", sortSymbols: true).isEmpty)
    }

    func testMalformedMachOInsideFatIsRejectedByConsumers() throws {
        // The container itself is well-formed; the Mach-O inside it declares a load command that the
        // 40-byte slice cannot hold. Each hash must report that rather than treat the slice as unsigned.
        var slice = Data()
        slice.appendUInt32(MH_MAGIC_64)
        slice.appendInt32(CPU_TYPE_ARM64)
        slice.appendInt32(0)
        slice.appendUInt32(UInt32(MH_EXECUTE))
        slice.appendUInt32(1) // ncmds
        slice.appendUInt32(16) // sizeofcmds
        slice.appendUInt32(0)
        slice.appendUInt32(0)
        slice.appendUInt32(UInt32(LC_CODE_SIGNATURE))
        slice.appendUInt32(16) // cmdsize, but only 8 bytes follow the header

        var data = Data()
        data.appendUInt32BE(FAT_MAGIC)
        data.appendUInt32BE(1)
        data.appendInt32BE(CPU_TYPE_ARM64)
        data.appendInt32BE(0)
        data.appendUInt32BE(32) // offset
        data.appendUInt32BE(UInt32(slice.count))
        data.appendUInt32BE(5)
        data.append(Data(repeating: 0, count: 32 - data.count))
        data.append(slice)

        XCTAssertNoThrow(try Universal.open(data: data))

        let url = FileManager.default.temporaryDirectory / "fashion-fat-malformed-\(UUID())"
        try data.write(to: url)
        defer {
            try? FileManager.default.removeItem(at: url)
        }

        let expected = ParserError.invalidLoadCommandTable(size: 16, fileSize: slice.count)
        XCTAssertThrowsError(try CDHash.hash(path: url.path())) { error in
            XCTAssertEqual(error as? ParserError, expected)
        }
        XCTAssertThrowsError(try SymHash.compute(File(path: url.path()), algorithm: .md5, separator: ",", sortSymbols: true)) { error in
            XCTAssertEqual(error as? ParserError, expected)
        }
    }

    func testOpenRejectsFatSliceRanges() throws {
        let slice = self.makeThin64()
        let table = 8 + 20 // header + one fat_arch

        func fat(offset: UInt32, size: UInt32) -> Data {
            var data = Data()
            data.appendUInt32BE(FAT_MAGIC)
            data.appendUInt32BE(1)
            data.appendInt32BE(CPU_TYPE_ARM64)
            data.appendInt32BE(0)
            data.appendUInt32BE(offset)
            data.appendUInt32BE(size)
            data.appendUInt32BE(0) // align
            data.append(Data(repeating: 0, count: 64 - data.count))
            data.append(slice)
            return data
        }

        // Positive control: the true geometry opens.
        guard case let .fat(archs) = try Universal.open(data: fat(offset: 64, size: UInt32(slice.count))) else {
            return XCTFail("Expected a fat binary")
        }
        XCTAssertEqual(archs.count, 1)

        // A slice inside the table, an empty slice, and a slice past the end of the file.
        let rejected: [(offset: UInt32, size: UInt32)] = [(UInt32(table - 4), UInt32(slice.count)), (64, 0), (64, UInt32(slice.count) + 1000)]
        for (offset, size) in rejected {
            let data = fat(offset: offset, size: size)
            XCTAssertThrowsError(try Universal.open(data: data), "offset \(offset) size \(size)") { error in
                XCTAssertEqual(error as? ParserError, .invalidFatArchitectureRange(offset: UInt64(offset), size: UInt64(size), fileSize: data.count))
            }
        }
    }

    func testOpenShortMagicIsNotMachO() throws {
        // Security (MachORep::candidate) reads a 28-byte mach_header before it calls a file Mach-O, and isMachO(path:)
        // does too; open(data:) must agree, so no mode reports a shorter stub as a broken Mach-O.
        for magic in [MH_MAGIC, MH_CIGAM, MH_MAGIC_64, MH_CIGAM_64, FAT_MAGIC, FAT_CIGAM, FAT_MAGIC_64, FAT_CIGAM_64] {
            for count in [4, 7, 8, 20, 27] {
                var data = Data()
                data.appendUInt32(magic)
                data.append(Data(repeating: 0, count: count - 4))

                guard case .notMachO = try Universal.open(data: data) else {
                    return XCTFail("\(count)-byte magic \(String(magic, radix: 16)) must not be a Mach-O")
                }
            }
        }
    }

    func testOpenFromPath() throws {
        let url = FileManager.default.temporaryDirectory / "fashion-macho-\(UUID())"
        try self.makeThin64().write(to: url)
        defer {
            try? FileManager.default.removeItem(at: url)
        }

        if case .thin = try Universal.open(path: url.path()) {
            // pass
        } else {
            XCTFail("Expected thin from path")
        }
    }

    func testOpenFromMissingPath() {
        XCTAssertThrowsError(try Universal.open(path: "/tmp/fashion-nonexistent-\(UUID())"))
    }

    // MARK: - isMachO (whether open reads a Mach-O)

    func testIsMachOTrueForThinBinary() throws {
        let url = FileManager.default.temporaryDirectory / "fashion-ismacho-\(UUID())"
        try self.makeThin64().write(to: url)
        defer {
            try? FileManager.default.removeItem(at: url)
        }

        XCTAssertTrue(try Universal.isMachO(path: url.path()))
    }

    func testIsMachOFalseForNonMachO() throws {
        let url = FileManager.default.temporaryDirectory / "fashion-ismacho-\(UUID()).txt"
        try Data("not a mach-o, just text".utf8).write(to: url)
        defer {
            try? FileManager.default.removeItem(at: url)
        }

        XCTAssertFalse(try Universal.isMachO(path: url.path()))
    }

    func testIsMachOThrowsForMissingFile() {
        XCTAssertThrowsError(try Universal.isMachO(path: "/tmp/fashion-nonexistent-\(UUID())"))
    }

    func testIsMachOTrueForFatBinary() throws {
        let url = FileManager.default.temporaryDirectory / "fashion-fat-\(UUID())"
        try self.makeFat().write(to: url) // 1 architecture
        defer {
            try? FileManager.default.removeItem(at: url)
        }

        XCTAssertTrue(try Universal.isMachO(path: url.path()))
    }

    func testUniversalSliceLimitMatchesDyld() throws {
        // dyld's mach_o::Universal accepts at most kMaxSliceCount (16) slices: fashion reads a universal file exactly
        // when libdyld's macho_for_each_slice does.
        for count in [16, 17] {
            var data = Data()
            data.appendUInt32BE(FAT_MAGIC)
            data.appendUInt32BE(UInt32(count))
            for index in 0 ..< count { // arm64 slices with distinct subtypes, one page each
                data.appendInt32BE(CPU_TYPE_ARM64)
                data.appendInt32BE(Int32(index))
                data.appendUInt32BE(UInt32(4096 * (index + 1)))
                data.appendUInt32BE(32)
                data.appendUInt32BE(12)
            }
            data.append(Data(count: 4096 - data.count))
            for index in 0 ..< count {
                var slice = Data()
                [MH_MAGIC_64, UInt32(CPU_TYPE_ARM64), UInt32(index), UInt32(MH_EXECUTE), 0, 0, 0, 0].forEach { slice.appendUInt32($0) }
                data.append(slice + Data(count: 4096 - slice.count))
            }
            let url = FileManager.default.temporaryDirectory / "fashion-fat\(count)-\(UUID())"
            try data.write(to: url)
            defer {
                try? FileManager.default.removeItem(at: url)
            }

            var dyldSlices = 0
            let status = macho_for_each_slice(url.path()) { _, _, _, _ in dyldSlices += 1 }
            if case let .fat(archs) = try Universal.open(data: data) {
                XCTAssertEqual(status, 0, "dyld rejects the \(count)-slice file fashion reads as universal")
                XCTAssertEqual(archs.count, dyldSlices)
            } else {
                XCTAssertNotEqual(status, 0, "dyld reads the \(count)-slice file fashion rejects")
            }
            XCTAssertEqual(try Universal.isMachO(path: url.path()), count <= 16)
        }
    }

    func testIsMachOFalseForJavaClass() throws {
        // 0xCAFEBABE shared magic, but the big-endian u32 at offset 4 is a Java major version (52), not an arch count.
        var data = Data([0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x34])
        data.append(Data(repeating: 0, count: 64))
        let url = FileManager.default.temporaryDirectory / "fashion-class-\(UUID()).class"
        try data.write(to: url)
        defer {
            try? FileManager.default.removeItem(at: url)
        }

        XCTAssertFalse(try Universal.isMachO(path: url.path()))
    }

    func testIsMachOFalseForBogusFatArchCount() throws {
        var data = Data()
        data.appendUInt32BE(FAT_MAGIC)
        data.appendUInt32BE(9999) // absurd architecture count — not a universal binary
        data.append(Data(repeating: 0, count: 64))
        let url = FileManager.default.temporaryDirectory / "fashion-bogusfat-\(UUID())"
        try data.write(to: url)
        defer {
            try? FileManager.default.removeItem(at: url)
        }

        XCTAssertFalse(try Universal.isMachO(path: url.path()))
    }

    // MARK: - Load commands

    func testLoadCommandsThin64() {
        let data = self.makeThin64()
        let cmds = MachO.loadCommands(data: data)

        XCTAssertEqual(cmds.count, 1)
        XCTAssertEqual(cmds[0].cmd, UInt32(LC_SYMTAB))
        XCTAssertEqual(cmds[0].data.count, 24)
    }

    func testLoadCommandsThin64Swapped() {
        let data = self.makeThin64Swapped()
        let cmds = MachO.loadCommands(data: data)

        XCTAssertEqual(cmds.count, 1)
        XCTAssertEqual(cmds[0].cmd, UInt32(LC_SYMTAB))
    }

    func testLoadCommandsEmptyData() {
        XCTAssertTrue(MachO.loadCommands(data: Data()).isEmpty)
    }

    func testLoadCommandsNotMachO() {
        XCTAssertTrue(MachO.loadCommands(data: Data("hello".utf8)).isEmpty)
    }

    func testLoadCommandsTruncatedHeader() {
        var data = Data()
        data.appendUInt32(MH_MAGIC_64)

        XCTAssertTrue(MachO.loadCommands(data: data).isEmpty)
    }

    func testSliceRejectsTruncatedLoadCommand() {
        var data = Data()
        data.appendUInt32(MH_MAGIC_64)
        data.appendInt32(CPU_TYPE_ARM64)
        data.appendInt32(0)
        data.appendUInt32(UInt32(MH_EXECUTE))
        data.appendUInt32(1)
        data.appendUInt32(16)
        data.appendUInt32(0)
        data.appendUInt32(0)
        data.appendUInt32(UInt32(LC_CODE_SIGNATURE))
        data.appendUInt32(16)

        XCTAssertThrowsError(try MachO(data)) { error in
            XCTAssertEqual(error as? ParserError, .invalidLoadCommandTable(size: 16, fileSize: 40))
        }
    }

    func testSliceRejectsCommandPastDeclaredTable() {
        var data = Data()
        data.appendUInt32(MH_MAGIC_64)
        data.appendInt32(CPU_TYPE_ARM64)
        data.appendInt32(0)
        data.appendUInt32(UInt32(MH_EXECUTE))
        data.appendUInt32(1)
        data.appendUInt32(8)
        data.appendUInt32(0)
        data.appendUInt32(0)
        data.appendUInt32(UInt32(LC_CODE_SIGNATURE))
        data.appendUInt32(16)
        data.appendUInt32(48)
        data.appendUInt32(12)

        XCTAssertThrowsError(try MachO(data)) { error in
            XCTAssertEqual(error as? ParserError, .invalidLoadCommandTable(size: 8, fileSize: 48))
        }
    }

    // MARK: - Load-command rules (Security's MachO)

    /**
     A thin header with the declared counts under test control, followed by `commands`.
     */
    private func thinHeader(is64: Bool = true, ncmds: UInt32, sizeofcmds: UInt32, commands: Data) -> Data {
        var data = Data()
        data.appendUInt32(is64 ? MH_MAGIC_64 : MH_MAGIC)
        data.appendInt32(is64 ? CPU_TYPE_ARM64 : CPU_TYPE_I386)
        data.appendInt32(0)
        data.appendUInt32(UInt32(MH_EXECUTE))
        data.appendUInt32(ncmds)
        data.appendUInt32(sizeofcmds)
        data.appendUInt32(0) // flags
        if is64 {
            data.appendUInt32(0) // reserved
        }
        data.append(commands)
        return data
    }

    /**
     A load command of the given size whose payload is all zero.
     */
    private func command(_ cmd: Int32, size: UInt32) -> Data {
        var data = Data()
        data.appendUInt32(UInt32(cmd))
        data.appendUInt32(size)
        data.append(Data(repeating: 0, count: Int(size) - 8))
        return data
    }

    func testSliceRejectsTruncatedHeader() {
        for (magic, expectedSize) in [(MH_MAGIC_64, MemoryLayout<mach_header_64>.size), (MH_MAGIC, MemoryLayout<mach_header>.size)] {
            var data = Data()
            data.appendUInt32(magic)
            data.appendInt32(CPU_TYPE_ARM64)

            XCTAssertThrowsError(try MachO(data)) { error in
                XCTAssertEqual(error as? ParserError, .truncatedMachHeader(expectedSize: expectedSize, fileSize: 8))
            }
        }
    }

    func testSliceRejectsCommandsNotFillingTable() {
        // One 24-byte command inside a declared 32-byte table: the leftover bytes are not a command.
        let data = self.thinHeader(ncmds: 1, sizeofcmds: 32, commands: self.command(LC_UUID, size: 24) + Data(repeating: 0, count: 8))

        XCTAssertThrowsError(try MachO(data)) { error in
            XCTAssertEqual(error as? ParserError, .invalidLoadCommandTable(size: 32, fileSize: data.count))
        }
    }

    func testSliceAcceptsUnalignedCommand() {
        // Security requires no alignment of cmdsize (codesign signs such a binary, and Rosetta runs it).
        for (is64, size) in [(true, UInt32(28)), (false, UInt32(26))] {
            XCTAssertNotNil(try MachO(self.thinHeader(is64: is64, ncmds: 1, sizeofcmds: size, commands: self.command(LC_UUID, size: size))), "is64 \(is64)")
        }
    }

    func testSliceIgnoresNcmds() throws {
        // MachOBase::nextCommand walks sizeofcmds alone: a wrong ncmds neither hides nor invents a command.
        let commands = self.command(LC_UUID, size: 24) + self.command(LC_SOURCE_VERSION, size: 16)
        for ncmds: UInt32 in [0, 1, 3] {
            let slice = try XCTUnwrap(MachO(self.thinHeader(ncmds: ncmds, sizeofcmds: 40, commands: commands)))
            XCTAssertEqual(slice.loadCommands.map(\.cmd), [UInt32(LC_UUID), UInt32(LC_SOURCE_VERSION)], "ncmds \(ncmds)")
        }
    }

    func testSliceRejectsCommandBelowMinimumSize() {
        // MachO::validateStructure: an LC_SEGMENT_64 must hold a whole segment_command_64, not just the 8-byte header.
        let data = self.thinHeader(ncmds: 1, sizeofcmds: 16, commands: self.command(LC_SEGMENT_64, size: 16))

        XCTAssertThrowsError(try MachO(data)) { error in
            XCTAssertEqual(error as? ParserError, .truncatedLoadCommand(cmd: UInt32(LC_SEGMENT_64), size: 16, expectedSize: 72))
        }
    }

    func testSliceChecksSizesOnlyUpToTheImageEnd() throws {
        // validateStructure stops at the first __LINKEDIT segment or LC_SYMTAB, and checks no other command: a short
        // command after it parses (a short LC_SYMTAB is then an error to symhash alone).
        var linkedit = self.command(LC_SEGMENT_64, size: 72)
        linkedit.replaceSubrange(8 ..< 18, with: Data("__LINKEDIT".utf8))
        let commands = linkedit + self.command(LC_SYMTAB, size: 16) + self.command(LC_DYSYMTAB, size: 16)
        let slice = try XCTUnwrap(MachO(self.thinHeader(ncmds: 3, sizeofcmds: UInt32(commands.count), commands: commands)))
        XCTAssertEqual(slice.loadCommands.count, 3)

        XCTAssertThrowsError(try SymHash.parseSymtab(command: slice.loadCommands[1])) { error in
            XCTAssertEqual(error as? ParserError, .truncatedLoadCommand(cmd: UInt32(LC_SYMTAB), size: 16, expectedSize: 24))
        }
    }

    func testSliceRejectsZeroSizeCommand() {
        // A command header declaring cmdsize 0 can never advance the parser; it must not count as a command.
        var zeroSized = Data()
        zeroSized.appendUInt32(UInt32(LC_UUID))
        zeroSized.appendUInt32(0)
        let data = self.thinHeader(ncmds: 1, sizeofcmds: 8, commands: zeroSized)

        XCTAssertThrowsError(try MachO(data)) { error in
            XCTAssertEqual(error as? ParserError, .invalidLoadCommandTable(size: 8, fileSize: data.count))
        }
    }

    // MARK: - parseSymtab

    func testParseSymtab() throws {
        let data = self.makeThin64()
        let cmds = MachO.loadCommands(data: data)
        let symtab = try SymHash.parseSymtab(command: cmds[0])

        XCTAssertNotNil(symtab)
        XCTAssertEqual(symtab?.symoff, 56)
        XCTAssertEqual(symtab?.nsyms, 0)
    }

    func testParseSymtabWrongCommand() {
        let cmd = MachO.LoadCommand(cmd: UInt32(LC_SEGMENT_64), data: Data(repeating: 0, count: 24))

        XCTAssertNil(try SymHash.parseSymtab(command: cmd))
    }

    func testParseSymtabTooShort() {
        let cmd = MachO.LoadCommand(cmd: UInt32(LC_SYMTAB), data: Data(repeating: 0, count: 8))

        XCTAssertThrowsError(try SymHash.parseSymtab(command: cmd)) { error in
            XCTAssertEqual(error as? ParserError, .truncatedLoadCommand(cmd: UInt32(LC_SYMTAB), size: 8, expectedSize: 24))
        }
    }

    // MARK: - externalSymbolNames / symbolName

    /**
     An `nlist` / `nlist_64` entry with the given string index and type; the trailing fields are zero.
     */
    private func nlist(strx: UInt32, type: UInt8, is64: Bool = true) -> Data {
        var entry = Data(count: is64 ? 16 : 12)
        entry.withUnsafeMutableBytes { ptr in
            ptr.storeBytes(of: strx, toByteOffset: 0, as: UInt32.self)
            ptr.storeBytes(of: type, toByteOffset: 4, as: UInt8.self)
        }
        return entry
    }

    /**
     `externalSymbolNames` decoded for comparison: it returns bytes.
     */
    private func externalSymbolNames(_ data: Data, _ symtab: symtab_command, is64: Bool = true, swap: Bool = false) throws -> [String] {
        try SymHash.externalSymbolNames(data: data, symtab: symtab, is64: is64, swap: swap).map { String(decoding: $0, as: UTF8.self) }
    }

    /**
     A string table followed by one undefined external symbol per index, and its `symtab_command`.
     */
    private func symbols(strings: Data, strsize: Int? = nil, indexes: [UInt32]) -> (data: Data, symtab: symtab_command) {
        var data = strings
        for strx in indexes {
            data.append(self.nlist(strx: strx, type: 0x01))
        }
        let symtab = symtab_command(cmd: UInt32(LC_SYMTAB), cmdsize: 24, symoff: UInt32(strings.count), nsyms: UInt32(indexes.count), stroff: 0, strsize: UInt32(strsize ?? strings.count))
        return (data, symtab)
    }

    func testExternalSymbolNamesKeepsUndefinedExternalsOnly() throws {
        // Only N_UNDF | N_EXT entries count: a defined external (N_SECT), a local, and a stab are skipped.
        let strTable = Data("_puts\u{0}_main\u{0}_local\u{0}".utf8)
        let symoff = UInt32(strTable.count)
        var data = strTable
        data.append(self.nlist(strx: 0, type: 0x01)) // _puts: N_UNDF | N_EXT
        data.append(self.nlist(strx: 6, type: 0x0f)) // _main: N_SECT | N_EXT
        data.append(self.nlist(strx: 12, type: 0x0e)) // _local: N_SECT
        data.append(self.nlist(strx: 0, type: 0x21)) // stab entry carrying N_EXT

        let symtab = symtab_command(cmd: UInt32(LC_SYMTAB), cmdsize: 24, symoff: symoff, nsyms: 4, stroff: 0, strsize: UInt32(strTable.count))
        XCTAssertEqual(try self.externalSymbolNames(data, symtab), ["_puts"])
    }

    func testExternalSymbolNamesSwapsStringIndex() throws {
        // A foreign-endian slice stores n_strx byte-swapped; the reader must swap it back before indexing.
        let strTable = Data("_a\u{0}_b\u{0}".utf8)
        let symoff = UInt32(strTable.count)
        var data = strTable
        data.append(self.nlist(strx: UInt32(3).byteSwapped, type: 0x01))

        let symtab = symtab_command(cmd: UInt32(LC_SYMTAB), cmdsize: 24, symoff: symoff, nsyms: 1, stroff: 0, strsize: UInt32(strTable.count))
        XCTAssertEqual(try self.externalSymbolNames(data, symtab, swap: true), ["_b"])
    }

    func testSymbolNameUnterminatedTableIsBounded() throws {
        // A string table with no NUL terminator: the name ends with the table, whatever follows it in the file.
        let (data, symtab) = self.symbols(strings: Data("_main".utf8), indexes: [0])

        XCTAssertEqual(try self.externalSymbolNames(data, symtab), ["_main"])
    }

    func testSymbolNameStrxBeyondStrsizeThrows() {
        // strx points past the declared string table extent even though it is within the file.
        let (data, symtab) = self.symbols(strings: Data("_main\u{0}padding".utf8), strsize: 6, indexes: [6])

        XCTAssertThrowsError(try self.externalSymbolNames(data, symtab)) { error in
            XCTAssertEqual(error as? ParserError, .invalidStringTableIndex(index: 6, tableSize: 6))
        }
    }

    func testExternalSymbolNamesAcrossWindows() throws {
        // The string table is read in windows of File.chunkSize from the names wanted: names crossing a window's end,
        // overlapping names, a repeated index, and a last name running to the end of the table all read whole, in
        // table order.
        var strings = Data(repeating: 0x2e, count: 3 * File.chunkSize)
        func put(_ name: String, at offset: Int) {
            strings.replaceSubrange(offset ..< offset + name.utf8.count + 1, with: Data(name.utf8) + Data([0]))
        }
        let crossing = File.chunkSize - 3
        put("_crossing_a_window", at: crossing)
        put("_overlapping", at: 2 * File.chunkSize + 100)
        put("_first", at: 10)
        strings.replaceSubrange(strings.count - 5 ..< strings.count, with: Data("_last".utf8))
        let indexes = [crossing, 2 * File.chunkSize + 100, 2 * File.chunkSize + 103, 10, crossing, strings.count - 5].map(UInt32.init)
        let (data, symtab) = self.symbols(strings: strings, indexes: indexes)

        let expected = indexes.map { strx in
            String(decoding: strings[Int(strx)...].prefix { $0 != 0 }, as: UTF8.self)
        }
        XCTAssertEqual(expected, ["_crossing_a_window", "_overlapping", "erlapping", "_first", "_crossing_a_window", "_last"])
        XCTAssertEqual(try self.externalSymbolNames(data, symtab), expected)
    }

    func testExternalSymbolNamesReportTheFirstFailureInTableOrder() throws {
        // As if each name were read in turn: names beyond the limit before a bad index fail as too long, and a bad
        // index before them fails as a bad index.
        let name = Data(repeating: 0x41, count: 1 << 20) + Data([0])
        let count = SymHash.maxSymbolNamesLength / (1 << 20) + 1
        let bad = UInt32(name.count)

        let (tooLong, tooLongTable) = self.symbols(strings: name, indexes: Array(repeating: 0, count: count) + [bad])
        XCTAssertThrowsError(try self.externalSymbolNames(tooLong, tooLongTable)) { error in
            XCTAssertEqual(error as? ParserError, .symbolNamesTooLong(limit: SymHash.maxSymbolNamesLength))
        }
        let (badIndex, badIndexTable) = self.symbols(strings: name, indexes: [bad] + Array(repeating: 0, count: count))
        XCTAssertThrowsError(try self.externalSymbolNames(badIndex, badIndexTable)) { error in
            XCTAssertEqual(error as? ParserError, .invalidStringTableIndex(index: bad, tableSize: bad))
        }
    }

    func testExternalSymbolNames32BitStride() throws {
        // A 32-bit slice packs symbols as 12-byte `nlist`; the reader must use the 12-byte stride so the
        // second entry's n_strx is read at the right offset rather than 4 bytes into a 16-byte gap.
        let strTable = Data("_a\u{0}_b\u{0}".utf8)
        let symoff = UInt32(strTable.count)
        var data = strTable
        data.append(self.nlist(strx: 0, type: 0x01, is64: false)) // "_a"
        data.append(self.nlist(strx: 3, type: 0x01, is64: false)) // "_b"

        let symtab = symtab_command(cmd: UInt32(LC_SYMTAB), cmdsize: 24, symoff: symoff, nsyms: 2, stroff: 0, strsize: UInt32(strTable.count))
        XCTAssertEqual(try self.externalSymbolNames(data, symtab, is64: false), ["_a", "_b"])
    }

    func testExternalSymbolNamesAreBounded() throws {
        // Names may overlap: symbols all pointing at one long name add up to far more than the file holds.
        let name = Data(repeating: 0x41, count: 1 << 20)
        let count = SymHash.maxSymbolNamesLength / name.count + 1
        var data = name
        for _ in 0 ..< count {
            data.append(self.nlist(strx: 0, type: 0x01))
        }
        let symtab = symtab_command(cmd: UInt32(LC_SYMTAB), cmdsize: 24, symoff: UInt32(name.count), nsyms: UInt32(count), stroff: 0, strsize: UInt32(name.count))

        XCTAssertThrowsError(try SymHash.externalSymbolNames(data: data, symtab: symtab, is64: true, swap: false)) { error in
            XCTAssertEqual(error as? ParserError, .symbolNamesTooLong(limit: SymHash.maxSymbolNamesLength))
        }
        // Up to the limit, overlapping names are names like any other.
        let atLimit = symtab_command(cmd: UInt32(LC_SYMTAB), cmdsize: 24, symoff: UInt32(name.count), nsyms: UInt32(count - 1), stroff: 0, strsize: UInt32(name.count))
        XCTAssertEqual(try SymHash.externalSymbolNames(data: data, symtab: atLimit, is64: true, swap: false).count, count - 1)
    }

    func testExternalSymbolNamesOutOfBounds() {
        let data = Data(count: 10)
        let symtab = symtab_command(cmd: UInt32(LC_SYMTAB), cmdsize: 24, symoff: 0, nsyms: 100, stroff: 0, strsize: 10)

        XCTAssertThrowsError(try SymHash.externalSymbolNames(data: data, symtab: symtab, is64: true, swap: false)) { error in
            XCTAssertEqual(error as? ParserError, .invalidSymbolTableRange(offset: 0, count: 100, fileSize: 10))
        }
    }

    func testSymbolNameOutOfBounds() {
        let (data, symtab) = self.symbols(strings: Data(count: 4), indexes: [100])

        XCTAssertThrowsError(try self.externalSymbolNames(data, symtab)) { error in
            XCTAssertEqual(error as? ParserError, .invalidStringTableIndex(index: 100, tableSize: 4))
        }
    }

    // MARK: - Architectures

    func testArchitectureReadsAtItsOffset() throws {
        let fat = self.makeFat()
        guard case let .fat(archs) = try Universal.open(data: fat) else {
            return XCTFail("Expected fat")
        }
        let image = try XCTUnwrap(MachO(File(data: fat), offset: archs[0].range.lowerBound, length: archs[0].range.count))

        XCTAssertEqual(image.offset, archs[0].range.lowerBound)
        XCTAssertEqual(image.length, archs[0].range.count)
        XCTAssertEqual(image.cpuType, CPU_TYPE_ARM64)
        // Load commands count from the image's start, wherever it lies in the file.
        XCTAssertEqual(image.loadCommands.first?.data.startIndex, MemoryLayout<mach_header_64>.size)
    }

    // MARK: - machOEnd (logical extent / exact-image trimming)

    func testMachOEndNoTrailingSlack() {
        let data = self.makeThin64()

        XCTAssertEqual(MachO.logicalEnd(data: data), data.count)
    }

    func testMachOEndStripsAppendedGarbage() {
        var data = self.makeThin64()
        let original = data.count
        data.append(Data(repeating: 0x41, count: 100))

        XCTAssertEqual(MachO.logicalEnd(data: data), original)
    }

    func testMachOEndSwappedStripsAppendedGarbage() {
        var data = self.makeThin64Swapped()
        let original = data.count
        data.append(Data(repeating: 0xff, count: 64))

        XCTAssertEqual(MachO.logicalEnd(data: data), original)
    }

    func testMachOEndNonMachOReturnsFullLength() {
        let data = Data("not a mach-o, just some text".utf8)

        XCTAssertEqual(MachO.logicalEnd(data: data), data.count)
    }

    func testMachOEndTruncatedReturnsFullLength() {
        let data = Data([0xcf, 0xfa, 0xed]) // truncated MH_MAGIC_64

        XCTAssertEqual(MachO.logicalEnd(data: data), data.count)
    }

    func testMachOEndRealBinaryWithinBounds() throws {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: "/bin/ls")) else {
            throw XCTSkip("/bin/ls not readable")
        }

        let slice: Data = switch try Universal.open(data: data) {
        case let .fat(archs): Universal.sliceData(fileData: data, arch: archs[0])
        case .thin: data
        case .notMachO: Data()
        }
        let end = MachO.logicalEnd(data: slice)

        XCTAssertGreaterThan(end, 0)
        XCTAssertLessThanOrEqual(end, slice.count)
    }

    func testExactHashIgnoresAppendedGarbage() throws {
        var macho = self.makeThin64()
        let cleanEnd = MachO.logicalEnd(data: macho)
        let cleanHash = try ByteHash.sha256.digest(Data(macho.prefix(cleanEnd)))

        macho.append(Data(repeating: 0x41, count: 4096))
        let dirtyEnd = MachO.logicalEnd(data: macho)
        let dirtyTrimmed = try ByteHash.sha256.digest(Data(macho.prefix(dirtyEnd)))
        let dirtyWhole = try ByteHash.sha256.digest(macho)

        XCTAssertEqual(cleanHash, dirtyTrimmed, "exact (trimmed) hash must be stable across appended garbage")
        XCTAssertNotEqual(cleanHash, dirtyWhole, "whole-file hash must change when garbage is appended")
    }

    func testMachOEndLinkedit64Trim() {
        var data = Data()
        data.appendUInt32(MH_MAGIC_64)
        data.appendInt32(CPU_TYPE_ARM64)
        data.appendInt32(0)
        data.appendUInt32(2) // filetype MH_EXECUTE
        data.appendUInt32(1) // ncmds
        data.appendUInt32(72) // sizeofcmds (segment_command_64 = 72)
        data.appendUInt32(0)
        data.appendUInt32(0)
        data.appendUInt32(UInt32(LC_SEGMENT_64))
        data.appendUInt32(72) // cmdsize
        data.append(Data("__LINKEDIT".utf8)); data.append(Data(repeating: 0, count: 6)) // segname[16]
        data.appendUInt64(0) // vmaddr
        data.appendUInt64(256) // vmsize
        data.appendUInt64(0) // fileoff
        data.appendUInt64(256) // filesize -> logical end 256
        data.appendUInt32(7) // maxprot
        data.appendUInt32(5) // initprot
        data.appendUInt32(0) // nsects
        data.appendUInt32(0) // flags
        data.append(Data(repeating: 0xab, count: 256 - data.count)) // segment content
        let logicalEnd = data.count
        data.append(Data(repeating: 0x41, count: 100)) // appended garbage

        XCTAssertEqual(MachO.logicalEnd(data: data), logicalEnd)
    }

    func testMachOEndLinkedit32Trim() {
        var data = Data()
        data.appendUInt32(MH_MAGIC)
        data.appendInt32(CPU_TYPE_ARM)
        data.appendInt32(0)
        data.appendUInt32(2) // filetype
        data.appendUInt32(1) // ncmds
        data.appendUInt32(56) // sizeofcmds (segment_command = 56)
        data.appendUInt32(0)
        data.appendUInt32(UInt32(LC_SEGMENT))
        data.appendUInt32(56) // cmdsize
        data.append(Data("__LINKEDIT".utf8)); data.append(Data(repeating: 0, count: 6))
        data.appendUInt32(0) // vmaddr
        data.appendUInt32(200) // vmsize
        data.appendUInt32(0) // fileoff
        data.appendUInt32(200) // filesize -> logical end 200
        data.appendUInt32(7) // maxprot
        data.appendUInt32(5) // initprot
        data.appendUInt32(0) // nsects
        data.appendUInt32(0) // flags
        data.append(Data(repeating: 0xab, count: 200 - data.count))
        let logicalEnd = data.count
        data.append(Data(repeating: 0x41, count: 80))

        XCTAssertEqual(MachO.logicalEnd(data: data), logicalEnd)
    }

    func testMachOEndWithoutLinkeditOrSymtabKeepsWholeSlice() {
        // Security's MachO ends the image only at __LINKEDIT or the LC_SYMTAB strings: other commands never trim.
        var data = Data()
        data.appendUInt32(MH_MAGIC_64)
        data.appendInt32(CPU_TYPE_ARM64)
        data.appendInt32(0)
        data.appendUInt32(2)
        data.appendUInt32(1) // ncmds
        data.appendUInt32(80) // sizeofcmds (dysymtab_command = 80)
        data.appendUInt32(0)
        data.appendUInt32(0)
        data.appendUInt32(UInt32(LC_DYSYMTAB))
        data.appendUInt32(80)
        for _ in 0 ..< 6 {
            data.appendUInt32(0)
        } // ilocalsym..nundefsym
        data.appendUInt32(0); data.appendUInt32(0) // tocoff, ntoc
        data.appendUInt32(0); data.appendUInt32(0) // modtaboff, nmodtab
        data.appendUInt32(0); data.appendUInt32(0) // extrefsymoff, nextrefsyms
        data.appendUInt32(112); data.appendUInt32(4) // indirectsymoff=112, nindirectsyms=4 -> 128
        data.appendUInt32(0); data.appendUInt32(0) // extreloff, nextrel
        data.appendUInt32(0); data.appendUInt32(0) // locreloff, nlocrel
        data.append(Data(repeating: 0xab, count: 128 - data.count))
        data.append(Data(repeating: 0x41, count: 50))

        XCTAssertEqual(MachO.logicalEnd(data: data), data.count)
    }

    func testMachOEndFirstCommandWins() {
        // LC_SYMTAB comes before __LINKEDIT here, so its string table ends the image even though __LINKEDIT reaches further.
        var data = Data()
        data.appendUInt32(MH_MAGIC_64)
        data.appendInt32(CPU_TYPE_ARM64)
        data.appendInt32(0)
        data.appendUInt32(2)
        data.appendUInt32(2) // ncmds
        data.appendUInt32(96) // sizeofcmds = LC_SYMTAB(24) + LC_SEGMENT_64(72)
        data.appendUInt32(0)
        data.appendUInt32(0)
        data.appendUInt32(UInt32(LC_SYMTAB))
        data.appendUInt32(24)
        data.appendUInt32(128); data.appendUInt32(0); data.appendUInt32(128); data.appendUInt32(16) // strings end at 144
        data.appendUInt32(UInt32(LC_SEGMENT_64))
        data.appendUInt32(72)
        data.append(Data("__LINKEDIT".utf8)); data.append(Data(repeating: 0, count: 6))
        data.appendUInt64(0); data.appendUInt64(200); data.appendUInt64(0); data.appendUInt64(200) // vmaddr, vmsize, fileoff, filesize
        data.appendUInt32(1); data.appendUInt32(1); data.appendUInt32(0); data.appendUInt32(0) // maxprot, initprot, nsects, flags
        data.append(Data(repeating: 0xab, count: 250 - data.count))

        XCTAssertEqual(MachO.logicalEnd(data: data), 144)
    }

    func testMachOEndPastSliceKeepsWholeSlice() {
        var data = self.makeThin64()
        data.replaceSubrange(52 ..< 56, with: withUnsafeBytes(of: UInt32(1000).littleEndian) { Data($0) }) // strsize past the slice

        XCTAssertEqual(MachO.logicalEnd(data: data), data.count)
    }

    func testMachOEndFatSliceStripsGarbage() throws {
        let cleanSlice = self.makeThin64()
        let cleanEnd = cleanSlice.count
        var slice = cleanSlice
        slice.append(Data(repeating: 0x41, count: 64)) // garbage inside the slice region

        var fat = Data()
        fat.appendUInt32BE(FAT_MAGIC)
        fat.appendUInt32BE(1)
        fat.appendInt32BE(CPU_TYPE_ARM64)
        fat.appendInt32BE(0)
        fat.appendUInt32BE(4096) // offset
        fat.appendUInt32BE(UInt32(slice.count)) // size (includes garbage)
        fat.appendUInt32BE(12)
        fat.append(Data(repeating: 0, count: 4096 - fat.count))
        fat.append(slice)

        guard case let .fat(archs) = try Universal.open(data: fat) else {
            XCTFail("Expected fat"); return
        }
        let extracted = Universal.sliceData(fileData: fat, arch: archs[0])
        XCTAssertEqual(MachO.logicalEnd(data: extracted), cleanEnd, "per-arch slice trim must strip in-slice garbage")
    }

    func testMachOEndSkipsOtherCommands() {
        var data = Data()
        data.appendUInt32(MH_MAGIC_64)
        data.appendInt32(CPU_TYPE_ARM64)
        data.appendInt32(0)
        data.appendUInt32(2)
        data.appendUInt32(2) // ncmds
        data.appendUInt32(48) // sizeofcmds = LC_UUID(24) + LC_SYMTAB(24)
        data.appendUInt32(0)
        data.appendUInt32(0)
        data.appendUInt32(UInt32(bitPattern: LC_UUID)) // any other command
        data.appendUInt32(24)
        data.append(Data(repeating: 0xaa, count: 16))
        data.appendUInt32(UInt32(LC_SYMTAB)) // handled command
        data.appendUInt32(24)
        data.appendUInt32(80); data.appendUInt32(0); data.appendUInt32(80); data.appendUInt32(0)
        let logicalEnd = data.count // 80
        data.append(Data(repeating: 0x41, count: 50))

        XCTAssertEqual(MachO.logicalEnd(data: data), logicalEnd, "a command before LC_SYMTAB must not block trimming")
    }

    // MARK: - fileEnd (whole-file logical end)

    func testFileEndThinTrims() throws {
        var thin = self.makeThin64()
        let clean = thin.count
        thin.append(Data(repeating: 0x41, count: 100))
        XCTAssertEqual(try Universal.fileEnd(data: thin), clean)
    }

    func testFileEndFatStripsTrailingGarbage() throws {
        var fat = self.makeFat()
        let clean = fat.count
        fat.append(Data(repeating: 0x41, count: 200))
        XCTAssertEqual(try Universal.fileEnd(data: fat), clean)
    }

    func testFileEndFat64RejectsHugeOffset() {
        var data = Data()
        data.appendUInt32BE(FAT_MAGIC_64)
        data.appendUInt32BE(1)
        data.appendInt32BE(CPU_TYPE_ARM64)
        data.appendInt32BE(0)
        data.appendUInt64BE(UInt64.max)
        data.appendUInt64BE(1)
        data.appendUInt32BE(0)
        data.appendUInt32BE(0)

        XCTAssertThrowsError(try Universal.fileEnd(data: data)) { error in
            XCTAssertEqual(
                error.localizedDescription,
                "Invalid Mach-O: fat architecture range at offset \(UInt64.max) with size 1 is outside the 40-byte file",
            )
        }
    }

    func testErrorDescriptionsAgreeWithCounts() {
        XCTAssertEqual(
            ParserError.invalidLoadCommandTable(size: 24, fileSize: 40).localizedDescription,
            "Invalid Mach-O: sizeofcmds 24 does not hold a load-command table in the 40-byte slice",
        )
        XCTAssertEqual(
            ParserError.invalidFatArchitectureTable(count: 1, fileSize: 20).localizedDescription,
            "Invalid Mach-O: nfat_arch 1 does not fit in the 20-byte file",
        )
        XCTAssertEqual(
            ParserError.invalidSymbolTableRange(offset: 32, count: 1, fileSize: 40).localizedDescription,
            "Invalid Mach-O: symbol table at offset 32 with 1 entry is outside the 40-byte slice",
        )
        XCTAssertEqual(
            ParserError.invalidSymbolTableRange(offset: 32, count: 2, fileSize: 40).localizedDescription,
            "Invalid Mach-O: symbol table at offset 32 with 2 entries is outside the 40-byte slice",
        )
        XCTAssertEqual(
            CDHashError.truncatedCodeSignatureSuperblob(signatureSize: 1).localizedDescription,
            "Invalid Mach-O: code signature is only 1 byte; an embedded signature header requires 12",
        )
        XCTAssertEqual(
            ParserError.truncatedLoadCommand(cmd: 0x19, size: 1, expectedSize: 72).localizedDescription,
            "Invalid Mach-O: load command 0x19 is only 1 byte; its structure requires 72",
        )
    }

    func testFileEndNonMachOReturnsFullLength() throws {
        let data = Data("plain text, not mach-o".utf8)
        XCTAssertEqual(try Universal.fileEnd(data: data), data.count)
    }
}
