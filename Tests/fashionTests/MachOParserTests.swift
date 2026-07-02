@testable import fashion
import MachO
import XCTest

final class MachOParserTests: XCTestCase {
    func testArchNameARM64() {
        XCTAssertEqual(MachOParser.archName(cpuType: CPU_TYPE_ARM64, cpuSubtype: 0), "arm64")
    }

    func testArchNameARM64E() {
        XCTAssertEqual(MachOParser.archName(cpuType: CPU_TYPE_ARM64, cpuSubtype: CPU_SUBTYPE_ARM64E), "arm64e")
    }

    func testArchNameX86_64() {
        XCTAssertEqual(MachOParser.archName(cpuType: CPU_TYPE_X86_64, cpuSubtype: 3), "x86_64")
    }

    func testArchNameI386() {
        XCTAssertEqual(MachOParser.archName(cpuType: CPU_TYPE_I386, cpuSubtype: 0), "i386")
    }

    func testArchNameARM() {
        XCTAssertEqual(MachOParser.archName(cpuType: CPU_TYPE_ARM, cpuSubtype: 0), "arm")
    }

    func testArchNamePPC() {
        XCTAssertEqual(MachOParser.archName(cpuType: CPU_TYPE_POWERPC, cpuSubtype: 0), "ppc")
    }

    func testArchNamePPC64() {
        XCTAssertEqual(MachOParser.archName(cpuType: CPU_TYPE_POWERPC64, cpuSubtype: 0), "ppc64")
    }

    func testArchNameMasksCapabilityBits() {
        let subtypeWithCaps = CPU_SUBTYPE_ARM64E | cpu_subtype_t(bitPattern: 0x8000_0000)
        XCTAssertEqual(MachOParser.archName(cpuType: CPU_TYPE_ARM64, cpuSubtype: subtypeWithCaps), "arm64e")
    }

    func testArchNameUnknownCPU() {
        XCTAssertEqual(MachOParser.archName(cpuType: 9999, cpuSubtype: 0), "unknown")
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
        data.appendUInt32(0) // ncmds
        data.appendUInt32(0) // sizeofcmds
        data.appendUInt32(0) // flags
        return data
    }

    private func makeThin32Swapped(cpuType: cpu_type_t = CPU_TYPE_I386, cpuSubtype: cpu_subtype_t = 0) -> Data {
        var data = Data()
        data.appendUInt32(MH_CIGAM)
        data.appendInt32(cpuType.byteSwapped)
        data.appendInt32(cpuSubtype.byteSwapped)
        data.appendUInt32(UInt32(2).byteSwapped)
        data.appendUInt32(0)
        data.appendUInt32(0)
        data.appendUInt32(0)
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

    func testOpenNotMachO() {
        let data = Data("Hello, World!".utf8)

        if case .notMachO = MachOParser.open(data: data) {
            // pass
        } else {
            XCTFail("Expected notMachO")
        }
    }

    func testOpenEmptyData() {
        let data = Data()

        if case .notMachO = MachOParser.open(data: data) {
            // pass
        } else {
            XCTFail("Expected notMachO for empty data")
        }
    }

    func testOpenThin64() {
        let data = self.makeThin64(cpuType: CPU_TYPE_ARM64, cpuSubtype: CPU_SUBTYPE_ARM64E)

        if case let .thin(cpu, sub) = MachOParser.open(data: data) {
            XCTAssertEqual(cpu, CPU_TYPE_ARM64)
            XCTAssertEqual(sub, CPU_SUBTYPE_ARM64E)
        } else {
            XCTFail("Expected thin for MH_MAGIC_64")
        }
    }

    func testOpenThin64Swapped() {
        let data = self.makeThin64Swapped(cpuType: CPU_TYPE_X86_64, cpuSubtype: 3)

        if case let .thin(cpu, sub) = MachOParser.open(data: data) {
            XCTAssertEqual(cpu, CPU_TYPE_X86_64)
            XCTAssertEqual(sub, 3)
        } else {
            XCTFail("Expected thin for MH_CIGAM_64")
        }
    }

    func testOpenThin32() {
        let data = self.makeThin32(cpuType: CPU_TYPE_I386)

        if case let .thin(cpu, _) = MachOParser.open(data: data) {
            XCTAssertEqual(cpu, CPU_TYPE_I386)
        } else {
            XCTFail("Expected thin for MH_MAGIC")
        }
    }

    func testOpenThin32Swapped() {
        let data = self.makeThin32Swapped(cpuType: CPU_TYPE_ARM)

        if case let .thin(cpu, _) = MachOParser.open(data: data) {
            XCTAssertEqual(cpu, CPU_TYPE_ARM)
        } else {
            XCTFail("Expected thin for MH_CIGAM")
        }
    }

    func testOpenFat() {
        let data = self.makeFat()

        if case let .fat(archs) = MachOParser.open(data: data) {
            XCTAssertEqual(archs.count, 1)
            XCTAssertEqual(archs[0].cpuType, CPU_TYPE_ARM64)
        } else {
            XCTFail("Expected fat binary")
        }
    }

    func testOpenFat64() {
        let data = self.makeFat64()

        if case let .fat(archs) = MachOParser.open(data: data) {
            XCTAssertEqual(archs.count, 1)
            XCTAssertEqual(archs[0].cpuType, CPU_TYPE_ARM64)
            XCTAssertEqual(archs[0].offset, 4096)
            let slice = MachOParser.sliceData(fileData: data, arch: archs[0])
            XCTAssertEqual(slice.count, Int(archs[0].size))
        } else {
            XCTFail("Expected fat64 binary")
        }
    }

    func testSliceDataRejectsHugeOffset() {
        // A crafted 64-bit fat arch with an out-of-range offset must not trap on Int(exactly:).
        let arch = MachOParser.FatArch(cpuType: 0, cpuSubtype: 0, offset: UInt64.max, size: 100, align: 0)
        XCTAssertTrue(MachOParser.sliceData(fileData: Data(count: 4096), arch: arch).isEmpty)
    }

    func testOpenFromPath() throws {
        let url = FileManager.default.temporaryDirectory / "fashion-macho-\(UUID())"
        try self.makeThin64().write(to: url)
        defer {
            try? FileManager.default.removeItem(at: url)
        }

        if case .thin = MachOParser.open(path: url.path()) {
            // pass
        } else {
            XCTFail("Expected thin from path")
        }
    }

    func testOpenFromMissingPath() {
        if case .notMachO = MachOParser.open(path: "/tmp/fashion-nonexistent-\(UUID())") {
            // pass
        } else {
            XCTFail("Expected notMachO for missing file")
        }
    }

    // MARK: - isMachO (cheap magic peek)

    func testIsMachOTrueForThinBinary() throws {
        let url = FileManager.default.temporaryDirectory / "fashion-ismacho-\(UUID())"
        try self.makeThin64().write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }

        XCTAssertTrue(try MachOParser.isMachO(path: url.path()))
    }

    func testIsMachOFalseForNonMachO() throws {
        let url = FileManager.default.temporaryDirectory / "fashion-ismacho-\(UUID()).txt"
        try Data("not a mach-o, just text".utf8).write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }

        XCTAssertFalse(try MachOParser.isMachO(path: url.path()))
    }

    func testIsMachOThrowsForMissingFile() {
        XCTAssertThrowsError(try MachOParser.isMachO(path: "/tmp/fashion-nonexistent-\(UUID())"))
    }

    func testIsMachOTrueForFatBinary() throws {
        let url = FileManager.default.temporaryDirectory / "fashion-fat-\(UUID())"
        try self.makeFat().write(to: url) // 1 architecture
        defer { try? FileManager.default.removeItem(at: url) }

        XCTAssertTrue(try MachOParser.isMachO(path: url.path()))
    }

    func testIsMachOFalseForJavaClass() throws {
        // 0xCAFEBABE shared magic, but the big-endian u32 at offset 4 is a Java major version (52), not an arch count.
        var data = Data([0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x34])
        data.append(Data(repeating: 0, count: 64))
        let url = FileManager.default.temporaryDirectory / "fashion-class-\(UUID()).class"
        try data.write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }

        XCTAssertFalse(try MachOParser.isMachO(path: url.path()))
    }

    func testIsMachOFalseForBogusFatArchCount() throws {
        var data = Data()
        data.appendUInt32BE(FAT_MAGIC)
        data.appendUInt32BE(9999) // absurd architecture count — not a universal binary
        data.append(Data(repeating: 0, count: 64))
        let url = FileManager.default.temporaryDirectory / "fashion-bogusfat-\(UUID())"
        try data.write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }

        XCTAssertFalse(try MachOParser.isMachO(path: url.path()))
    }

    // MARK: - Load commands

    func testLoadCommandsThin64() {
        let data = self.makeThin64()
        let cmds = MachOParser.loadCommands(data: data)

        XCTAssertEqual(cmds.count, 1)
        XCTAssertEqual(cmds[0].cmd, UInt32(LC_SYMTAB))
        XCTAssertEqual(cmds[0].cmdSize, 24)
    }

    func testLoadCommandsThin64Swapped() {
        let data = self.makeThin64Swapped()
        let cmds = MachOParser.loadCommands(data: data)

        XCTAssertEqual(cmds.count, 1)
        XCTAssertEqual(cmds[0].cmd, UInt32(LC_SYMTAB))
    }

    func testLoadCommandsEmptyData() {
        XCTAssertTrue(MachOParser.loadCommands(data: Data()).isEmpty)
    }

    func testLoadCommandsNotMachO() {
        XCTAssertTrue(MachOParser.loadCommands(data: Data("hello".utf8)).isEmpty)
    }

    func testLoadCommandsTruncatedHeader() {
        var data = Data()
        data.appendUInt32(MH_MAGIC_64)

        XCTAssertTrue(MachOParser.loadCommands(data: data).isEmpty)
    }

    // MARK: - parseSymtab

    func testParseSymtab() {
        let data = self.makeThin64()
        let cmds = MachOParser.loadCommands(data: data)
        let symtab = MachOParser.parseSymtab(command: cmds[0])

        XCTAssertNotNil(symtab)
        XCTAssertEqual(symtab?.symoff, 56)
        XCTAssertEqual(symtab?.nsyms, 0)
    }

    func testParseSymtabWrongCommand() {
        let cmd = MachOParser.LoadCommand(cmd: UInt32(LC_SEGMENT_64), cmdSize: 24, data: Data(repeating: 0, count: 24))

        XCTAssertNil(MachOParser.parseSymtab(command: cmd))
    }

    func testParseSymtabTooShort() {
        let cmd = MachOParser.LoadCommand(cmd: UInt32(LC_SYMTAB), cmdSize: 8, data: Data(repeating: 0, count: 8))

        XCTAssertNil(MachOParser.parseSymtab(command: cmd))
    }

    // MARK: - readSymbols / symbolName

    func testReadSymbolsAndName() {
        let symbolName = "_main"
        let strTable = Data(symbolName.utf8) + Data([0])

        let stroff: UInt32 = 0
        let symoff = UInt32(strTable.count)
        var data = strTable

        // nlist_64: n_strx(4) + n_type(1) + n_sect(1) + n_desc(2) + n_value(8) = 16 bytes
        var entry = Data(count: 16)
        entry.withUnsafeMutableBytes { ptr in
            ptr.storeBytes(of: UInt32(0), toByteOffset: 0, as: UInt32.self) // strx = 0 -> "_main"
            ptr.storeBytes(of: UInt8(0x0f), toByteOffset: 4, as: UInt8.self) // N_SECT | N_EXT
        }
        data.append(entry)

        let symtab = symtab_command(cmd: UInt32(LC_SYMTAB), cmdsize: 24, symoff: symoff, nsyms: 1, stroff: stroff, strsize: UInt32(strTable.count))
        let symbols = MachOParser.readSymbols(data: data, symtab: symtab)

        XCTAssertEqual(symbols.count, 1)
        XCTAssertEqual(symbols[0].n_un.n_strx, 0)
        XCTAssertEqual(symbols[0].n_type, 0x0f)

        let name = MachOParser.symbolName(data: data, stroff: stroff, strsize: UInt32(strTable.count), strx: 0)

        XCTAssertEqual(name, symbolName)
    }

    func testSymbolNameUnterminatedTableIsBounded() {
        // A string table with no NUL terminator: the scan must stop at strsize, not run off the buffer.
        let strTable = Data("_main".utf8)
        let symbolName = MachOParser.symbolName(data: strTable, stroff: 0, strsize: UInt32(strTable.count), strx: 0)

        XCTAssertEqual(symbolName, "_main")
    }

    func testSymbolNameStrxBeyondStrsizeReturnsNil() {
        // strx points past the declared string table extent even though it is within the buffer.
        let data = Data("_main\u{0}padding".utf8)

        XCTAssertNil(MachOParser.symbolName(data: data, stroff: 0, strsize: 6, strx: 6))
    }

    func testReadSymbols32BitStride() {
        // A 32-bit slice packs symbols as 12-byte `nlist`; the reader must use the 12-byte stride so the
        // second entry's n_strx is read at the right offset rather than 4 bytes into a 16-byte gap.
        let strTable = Data("_a\u{0}_b\u{0}".utf8)
        let symoff = UInt32(strTable.count)
        var data = strTable

        func nlist32(strx: UInt32, type: UInt8) -> Data {
            var entry = Data(count: 12)
            entry.withUnsafeMutableBytes { ptr in
                ptr.storeBytes(of: strx, toByteOffset: 0, as: UInt32.self)
                ptr.storeBytes(of: type, toByteOffset: 4, as: UInt8.self)
            }
            return entry
        }
        data.append(nlist32(strx: 0, type: 0x0f)) // "_a"
        data.append(nlist32(strx: 3, type: 0x0f)) // "_b"

        let symtab = symtab_command(cmd: UInt32(LC_SYMTAB), cmdsize: 24, symoff: symoff, nsyms: 2, stroff: 0, strsize: UInt32(strTable.count))
        let symbols = MachOParser.readSymbols(data: data, symtab: symtab, is64: false, swap: false)

        XCTAssertEqual(symbols.count, 2)
        XCTAssertEqual(symbols[0].n_un.n_strx, 0)
        XCTAssertEqual(symbols[1].n_un.n_strx, 3)
    }

    func testReadSymbolsOutOfBounds() {
        let data = Data(count: 10)
        let symtab = symtab_command(cmd: UInt32(LC_SYMTAB), cmdsize: 24, symoff: 0, nsyms: 100, stroff: 0, strsize: 10)

        XCTAssertTrue(MachOParser.readSymbols(data: data, symtab: symtab).isEmpty)
    }

    func testSymbolNameOutOfBounds() {
        let data = Data(count: 4)

        XCTAssertNil(MachOParser.symbolName(data: data, stroff: 0, strsize: 4, strx: 100))
    }

    // MARK: - sliceData

    func testSliceData() {
        let fat = self.makeFat()
        if case let .fat(archs) = MachOParser.open(data: fat) {
            let slice = MachOParser.sliceData(fileData: fat, arch: archs[0])
            XCTAssertFalse(slice.isEmpty)

            let magic = slice.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }
            XCTAssertEqual(magic, MH_MAGIC_64)
        } else {
            XCTFail("Expected fat")
        }
    }

    func testSliceDataOutOfBounds() {
        let arch = MachOParser.FatArch(cpuType: 0, cpuSubtype: 0, offset: 9999, size: 100, align: 0)
        let data = Data(count: 10)

        XCTAssertTrue(MachOParser.sliceData(fileData: data, arch: arch).isEmpty)
    }

    // MARK: - machOEnd (logical extent / exact-image trimming)

    func testMachOEndNoTrailingSlack() {
        let data = self.makeThin64()

        XCTAssertEqual(MachOParser.machOEnd(data: data), data.count)
    }

    func testMachOEndStripsAppendedGarbage() {
        var data = self.makeThin64()
        let original = data.count
        data.append(Data(repeating: 0x41, count: 100))

        XCTAssertEqual(MachOParser.machOEnd(data: data), original)
    }

    func testMachOEndSwappedStripsAppendedGarbage() {
        var data = self.makeThin64Swapped()
        let original = data.count
        data.append(Data(repeating: 0xff, count: 64))

        XCTAssertEqual(MachOParser.machOEnd(data: data), original)
    }

    func testMachOEndNonMachOReturnsFullLength() {
        let data = Data("not a mach-o, just some text".utf8)

        XCTAssertEqual(MachOParser.machOEnd(data: data), data.count)
    }

    func testMachOEndTruncatedReturnsFullLength() {
        let data = Data([0xcf, 0xfa, 0xed]) // truncated MH_MAGIC_64

        XCTAssertEqual(MachOParser.machOEnd(data: data), data.count)
    }

    func testMachOEndRealBinaryWithinBounds() throws {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: "/bin/ls")) else {
            throw XCTSkip("/bin/ls not readable")
        }

        let slice: Data = switch MachOParser.open(data: data) {
        case let .fat(archs): MachOParser.sliceData(fileData: data, arch: archs[0])
        case .thin: data
        case .notMachO: Data()
        }
        let end = MachOParser.machOEnd(data: slice)

        XCTAssertGreaterThan(end, 0)
        XCTAssertLessThanOrEqual(end, slice.count)
    }

    func testExactHashIgnoresAppendedGarbage() throws {
        var macho = self.makeThin64()
        let cleanEnd = MachOParser.machOEnd(data: macho)
        let cleanHash = try CryptoDigest.hash(data: Data(macho.prefix(cleanEnd)), algorithm: .sha256)

        macho.append(Data(repeating: 0x41, count: 4096))
        let dirtyEnd = MachOParser.machOEnd(data: macho)
        let dirtyTrimmed = try CryptoDigest.hash(data: Data(macho.prefix(dirtyEnd)), algorithm: .sha256)
        let dirtyWhole = try CryptoDigest.hash(data: macho, algorithm: .sha256)

        XCTAssertEqual(cleanHash, dirtyTrimmed, "exact (trimmed) hash must be stable across appended garbage")
        XCTAssertNotEqual(cleanHash, dirtyWhole, "whole-file hash must change when garbage is appended")
    }

    func testMachOEndSegment64Trim() {
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
        data.append(Data("__TEXT".utf8)); data.append(Data(repeating: 0, count: 10)) // segname[16]
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

        XCTAssertEqual(MachOParser.machOEnd(data: data), logicalEnd)
    }

    func testMachOEndSegment32Trim() {
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
        data.append(Data("__TEXT".utf8)); data.append(Data(repeating: 0, count: 10))
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

        XCTAssertEqual(MachOParser.machOEnd(data: data), logicalEnd)
    }

    func testMachOEndDysymtabTrim() {
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
        let logicalEnd = data.count
        data.append(Data(repeating: 0x41, count: 50))

        XCTAssertEqual(MachOParser.machOEnd(data: data), logicalEnd)
    }

    func testMachOEndIgnoresOversizedSizeofcmds() {
        var data = Data()
        data.appendUInt32(MH_MAGIC_64)
        data.appendInt32(CPU_TYPE_ARM64)
        data.appendInt32(0)
        data.appendUInt32(2)
        data.appendUInt32(0) // ncmds = 0
        data.appendUInt32(0xffff_ffff) // hostile sizeofcmds
        data.appendUInt32(0)
        data.appendUInt32(0)
        data.append(Data(repeating: 0x41, count: 200)) // appended garbage

        // Must fall back to the header end, not retain the appended bytes.
        XCTAssertEqual(MachOParser.machOEnd(data: data), 32)
    }

    func testMachOEndFatSliceStripsGarbage() {
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

        guard case let .fat(archs) = MachOParser.open(data: fat) else {
            XCTFail("Expected fat"); return
        }
        let extracted = MachOParser.sliceData(fileData: fat, arch: archs[0])
        XCTAssertEqual(MachOParser.machOEnd(data: extracted), cleanEnd, "per-arch slice trim must strip in-slice garbage")
    }

    func testMachOEndUnknownCommandDisablesTrim() {
        var data = Data()
        data.appendUInt32(MH_MAGIC_64)
        data.appendInt32(CPU_TYPE_ARM64)
        data.appendInt32(0)
        data.appendUInt32(2)
        data.appendUInt32(1) // ncmds
        data.appendUInt32(16) // sizeofcmds
        data.appendUInt32(0)
        data.appendUInt32(0)
        data.appendUInt32(0x0000_00ab) // unknown command id (not handled, not benign)
        data.appendUInt32(16)
        data.append(Data(repeating: 0, count: 8))
        data.append(Data(repeating: 0x41, count: 100)) // trailing bytes that must NOT be trimmed

        XCTAssertEqual(MachOParser.machOEnd(data: data), data.count, "an unrecognized command must disable trimming")
    }

    func testMachOEndBenignCommandStillTrims() {
        var data = Data()
        data.appendUInt32(MH_MAGIC_64)
        data.appendInt32(CPU_TYPE_ARM64)
        data.appendInt32(0)
        data.appendUInt32(2)
        data.appendUInt32(2) // ncmds
        data.appendUInt32(48) // sizeofcmds = LC_UUID(24) + LC_SYMTAB(24)
        data.appendUInt32(0)
        data.appendUInt32(0)
        data.appendUInt32(UInt32(bitPattern: LC_UUID)) // benign command
        data.appendUInt32(24)
        data.append(Data(repeating: 0xaa, count: 16))
        data.appendUInt32(UInt32(LC_SYMTAB)) // handled command
        data.appendUInt32(24)
        data.appendUInt32(80); data.appendUInt32(0); data.appendUInt32(80); data.appendUInt32(0)
        let logicalEnd = data.count // 80
        data.append(Data(repeating: 0x41, count: 50))

        XCTAssertEqual(MachOParser.machOEnd(data: data), logicalEnd, "a benign command must be ignored, not block trimming")
    }

    // MARK: - fileEnd (whole-file logical end)

    func testFileEndThinTrims() {
        var thin = self.makeThin64()
        let clean = thin.count
        thin.append(Data(repeating: 0x41, count: 100))
        XCTAssertEqual(MachOParser.fileEnd(data: thin), clean)
    }

    func testFileEndFatStripsTrailingGarbage() {
        var fat = self.makeFat()
        let clean = fat.count
        fat.append(Data(repeating: 0x41, count: 200))
        XCTAssertEqual(MachOParser.fileEnd(data: fat), clean)
    }

    func testFileEndNonMachOReturnsFullLength() {
        let data = Data("plain text, not mach-o".utf8)
        XCTAssertEqual(MachOParser.fileEnd(data: data), data.count)
    }
}

// MARK: - Data helpers for building synthetic binaries

private extension Data {
    mutating func appendUInt32(_ value: UInt32) {
        var v = value
        append(Data(bytes: &v, count: 4))
    }

    mutating func appendInt32(_ value: Int32) {
        var v = value
        append(Data(bytes: &v, count: 4))
    }

    mutating func appendUInt32BE(_ value: UInt32) {
        var v = value.bigEndian
        append(Data(bytes: &v, count: 4))
    }

    mutating func appendInt32BE(_ value: Int32) {
        var v = value.bigEndian
        append(Data(bytes: &v, count: 4))
    }

    mutating func appendUInt64BE(_ value: UInt64) {
        var v = value.bigEndian
        append(Data(bytes: &v, count: 8))
    }

    mutating func appendUInt64(_ value: UInt64) {
        var v = value
        append(Data(bytes: &v, count: 8))
    }
}
