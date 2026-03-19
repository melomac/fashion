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

        let name = MachOParser.symbolName(data: data, stroff: stroff, strx: 0)

        XCTAssertEqual(name, symbolName)
    }

    func testReadSymbolsOutOfBounds() {
        let data = Data(count: 10)
        let symtab = symtab_command(cmd: UInt32(LC_SYMTAB), cmdsize: 24, symoff: 0, nsyms: 100, stroff: 0, strsize: 10)

        XCTAssertTrue(MachOParser.readSymbols(data: data, symtab: symtab).isEmpty)
    }

    func testSymbolNameOutOfBounds() {
        let data = Data(count: 4)

        XCTAssertNil(MachOParser.symbolName(data: data, stroff: 0, strx: 100))
    }

    // MARK: - sliceData

    func testSliceData() {
        let fat = self.makeFat()
        if case let .fat(archs) = MachOParser.open(data: fat) {
            let slice = MachOParser.sliceData(fileData: fat, arch: archs[0])
            XCTAssertFalse(slice.isEmpty)

            let magic = slice.withUnsafeBytes {
                $0.loadUnaligned(as: UInt32.self)
            }
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
}
