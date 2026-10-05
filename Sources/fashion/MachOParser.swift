import CMachOCompat // CPU_SUBTYPE_ARM64E_X1 on SDKs older than macOS 27
import Foundation
import MachO
import MachO.dyld.utils // macho_arch_name_for_cpu_type

enum ParserError: Error, Equatable {
    case truncatedMachHeader(expectedSize: Int, fileSize: Int)
    case invalidLoadCommandTable(size: UInt32, fileSize: Int)
    case truncatedLoadCommand(cmd: UInt32, size: Int, expectedSize: Int)
    case invalidFatArchitectureTable(count: UInt32, fileSize: Int)
    case invalidFatArchitectureRange(offset: UInt64, size: UInt64, fileSize: Int)
    case invalidSymbolTableRange(offset: UInt32, count: UInt32, fileSize: Int)
    case invalidStringTableRange(offset: UInt32, size: UInt32, fileSize: Int)
    case invalidStringTableIndex(index: UInt32, tableSize: UInt32)
}

extension ParserError: LocalizedError {
    var errorDescription: String? {
        switch self {
        case let .truncatedMachHeader(expectedSize, fileSize):
            String(format: NSLocalizedString("Invalid Mach-O: expected a %d-byte header in a %d-byte file", comment: "Truncated thin Mach-O header"), expectedSize, fileSize)
        case let .invalidLoadCommandTable(size, fileSize):
            String(format: NSLocalizedString("Invalid Mach-O: sizeofcmds %u does not hold a load-command table in the %d-byte slice", comment: "Malformed Mach-O load-command table"), size, fileSize)
        case let .truncatedLoadCommand(cmd, size, expectedSize):
            String(format: NSLocalizedString("Invalid Mach-O: load command 0x%x is only %@; its structure requires %ld", comment: "Truncated Mach-O load command"), cmd, String(size, pluralizing: "byte"), expectedSize)
        case let .invalidFatArchitectureTable(count, fileSize):
            String(format: NSLocalizedString("Invalid Mach-O: nfat_arch %u does not fit in the %d-byte file", comment: "Truncated universal Mach-O architecture table"), count, fileSize)
        case let .invalidFatArchitectureRange(offset, size, fileSize):
            String(format: NSLocalizedString("Invalid Mach-O: fat architecture range at offset %llu with size %llu is outside the %d-byte file", comment: "Malformed universal Mach-O architecture range"), offset, size, fileSize)
        case let .invalidSymbolTableRange(offset, count, fileSize):
            String(format: NSLocalizedString("Invalid Mach-O: symbol table at offset %u with %@ is outside the %d-byte slice", comment: "Malformed Mach-O symbol-table range"), offset, String(Int(count), pluralizing: "entry", plural: "entries"), fileSize)
        case let .invalidStringTableRange(offset, size, fileSize):
            String(format: NSLocalizedString("Invalid Mach-O: string table at offset %u with size %u is outside the %d-byte slice", comment: "Malformed Mach-O string-table range"), offset, size, fileSize)
        case let .invalidStringTableIndex(index, tableSize):
            String(format: NSLocalizedString("Invalid Mach-O: string table index %u is outside the %u-byte table", comment: "Malformed Mach-O string-table index"), index, tableSize)
        }
    }
}

enum MachOParser {
    // MARK: - Types

    struct FatArch {
        let cpuType: cpu_type_t
        let cpuSubtype: cpu_subtype_t
        let offset: UInt64
        let size: UInt64
    }

    /**
     A load command as laid out on disk: `data` spans the whole command, 8-byte header included, so its
     count is the command's `cmdsize`.
     */
    struct LoadCommand {
        let cmd: UInt32
        let data: Data
    }

    enum BinaryType {
        case fat([FatArch])
        case thin(MachOSlice)
        case notMachO
    }

    // MARK: - Open

    /**
     Open a Mach-O and reject an incomplete header, load-command table, or fat architecture table.

     A fat architecture is checked to lie inside the file; what it contains is left to each consumer,
     since a universal static library carries `ar` archives rather than Mach-O slices.
     */
    static func open(data: Data) throws -> BinaryType {
        // Mirror isMachO(path:): a file shorter than a 32-bit mach_header is not Mach-O code to Security
        // (MachORep::candidate), so a magic-only stub (a truncated Java class, say) is an ordinary file.
        guard data.count >= self.minimumSize else {
            return .notMachO
        }

        if let slice = try MachOSlice(data) {
            return .thin(slice)
        }

        switch data.withUnsafeBytes({ $0.loadUnaligned(as: UInt32.self) }) {
        case FAT_MAGIC, FAT_CIGAM:
            return try self.parseFat(data: data, is64: false)
        case FAT_MAGIC_64, FAT_CIGAM_64:
            return try self.parseFat(data: data, is64: true)
        default:
            return .notMachO
        }
    }

    /**
     Cheap Mach-O check that reads only the leading bytes (uncached), so callers can avoid mapping a
     large non-Mach-O file (e.g. a multi-GB disk image) just to discover there is nothing to trim.

     Throws on an I/O failure (the file cannot be opened or read),
     a file that reads successfully but is not Mach-O (or is too small) simply returns false.
     */
    static func isMachO(path: String) throws -> Bool {
        let head = try FileReader.head(path: path, count: self.minimumSize)
        guard head.count >= self.minimumSize else {
            return false
        }

        return head.withUnsafeBytes { raw -> Bool in
            switch raw.loadUnaligned(as: UInt32.self) {
            case MH_MAGIC, MH_CIGAM, MH_MAGIC_64, MH_CIGAM_64:
                return true
            case FAT_MAGIC, FAT_CIGAM, FAT_MAGIC_64, FAT_CIGAM_64:
                let nfatArch = UInt32(bigEndian: raw.loadUnaligned(fromByteOffset: 4, as: UInt32.self))
                return 1 ... self.maxSliceCount ~= nfatArch
            default:
                return false
            }
        }
    }

    // MARK: - Architecture Naming

    /**
     The architecture name of a slice, as `codesign --arch` spells it.

     Names come from the OS's own Mach-O naming (`macho_arch_name_for_cpu_type`, the table `codesign` draws on),
     so every subtype the running OS knows — `arm64e.x1`, `x86_64h`, `armv7k`… — is spelled the way Apple's tools
     spell it, capability bits included.

     A slice the OS cannot name (newer than the OS, or legacy `ppc64`) falls
     back to a built-in table. The closed families there keep their base name for any subtype; the still-growing
     arm64 family labels an unrecognized subtype `unknown(cputype,cpusubtype)` like `lipo -archs`, because a
     base name `codesign --arch` would resolve to some other slice.
     */
    static func archName(cpuType: cpu_type_t, cpuSubtype: cpu_subtype_t) -> String {
        if let name = macho_arch_name_for_cpu_type(cpuType, cpuSubtype) {
            return String(cString: name)
        }

        let masked = cpuSubtype & ~cpu_subtype_t(bitPattern: CPU_SUBTYPE_MASK)
        switch cpuType {
        case CPU_TYPE_ARM64:
            switch masked {
            case CPU_SUBTYPE_ARM64_ALL, CPU_SUBTYPE_ARM64_V8:
                return "arm64"
            case CPU_SUBTYPE_ARM64E:
                return "arm64e"
            case CPU_SUBTYPE_ARM64E_X1:
                return "arm64e.x1"
            default:
                return self.unknownArchName(cpuType: cpuType, cpuSubtype: masked)
            }
        case CPU_TYPE_ARM64_32:
            return "arm64_32"
        case CPU_TYPE_X86_64:
            return "x86_64"
        case CPU_TYPE_I386:
            return "i386"
        case CPU_TYPE_ARM:
            return "arm"
        case CPU_TYPE_POWERPC:
            return "ppc"
        case CPU_TYPE_POWERPC64:
            return "ppc64"
        default:
            return self.unknownArchName(cpuType: cpuType, cpuSubtype: masked)
        }
    }

    // MARK: - Load Commands

    /**
     The `symtab_command` of an `LC_SYMTAB`, nil for any other command. Throws for one too short to hold it: Security
     checks a symbol table command only before `__LINKEDIT`, so a slice can parse with a later one cut short.
     */
    static func parseSymtab(command: LoadCommand, swap: Bool = false) throws -> symtab_command? {
        guard command.cmd == UInt32(LC_SYMTAB) else {
            return nil
        }

        let raw = try command.load(symtab_command.self)

        guard swap else {
            return raw
        }

        return symtab_command(
            cmd: raw.cmd.byteSwapped,
            cmdsize: raw.cmdsize.byteSwapped,
            symoff: raw.symoff.byteSwapped,
            nsyms: raw.nsyms.byteSwapped,
            stroff: raw.stroff.byteSwapped,
            strsize: raw.strsize.byteSwapped,
        )
    }

    /**
     Names of the external undefined symbols in a symbol table, in table order: entries whose type is
     exactly `N_EXT`, with no `N_STAB` bits and the `N_UNDF` section type.

     One pass over the mapped bytes, so memory grows with the names that qualify rather than with `nsyms`,
     which a hostile table sizes freely.
     */
    static func externalSymbolNames(data: Data, symtab: symtab_command, is64: Bool, swap: Bool) throws -> [String] {
        // 32-bit slices use the 12-byte `nlist`, 64-bit the 16-byte `nlist_64`; n_strx and n_type sit at the
        // same offsets in both.
        let entrySize = is64 ? MemoryLayout<nlist_64>.size : MemoryLayout<nlist>.size
        let symbolOffset = Int(symtab.symoff)
        guard
            symbolOffset <= data.count,
            Int(symtab.nsyms) <= (data.count - symbolOffset) / entrySize
        else {
            throw ParserError.invalidSymbolTableRange(offset: symtab.symoff, count: symtab.nsyms, fileSize: data.count)
        }
        try self.validateStringTable(data: data, stroff: symtab.stroff, strsize: symtab.strsize)

        let mask = UInt8(N_STAB | N_EXT | N_TYPE)
        var names: [String] = []
        try data.withUnsafeBytes { ptr in
            for symbolIndex in 0 ..< Int(symtab.nsyms) {
                let base = symbolOffset + symbolIndex * entrySize
                guard ptr.loadUnaligned(fromByteOffset: base + 4, as: UInt8.self) & mask == UInt8(N_EXT) else {
                    continue
                }
                let strx = ptr.loadUnaligned(fromByteOffset: base, as: UInt32.self)
                try names.append(self.symbolName(data: data, stroff: symtab.stroff, strsize: symtab.strsize, strx: swap ? strx.byteSwapped : strx))
            }
        }
        return names
    }

    static func validateStringTable(data: Data, stroff: UInt32, strsize: UInt32) throws {
        let tableOffset = Int(stroff)
        guard
            tableOffset <= data.count,
            Int(strsize) <= data.count - tableOffset
        else {
            throw ParserError.invalidStringTableRange(offset: stroff, size: strsize, fileSize: data.count)
        }
    }

    static func symbolName(data: Data, stroff: UInt32, strsize: UInt32, strx: UInt32) throws -> String {
        try self.validateStringTable(data: data, stroff: stroff, strsize: strsize)

        guard strx < strsize else {
            throw ParserError.invalidStringTableIndex(index: strx, tableSize: strsize)
        }

        let start = Int(stroff) + Int(strx)

        // The string is NUL-terminated, but a crafted table may omit the terminator:
        // bound the scan to the already-validated string table extent.
        let tableEnd = Int(stroff) + Int(strsize)

        return data.withUnsafeBytes { raw -> String in
            let bytes = raw.bindMemory(to: UInt8.self)
            var end = start
            while end < tableEnd, bytes[end] != 0 {
                end += 1
            }
            return String(decoding: bytes[start ..< end], as: UTF8.self)
        }
    }

    // MARK: - Slice Data

    /**
     One architecture of a universal file, for parsing, as a view into `fileData` rather than a copy: like Security's
     `MachO` at an offset in its universal file, it reads only the headers and tables it is asked for. A copy took the
     whole slice into the heap, each hash thread holding one at once.

     The view keeps the file's indices, so its `startIndex` is the slice's offset: read it with `Data.bytes(in:)`.
     */
    static func sliceData(fileData: Data, arch: FatArch) -> Data {
        // arch.offset/size come from an attacker-controllable fat header; convert through Int(exactly:)
        // and check the sum in wide arithmetic so a crafted 64-bit fat cannot trap on conversion/overflow.
        guard
            let start = Int(exactly: arch.offset),
            let size = Int(exactly: arch.size),
            start <= fileData.count,
            size <= fileData.count - start
        else {
            return Data()
        }

        return fileData.bytes(in: start ..< start + size)
    }

    // MARK: - Logical Extent

    /**
     The logical end of an entire file: a thin Mach-O trims to its referenced extent,
     a fat binary trims to the end of its last architecture slice, and any other input is left whole.

     Bytes beyond this are trailing slack appended after the Mach-O content.
     Throws when a Mach-O is malformed or a fat architecture range cannot address bytes within the file.
     */
    static func fileEnd(data: Data) throws -> Int {
        switch try self.open(data: data) {
        case let .thin(slice):
            slice.logicalEnd()
        case let .fat(archs):
            // parseFat has already proved every range fits, so the sums cannot overflow.
            archs.map { Int($0.offset) + Int($0.size) }.max() ?? data.count
        case .notMachO:
            data.count
        }
    }

    // MARK: - Private

    /**
     Label for a slice neither the OS nor the fallback table can name, in `lipo -archs` style: `unknown(16777228,13)`.
     */
    private static func unknownArchName(cpuType: cpu_type_t, cpuSubtype: cpu_subtype_t) -> String {
        "unknown(\(cpuType),\(cpuSubtype))"
    }

    /**
     The fewest bytes a Mach-O file holds: `MachORep::candidate` reads a 32-bit `mach_header` before it considers a file
     Mach-O code at all, and `codesign` signs any shorter one as a generic file.
     */
    private static let minimumSize = MemoryLayout<mach_header>.size

    /**
     The most slices a universal file holds, dyld's `mach_o::Universal::kMaxSliceCount`.

     Compiled Java class data shares the 0xCAFEBABE magic.
     Universal binaries have a small, big-endian, architecture count.
     */
    static let maxSliceCount: UInt32 = 16

    private static func parseFat(data: Data, is64: Bool) throws -> BinaryType {
        let nfatArch: UInt32 = data.withUnsafeBytes { ptr in
            UInt32(bigEndian: ptr.loadUnaligned(fromByteOffset: 4, as: UInt32.self))
        }

        guard 1 ... self.maxSliceCount ~= nfatArch else {
            return .notMachO
        }

        // fat_arch: cputype(4) cpusubtype(4) offset(4) size(4) align(4) = 20 bytes.
        // fat_arch_64: cputype(4) cpusubtype(4) offset(8) size(8) align(4) reserved(4) = 32 bytes.
        let entrySize = is64 ? 32 : 20
        let tableSize = 8 + Int(nfatArch) * entrySize
        guard tableSize <= data.count else {
            throw ParserError.invalidFatArchitectureTable(count: nfatArch, fileSize: data.count)
        }

        return try data.withUnsafeBytes { ptr in
            var archs: [FatArch] = []

            for architectureIndex in 0 ..< Int(nfatArch) {
                let entry = 8 + architectureIndex * entrySize
                let sliceOffset: UInt64
                let sliceSize: UInt64
                if is64 {
                    sliceOffset = UInt64(bigEndian: ptr.loadUnaligned(fromByteOffset: entry + 8, as: UInt64.self))
                    sliceSize = UInt64(bigEndian: ptr.loadUnaligned(fromByteOffset: entry + 16, as: UInt64.self))
                } else {
                    sliceOffset = UInt64(UInt32(bigEndian: ptr.loadUnaligned(fromByteOffset: entry + 8, as: UInt32.self)))
                    sliceSize = UInt64(UInt32(bigEndian: ptr.loadUnaligned(fromByteOffset: entry + 12, as: UInt32.self)))
                }

                // Every slice must start after the table and end inside the file. Int(exactly:) and the
                // subtraction keep a crafted 64-bit fat from trapping on conversion or overflow.
                guard
                    let start = Int(exactly: sliceOffset),
                    let size = Int(exactly: sliceSize),
                    start >= tableSize,
                    size > 0,
                    start <= data.count,
                    size <= data.count - start
                else {
                    throw ParserError.invalidFatArchitectureRange(offset: sliceOffset, size: sliceSize, fileSize: data.count)
                }

                archs.append(FatArch(
                    cpuType: cpu_type_t(bigEndian: ptr.loadUnaligned(fromByteOffset: entry, as: cpu_type_t.self)),
                    cpuSubtype: cpu_subtype_t(bigEndian: ptr.loadUnaligned(fromByteOffset: entry + 4, as: cpu_subtype_t.self)),
                    offset: sliceOffset,
                    size: sliceSize,
                ))
            }

            return .fat(archs)
        }
    }
}
