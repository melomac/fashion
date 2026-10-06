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
    case symbolNamesTooLong(limit: Int)
}

extension ParserError: LocalizedError {
    var errorDescription: String? {
        switch self {
        case let .truncatedMachHeader(expectedSize, fileSize):
            "Invalid Mach-O: expected a \(expectedSize)-byte header in a \(fileSize)-byte file"
        case let .invalidLoadCommandTable(size, fileSize):
            "Invalid Mach-O: sizeofcmds \(size) does not hold a load-command table in the \(fileSize)-byte slice"
        case let .truncatedLoadCommand(cmd, size, expectedSize):
            "Invalid Mach-O: load command 0x\(String(cmd, radix: 16)) is only \(String(size, pluralizing: "byte")); its structure requires \(expectedSize)"
        case let .invalidFatArchitectureTable(count, fileSize):
            "Invalid Mach-O: nfat_arch \(count) does not fit in the \(fileSize)-byte file"
        case let .invalidFatArchitectureRange(offset, size, fileSize):
            "Invalid Mach-O: fat architecture range at offset \(offset) with size \(size) is outside the \(fileSize)-byte file"
        case let .invalidSymbolTableRange(offset, count, fileSize):
            "Invalid Mach-O: symbol table at offset \(offset) with \(String(Int(count), pluralizing: "entry", plural: "entries")) is outside the \(fileSize)-byte slice"
        case let .invalidStringTableRange(offset, size, fileSize):
            "Invalid Mach-O: string table at offset \(offset) with size \(size) is outside the \(fileSize)-byte slice"
        case let .symbolNamesTooLong(limit):
            "Mach-O too large: its external symbol names add up to more than \(limit) bytes"
        case let .invalidStringTableIndex(index, tableSize):
            "Invalid Mach-O: string table index \(index) is outside the \(tableSize)-byte table"
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

        /// Where the architecture lies in its file, which `parseFat` has checked it fits.
        var range: Range<Int> {
            Int(self.offset) ..< Int(self.offset + self.size)
        }
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
        case thin(MachO)
        case notMachO
    }

    // MARK: - Open

    /**
     Open a Mach-O and reject an incomplete header, load-command table, or fat architecture table.

     A fat architecture is checked to lie inside the file; what it contains is left to each consumer,
     since a universal static library carries `ar` archives rather than Mach-O slices.
     */
    static func open(_ file: File) throws -> BinaryType {
        // A file shorter than a 32-bit mach_header is not Mach-O code to Security (MachORep::candidate), so a
        // magic-only stub (a truncated Java class, say) is an ordinary file.
        guard file.size >= self.minimumSize else {
            return .notMachO
        }

        if let image = try MachO(file) {
            return .thin(image)
        }

        let head = try file.read(at: 0, count: 8)
        switch head.withUnsafeBytes({ $0.loadUnaligned(as: UInt32.self) }) {
        case FAT_MAGIC, FAT_CIGAM:
            return try self.parseFat(file, head: head, is64: false)
        case FAT_MAGIC_64, FAT_CIGAM_64:
            return try self.parseFat(file, head: head, is64: true)
        default:
            return .notMachO
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
     The names of the external undefined symbols in a symbol table, in table order: entries whose type is exactly
     `N_EXT`, with no `N_STAB` bits and the `N_UNDF` section type, and each name up to its NUL or the end of the table.

     Neither table is held whole: real ones reach hundreds of MiB (an Affinity framework holds 200 MiB of strings).
     The entries are read in chunks, then the string table in windows that start at the names wanted, skipping what lies
     between them. Names may overlap in a string table, so one NUL can end several: they share one buffer, and their
     total length is bounded by `maxSymbolNamesLength` rather than by the file, since overlapping names let a small
     crafted table reach gigabytes. The names are checked in table order, as they would be one at a time: an index
     past the string table is an error unless the names before it already went beyond the limit.

     The image is `length` bytes at `offset` in `file`, which its `symtab` offsets count from; `is64` and `swap` describe
     its header.
     */
    static func externalSymbolNames(file: File, offset: Int, length: Int, symtab: symtab_command, is64: Bool, swap: Bool) throws -> [Data] {
        // 32-bit slices use the 12-byte `nlist`, 64-bit the 16-byte `nlist_64`; n_strx and n_type sit at the
        // same offsets in both.
        let entrySize = is64 ? MemoryLayout<nlist_64>.size : MemoryLayout<nlist>.size
        let symbolOffset = Int(symtab.symoff)
        guard
            symbolOffset <= length,
            Int(symtab.nsyms) <= (length - symbolOffset) / entrySize
        else {
            throw ParserError.invalidSymbolTableRange(offset: symtab.symoff, count: symtab.nsyms, fileSize: length)
        }
        let tableOffset = Int(symtab.stroff)
        let tableSize = Int(symtab.strsize)
        guard
            tableOffset <= length,
            tableSize <= length - tableOffset
        else {
            throw ParserError.invalidStringTableRange(offset: symtab.stroff, size: symtab.strsize, fileSize: length)
        }

        // The string index of each external undefined symbol, up to the first one past the table.
        let mask = UInt8(N_STAB | N_EXT | N_TYPE)
        let batch = File.chunkSize / entrySize
        var indexes: [Int] = []
        var badIndex: ParserError?
        for first in stride(from: 0, to: Int(symtab.nsyms), by: batch) where badIndex == nil {
            let count = min(batch, Int(symtab.nsyms) - first)
            let entries = try file.read(at: offset + symbolOffset + first * entrySize, count: count * entrySize)
            entries.withUnsafeBytes { raw in
                for base in stride(from: 0, to: count * entrySize, by: entrySize) where badIndex == nil {
                    guard raw.loadUnaligned(fromByteOffset: base + 4, as: UInt8.self) & mask == UInt8(N_EXT) else {
                        continue
                    }
                    let strx = raw.loadUnaligned(fromByteOffset: base, as: UInt32.self)
                    let index = swap ? strx.byteSwapped : strx
                    guard index < symtab.strsize else {
                        badIndex = .invalidStringTableIndex(index: index, tableSize: symtab.strsize)
                        continue
                    }
                    indexes.append(Int(index))
                }
            }
        }

        // Each wanted name opens where it starts and closes, with every other one open, at the next NUL.
        var starts = Set(indexes).sorted()[...]
        var names: [Int: Data] = [:]
        var open: [Int] = []
        var pending = Data()
        var pendingStart = 0
        var windowStart = starts.first ?? tableSize
        windows: while windowStart < tableSize {
            let window = try file.read(at: offset + tableOffset + windowStart, count: min(File.chunkSize, tableSize - windowStart))
            let windowEnd = windowStart + window.count
            var at = windowStart
            while at < windowEnd {
                if open.isEmpty {
                    guard let start = starts.first else {
                        break windows
                    }
                    at = start
                    guard at < windowEnd else {
                        break
                    }
                    pending = Data()
                    pendingStart = at
                }
                while starts.first == at {
                    open.append(starts.removeFirst())
                }

                let stop = min(windowEnd, starts.first ?? windowEnd)
                let nul = window[(at - windowStart) ..< (stop - windowStart)].firstIndex(of: 0)
                let end = nul.map { windowStart + $0 } ?? stop
                pending.append(window[(at - windowStart) ..< (end - windowStart)])
                guard pending.count <= self.maxSymbolNamesLength else {
                    throw ParserError.symbolNamesTooLong(limit: self.maxSymbolNamesLength)
                }
                at = end
                if nul != nil {
                    for start in open {
                        names[start] = pending[(start - pendingStart)...]
                    }
                    open.removeAll()
                    at += 1
                }
            }
            windowStart = at
        }
        // Names still open run to the end of the table.
        for start in open {
            names[start] = pending[(start - pendingStart)...]
        }

        let length = indexes.reduce(0) { $0 + names[$1]!.count }
        guard length <= self.maxSymbolNamesLength else {
            throw ParserError.symbolNamesTooLong(limit: self.maxSymbolNamesLength)
        }
        if let badIndex {
            throw badIndex
        }
        return indexes.map { names[$0]! }
    }

    // MARK: - Logical Extent

    /**
     The logical end of an entire file: a thin Mach-O trims to its referenced extent,
     a fat binary trims to the end of its last architecture slice, and any other input is left whole.

     Bytes beyond this are trailing slack appended after the Mach-O content.
     Throws when a Mach-O is malformed or a fat architecture range cannot address bytes within the file.
     */
    static func fileEnd(_ file: File) throws -> Int {
        switch try self.open(file) {
        case let .thin(image):
            image.logicalEnd()
        case let .fat(archs):
            archs.map(\.range.upperBound).max() ?? file.size
        case .notMachO:
            file.size
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

    /**
     The most bytes of external symbol names a symbol table may add up to (64 MiB). Overlapping names let a small crafted
     table reach gigabytes; the largest of 4,806 large slices of real applications held 2.2 MiB.
     */
    static let maxSymbolNamesLength = 64 << 20

    private static func parseFat(_ file: File, head: Data, is64: Bool) throws -> BinaryType {
        let nfatArch: UInt32 = head.withUnsafeBytes { ptr in
            UInt32(bigEndian: ptr.loadUnaligned(fromByteOffset: 4, as: UInt32.self))
        }

        guard 1 ... self.maxSliceCount ~= nfatArch else {
            return .notMachO
        }

        // fat_arch: cputype(4) cpusubtype(4) offset(4) size(4) align(4) = 20 bytes.
        // fat_arch_64: cputype(4) cpusubtype(4) offset(8) size(8) align(4) reserved(4) = 32 bytes.
        let entrySize = is64 ? 32 : 20
        let tableSize = 8 + Int(nfatArch) * entrySize
        guard tableSize <= file.size else {
            throw ParserError.invalidFatArchitectureTable(count: nfatArch, fileSize: file.size)
        }

        return try file.read(at: 0, count: tableSize).withUnsafeBytes { ptr in
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
                    start <= file.size,
                    size <= file.size - start
                else {
                    throw ParserError.invalidFatArchitectureRange(offset: sliceOffset, size: sliceSize, fileSize: file.size)
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
