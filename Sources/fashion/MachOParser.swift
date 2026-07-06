import Foundation
import MachO

enum MachOParser {
    // MARK: - Types

    struct FatArch {
        let cpuType: cpu_type_t
        let cpuSubtype: cpu_subtype_t
        let offset: UInt64
        let size: UInt64
        let align: UInt32
    }

    struct LoadCommand {
        let cmd: UInt32
        let cmdSize: UInt32
        let data: Data
    }

    enum BinaryType {
        case fat([FatArch])
        case thin(cpuType: cpu_type_t, cpuSubtype: cpu_subtype_t)
        case notMachO
    }

    // MARK: - Open

    static func open(data: Data) -> BinaryType {
        guard data.count >= 4 else {
            return .notMachO
        }

        let magic = data.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }

        switch magic {
        case FAT_MAGIC, FAT_CIGAM:
            return self.parseFat(data: data, is64: false)
        case FAT_MAGIC_64, FAT_CIGAM_64:
            return self.parseFat(data: data, is64: true)
        case MH_MAGIC_64, MH_CIGAM_64:
            return self.parseThinHeader(data: data, swap: magic == MH_CIGAM_64, headerSize: MemoryLayout<mach_header_64>.size)
        case MH_MAGIC, MH_CIGAM:
            return self.parseThinHeader(data: data, swap: magic == MH_CIGAM, headerSize: MemoryLayout<mach_header>.size)
        default:
            return .notMachO
        }
    }

    static func open(path: String) -> BinaryType {
        guard let data = try? FileReader.map(path: path) else {
            return .notMachO
        }
        return self.open(data: data)
    }

    /**
     Cheap Mach-O check that reads only the leading bytes (uncached), so callers can avoid mapping a
     large non-Mach-O file (e.g. a multi-GB disk image) just to discover there is nothing to trim.

     Throws on an I/O failure (the file cannot be opened or read),
     a file that reads successfully but is not Mach-O (or is too small) simply returns false.
     */
    static func isMachO(path: String) throws -> Bool {
        let head = try FileReader.head(path: path, count: 8)
        guard head.count >= 8 else {
            return false
        }

        return head.withUnsafeBytes { raw -> Bool in
            switch raw.loadUnaligned(as: UInt32.self) {
            case MH_MAGIC, MH_CIGAM, MH_MAGIC_64, MH_CIGAM_64:
                return true
            case FAT_MAGIC, FAT_CIGAM, FAT_MAGIC_64, FAT_CIGAM_64:
                // 0xCAFEBABE is shared with compiled Java class data.
                // Universal binaries have a small, big-endian, architecture count.
                let nfatArch = UInt32(bigEndian: raw.loadUnaligned(fromByteOffset: 4, as: UInt32.self))
                return nfatArch >= 1 && nfatArch < 25
            default:
                return false
            }
        }
    }

    // MARK: - Architecture Naming

    static func archName(cpuType: cpu_type_t, cpuSubtype: cpu_subtype_t) -> String {
        let masked = cpuSubtype & ~cpu_subtype_t(bitPattern: CPU_SUBTYPE_MASK)
        switch cpuType {
        case CPU_TYPE_ARM64:
            return masked == CPU_SUBTYPE_ARM64E ? "arm64e" : "arm64"
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
            return "unknown"
        }
    }

    // MARK: - Load Commands

    /// The load commands of a thin Mach-O slice, empty for anything else. Convenience over `MachOSlice`.
    static func loadCommands(data: Data) -> [LoadCommand] {
        MachOSlice(data)?.loadCommands ?? []
    }

    static func parseSymtab(command: LoadCommand, swap: Bool = false) -> symtab_command? {
        guard
            command.cmd == UInt32(LC_SYMTAB),
            command.data.count >= MemoryLayout<symtab_command>.size
        else {
            return nil
        }

        let raw = command.data.withUnsafeBytes { $0.loadUnaligned(as: symtab_command.self) }
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

    static func readSymbols(data: Data, symtab: symtab_command, is64: Bool = true, swap: Bool = false) -> [nlist_64] {
        // 32-bit slices use the 12-byte `nlist`, 64-bit the 16-byte `nlist_64`. The leading fields we read
        // (n_strx, n_type, n_sect) share the same offsets in both, so we extract them directly and build an
        // nlist_64 carrying only what SymHash consumes.
        let entrySize = is64 ? 16 : 12
        let symEnd = Int(symtab.symoff) + Int(symtab.nsyms) * entrySize
        guard symEnd <= data.count else {
            return []
        }

        return data.withUnsafeBytes { ptr in
            (0 ..< Int(symtab.nsyms)).map { i in
                let base = Int(symtab.symoff) + i * entrySize
                let strx = ptr.loadUnaligned(fromByteOffset: base, as: UInt32.self)
                return nlist_64(
                    n_un: .init(n_strx: swap ? strx.byteSwapped : strx),
                    n_type: ptr.loadUnaligned(fromByteOffset: base + 4, as: UInt8.self),
                    n_sect: ptr.loadUnaligned(fromByteOffset: base + 5, as: UInt8.self),
                    n_desc: 0,
                    n_value: 0,
                )
            }
        }
    }

    static func symbolName(data: Data, stroff: UInt32, strsize: UInt32, strx: UInt32) -> String? {
        let start = Int(stroff) + Int(strx)
        // The string is NUL-terminated, but a crafted table may omit the terminator: bound the
        // scan to the declared string table extent and the buffer so we never read past either.
        let tableEnd = Swift.min(Int(stroff) + Int(strsize), data.count)
        guard start < tableEnd else {
            return nil
        }

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

        return Data(fileData[start ..< start + size])
    }

    // MARK: - Logical Extent

    /**
     The logical end of a thin Mach-O slice; `data.count` when it is not a parseable thin Mach-O.

     Convenience over `MachOSlice.logicalEnd()`.
     */
    static func machOEnd(data: Data) -> Int {
        MachOSlice(data)?.logicalEnd() ?? data.count
    }

    /**
     The logical end of an entire file: a thin Mach-O trims to its referenced extent,
     a fat binary trims to the end of its last architecture slice, and any other input is left whole.

     Bytes beyond this are trailing slack appended after the Mach-O content.
     */
    static func fileEnd(data: Data) -> Int {
        switch self.open(data: data) {
        case .thin:
            return self.machOEnd(data: data)
        case let .fat(archs):
            let end = archs.map { Int($0.offset) + Int($0.size) }.max() ?? data.count
            return min(end, data.count)
        case .notMachO:
            return data.count
        }
    }

    // MARK: - Private

    private static func parseFat(data: Data, is64: Bool) -> BinaryType {
        guard data.count >= 8 else {
            return .notMachO
        }

        let nfatArch: UInt32 = data.withUnsafeBytes { ptr in
            UInt32(bigEndian: ptr.loadUnaligned(fromByteOffset: 4, as: UInt32.self))
        }

        // 0xCAFEBABE is shared with compiled Java class data.
        // Universal binaries have a small, big-endian, architecture count.
        guard
            nfatArch >= 1,
            nfatArch < 25
        else {
            return .notMachO
        }

        var archs: [FatArch] = []
        // fat_arch: cputype(4) cpusubtype(4) offset(4) size(4) align(4) = 20 bytes.
        // fat_arch_64: cputype(4) cpusubtype(4) offset(8) size(8) align(4) reserved(4) = 32 bytes.
        let entrySize = is64 ? 32 : 20

        for i in 0 ..< Int(nfatArch) {
            let offset = 8 + i * entrySize
            guard offset + entrySize <= data.count else {
                break
            }

            data.withUnsafeBytes { ptr in
                let sliceOffset: UInt64
                let sliceSize: UInt64
                let align: UInt32
                if is64 {
                    sliceOffset = UInt64(bigEndian: ptr.loadUnaligned(fromByteOffset: offset + 8, as: UInt64.self))
                    sliceSize = UInt64(bigEndian: ptr.loadUnaligned(fromByteOffset: offset + 16, as: UInt64.self))
                    align = UInt32(bigEndian: ptr.loadUnaligned(fromByteOffset: offset + 24, as: UInt32.self))
                } else {
                    sliceOffset = UInt64(UInt32(bigEndian: ptr.loadUnaligned(fromByteOffset: offset + 8, as: UInt32.self)))
                    sliceSize = UInt64(UInt32(bigEndian: ptr.loadUnaligned(fromByteOffset: offset + 12, as: UInt32.self)))
                    align = UInt32(bigEndian: ptr.loadUnaligned(fromByteOffset: offset + 16, as: UInt32.self))
                }

                archs.append(FatArch(
                    cpuType: cpu_type_t(bigEndian: ptr.loadUnaligned(fromByteOffset: offset, as: cpu_type_t.self)),
                    cpuSubtype: cpu_subtype_t(bigEndian: ptr.loadUnaligned(fromByteOffset: offset + 4, as: cpu_subtype_t.self)),
                    offset: sliceOffset,
                    size: sliceSize,
                    align: align,
                ))
            }
        }

        return archs.isEmpty ? .notMachO : .fat(archs)
    }

    private static func parseThinHeader(data: Data, swap: Bool, headerSize: Int) -> BinaryType {
        guard data.count >= headerSize else {
            return .notMachO
        }

        return data.withUnsafeBytes { ptr in
            let rawCpu = ptr.loadUnaligned(fromByteOffset: 4, as: cpu_type_t.self)
            let rawSub = ptr.loadUnaligned(fromByteOffset: 8, as: cpu_subtype_t.self)

            return .thin(
                cpuType: swap ? rawCpu.byteSwapped : rawCpu,
                cpuSubtype: swap ? rawSub.byteSwapped : rawSub,
            )
        }
    }
}
