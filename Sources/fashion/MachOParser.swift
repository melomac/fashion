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
            return self.parseFat(data: data)
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
            case FAT_MAGIC, FAT_CIGAM:
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

    static func parseSymtab(command: LoadCommand) -> symtab_command? {
        guard
            command.cmd == UInt32(LC_SYMTAB),
            command.data.count >= MemoryLayout<symtab_command>.size
        else {
            return nil
        }

        return command.data.withUnsafeBytes { $0.loadUnaligned(as: symtab_command.self) }
    }

    static func readSymbols(data: Data, symtab: symtab_command) -> [nlist_64] {
        let entrySize = MemoryLayout<nlist_64>.stride
        let symEnd = Int(symtab.symoff) + Int(symtab.nsyms) * entrySize
        guard symEnd <= data.count else { return [] }

        return data.withUnsafeBytes { ptr in
            (0 ..< Int(symtab.nsyms)).map { i in
                ptr.loadUnaligned(fromByteOffset: Int(symtab.symoff) + i * entrySize, as: nlist_64.self)
            }
        }
    }

    static func symbolName(data: Data, stroff: UInt32, strx: UInt32) -> String? {
        let offset = Int(stroff) + Int(strx)
        guard offset < data.count else { return nil }

        return data.withUnsafeBytes { ptr -> String? in
            guard let base = ptr.baseAddress?.advanced(by: offset).assumingMemoryBound(to: CChar.self) else {
                return nil
            }
            return String(cString: base)
        }
    }

    // MARK: - Slice Data

    static func sliceData(fileData: Data, arch: FatArch) -> Data {
        let start = Int(arch.offset)
        let end = start + Int(arch.size)

        guard
            start < fileData.count,
            end <= fileData.count
        else {
            return Data()
        }

        return Data(fileData[start ..< end])
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

    private static func parseFat(data: Data) -> BinaryType {
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
        let entrySize = MemoryLayout<fat_arch>.size

        for i in 0 ..< Int(nfatArch) {
            let offset = 8 + i * entrySize
            guard offset + entrySize <= data.count else {
                break
            }

            data.withUnsafeBytes { ptr in
                archs.append(FatArch(
                    cpuType: cpu_type_t(bigEndian: ptr.loadUnaligned(fromByteOffset: offset, as: cpu_type_t.self)),
                    cpuSubtype: cpu_subtype_t(bigEndian: ptr.loadUnaligned(fromByteOffset: offset + 4, as: cpu_subtype_t.self)),
                    offset: UInt64(UInt32(bigEndian: ptr.loadUnaligned(fromByteOffset: offset + 8, as: UInt32.self))),
                    size: UInt64(UInt32(bigEndian: ptr.loadUnaligned(fromByteOffset: offset + 12, as: UInt32.self))),
                    align: UInt32(bigEndian: ptr.loadUnaligned(fromByteOffset: offset + 16, as: UInt32.self)),
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
