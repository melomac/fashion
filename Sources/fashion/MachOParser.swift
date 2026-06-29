import Foundation
import MachO
import os

enum MachOParser {
    private static let logger = Logger(subsystem: "fashion", category: "mach-o")

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

    static func loadCommands(data: Data) -> [LoadCommand] {
        guard data.count >= 4 else {
            return []
        }

        let magic = data.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }

        let is64: Bool
        let swap: Bool

        switch magic {
        case MH_MAGIC_64: is64 = true; swap = false
        case MH_CIGAM_64: is64 = true; swap = true
        case MH_MAGIC: is64 = false; swap = false
        case MH_CIGAM: is64 = false; swap = true
        default: return []
        }

        let headerSize = is64 ? MemoryLayout<mach_header_64>.size : MemoryLayout<mach_header>.size
        guard data.count >= headerSize else {
            return []
        }

        let (ncmds, sizeofcmds) = data.withUnsafeBytes { ptr -> (UInt32, UInt32) in
            let raw16 = ptr.loadUnaligned(fromByteOffset: 16, as: UInt32.self)
            let raw20 = ptr.loadUnaligned(fromByteOffset: 20, as: UInt32.self)

            return (swap ? raw16.byteSwapped : raw16, swap ? raw20.byteSwapped : raw20)
        }

        var commands: [LoadCommand] = []
        var offset = headerSize
        let endOffset = headerSize + Int(sizeofcmds)

        for _ in 0 ..< ncmds {
            guard offset + 8 <= data.count, offset + 8 <= endOffset else {
                break
            }

            let (cmd, cmdSize) = data.withUnsafeBytes { ptr -> (UInt32, UInt32) in
                let rawCmd = ptr.loadUnaligned(fromByteOffset: offset, as: UInt32.self)
                let rawSize = ptr.loadUnaligned(fromByteOffset: offset + 4, as: UInt32.self)
                return (swap ? rawCmd.byteSwapped : rawCmd, swap ? rawSize.byteSwapped : rawSize)
            }

            guard
                cmdSize >= 8,
                offset + Int(cmdSize) <= data.count
            else {
                break
            }

            commands.append(LoadCommand(cmd: cmd, cmdSize: cmdSize, data: data[offset ..< (offset + Int(cmdSize))]))

            offset += Int(cmdSize)
        }

        return commands
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
     The logical end of a thin Mach-O slice: the highest file offset referenced by the header, load commands, segments, and link-edit tables.
     Any bytes beyond this are trailing slack — e.g. attacker-appended padding — that is not part of the Mach-O image.

     Returns `data.count` when the slice is not a parseable thin Mach-O, so callers can hash the whole input unchanged when there is nothing to trim.
     */
    static func machOEnd(data: Data) -> Int {
        guard data.count >= MemoryLayout<mach_header>.size else {
            return data.count
        }

        let magic = data.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }

        let is64: Bool
        let swap: Bool
        switch magic {
        case MH_MAGIC_64: is64 = true; swap = false
        case MH_CIGAM_64: is64 = true; swap = true
        case MH_MAGIC: is64 = false; swap = false
        case MH_CIGAM: is64 = false; swap = true
        default: return data.count
        }

        func sw<T: FixedWidthInteger>(_ value: T) -> T {
            swap ? value.byteSwapped : value
        }

        let headerSize = is64 ? MemoryLayout<mach_header_64>.size : MemoryLayout<mach_header>.size
        guard data.count >= headerSize else {
            return data.count
        }

        // mach_header and mach_header_64 share their leading fields, so the 32-bit struct reads sizeofcmds for both.
        let sizeofcmds = Int(sw(data.withUnsafeBytes { $0.loadUnaligned(as: mach_header.self) }.sizeofcmds))

        // Trust the declared load-command region only when it fits the file.
        // A hostile, oversized sizeofcmds must not push maxEnd past the data and silently defeat trimming.
        // Real extents are still recovered from the parsed load commands below.
        let loadCommandsEnd = headerSize + sizeofcmds
        var maxEnd = loadCommandsEnd <= data.count ? loadCommandsEnd : headerSize

        // Raise maxEnd to cover a referenced region [offset, offset + count * stride), byte-swapping and widening the raw header fields.
        // Out-of-range or wrapping ends are ignored.
        func extend(offset: some FixedWidthInteger, count: some FixedWidthInteger, stride: Int = 1) {
            let end = UInt64(sw(offset)) &+ (UInt64(sw(count)) &* UInt64(stride))
            if end <= UInt64(data.count), Int(end) > maxEnd {
                maxEnd = Int(end)
            }
        }

        for cmd in self.loadCommands(data: data) {
            let d = cmd.data
            switch ExtentCommand(rawValue: cmd.cmd) {
            case .segment64:
                guard d.count >= MemoryLayout<segment_command_64>.size else {
                    continue
                }
                let seg = d.withUnsafeBytes { $0.loadUnaligned(as: segment_command_64.self) }
                extend(offset: seg.fileoff, count: seg.filesize)
            case .segment:
                guard d.count >= MemoryLayout<segment_command>.size else {
                    continue
                }
                let seg = d.withUnsafeBytes { $0.loadUnaligned(as: segment_command.self) }
                extend(offset: seg.fileoff, count: seg.filesize)
            case .symtab:
                guard d.count >= MemoryLayout<symtab_command>.size else {
                    continue
                }
                let symtab = d.withUnsafeBytes { $0.loadUnaligned(as: symtab_command.self) }
                extend(offset: symtab.symoff, count: symtab.nsyms, stride: is64 ? MemoryLayout<nlist_64>.size : MemoryLayout<nlist>.size)
                extend(offset: symtab.stroff, count: symtab.strsize)
            case .dysymtab:
                guard d.count >= MemoryLayout<dysymtab_command>.size else {
                    continue
                }
                let dysym = d.withUnsafeBytes { $0.loadUnaligned(as: dysymtab_command.self) }
                let moduleSize = is64 ? MemoryLayout<dylib_module_64>.size : MemoryLayout<dylib_module>.size
                extend(offset: dysym.tocoff, count: dysym.ntoc, stride: MemoryLayout<dylib_table_of_contents>.size)
                extend(offset: dysym.modtaboff, count: dysym.nmodtab, stride: moduleSize)
                extend(offset: dysym.extrefsymoff, count: dysym.nextrefsyms, stride: MemoryLayout<dylib_reference>.size)
                extend(offset: dysym.indirectsymoff, count: dysym.nindirectsyms, stride: MemoryLayout<UInt32>.size)
                extend(offset: dysym.extreloff, count: dysym.nextrel, stride: MemoryLayout<relocation_info>.size)
                extend(offset: dysym.locreloff, count: dysym.nlocrel, stride: MemoryLayout<relocation_info>.size)
            case .dyldInfo, .dyldInfoOnly:
                guard d.count >= MemoryLayout<dyld_info_command>.size else {
                    continue
                }
                let info = d.withUnsafeBytes { $0.loadUnaligned(as: dyld_info_command.self) }
                extend(offset: info.rebase_off, count: info.rebase_size)
                extend(offset: info.bind_off, count: info.bind_size)
                extend(offset: info.weak_bind_off, count: info.weak_bind_size)
                extend(offset: info.lazy_bind_off, count: info.lazy_bind_size)
                extend(offset: info.export_off, count: info.export_size)
            case .codeSignature, .segmentSplitInfo, .functionStarts, .dataInCode,
                 .dylibCodeSignDrs, .linkerOptimizationHint, .atomInfo, .functionVariants,
                 .functionVariantFixups, .dyldExportsTrie, .dyldChainedFixups:
                guard d.count >= MemoryLayout<linkedit_data_command>.size else {
                    continue
                }
                let linkedit = d.withUnsafeBytes { $0.loadUnaligned(as: linkedit_data_command.self) }
                extend(offset: linkedit.dataoff, count: linkedit.datasize)
            case .encryptionInfo, .encryptionInfo64:
                guard d.count >= MemoryLayout<encryption_info_command>.size else {
                    continue
                }
                let enc = d.withUnsafeBytes { $0.loadUnaligned(as: encryption_info_command.self) }
                extend(offset: enc.cryptoff, count: enc.cryptsize)
            case .note:
                guard d.count >= MemoryLayout<note_command>.size else {
                    continue
                }
                let note = d.withUnsafeBytes { $0.loadUnaligned(as: note_command.self) }
                extend(offset: note.offset, count: note.size)
            case .none:
                // If it is a known command that carries no on-disk payload, ignore it.
                // Otherwise it may reference bytes we can't account for.
                // Return the whole file rather than risk dropping legitimately-referenced data.
                guard Self.benignCommands.contains(cmd.cmd) else {
                    self.logger.warning("Unrecognized load command: \(String(format: "0x%x", cmd.cmd), privacy: .public) -> hashing whole file.")
                    return data.count
                }
                continue
            }
        }

        return min(maxEnd, data.count)
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

    // Load command ids that reference on-disk data (LC_REQ_DYLD high bit folded in where applicable).
    private enum ExtentCommand: UInt32 {
        case segment = 0x01
        case symtab = 0x02
        case dysymtab = 0x0b
        case segment64 = 0x19
        case codeSignature = 0x1d
        case segmentSplitInfo = 0x1e
        case encryptionInfo = 0x21
        case dyldInfo = 0x22
        case functionStarts = 0x26
        case dataInCode = 0x29
        case dylibCodeSignDrs = 0x2b
        case encryptionInfo64 = 0x2c
        case linkerOptimizationHint = 0x2e
        case note = 0x31
        case atomInfo = 0x36
        case functionVariants = 0x37
        case functionVariantFixups = 0x38
        case dyldInfoOnly = 0x8000_0022
        case dyldExportsTrie = 0x8000_0033
        case dyldChainedFixups = 0x8000_0034
    }

    // Load commands known to carry no standalone on-disk data: their payload is inline in the command,
    // or lives inside a segment we already measure. Any command that is neither measured above nor
    // listed here is treated as unknown — machOEnd logs it and declines to trim. Commands that DO
    // reference file data we don't model (LC_TWOLEVEL_HINTS, LC_SYMSEG, LC_FILESET_ENTRY, …) are
    // deliberately omitted so they fall through to that safe path.
    private static let benignCommands: Set<UInt32> = {
        // Plain commands (no LC_REQ_DYLD bit) — imported as Int32.
        let plain: [Int32] = [
            LC_THREAD, LC_UNIXTHREAD, LC_LOAD_DYLIB, LC_ID_DYLIB, LC_LAZY_LOAD_DYLIB,
            LC_PREBOUND_DYLIB, LC_LOAD_DYLINKER, LC_ID_DYLINKER, LC_DYLD_ENVIRONMENT,
            LC_SUB_FRAMEWORK, LC_SUB_UMBRELLA, LC_SUB_CLIENT, LC_SUB_LIBRARY,
            LC_ROUTINES, LC_ROUTINES_64, LC_PREBIND_CKSUM, LC_LINKER_OPTION,
            LC_UUID, LC_SOURCE_VERSION, LC_VERSION_MIN_MACOSX, LC_VERSION_MIN_IPHONEOS,
            LC_VERSION_MIN_TVOS, LC_VERSION_MIN_WATCHOS, LC_BUILD_VERSION,
        ]
        // Commands carrying the LC_REQ_DYLD bit — imported as UInt32.
        let reqDyld: [UInt32] = [
            LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB, LC_LOAD_UPWARD_DYLIB, LC_RPATH, LC_MAIN,
        ]
        return Set(plain.map { UInt32(bitPattern: $0) } + reqDyld)
    }()

    // MARK: - Private

    private static func parseFat(data: Data) -> BinaryType {
        guard data.count >= 8 else { return .notMachO }

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
            guard offset + entrySize <= data.count else { break }

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
