import Foundation
import MachO
import os

/**
 A single parsed thin Mach-O slice.

 The header (endianness, architecture, filetype) and the load commands are parsed once at initialization;
 the executable-segment, code-signature, and logical-extent accessors all reuse that single pass.

 `init?` returns nil for anything that is not a thin Mach-O.
 For a fat binary, open the container with `MachOParser` and wrap each architecture slice in its own `MachOSlice`.
 */
struct MachOSlice {
    let data: Data
    let is64: Bool
    let swap: Bool
    let cpuType: cpu_type_t

    private let filetype: UInt32
    private let sizeofcmds: Int
    let loadCommands: [MachOParser.LoadCommand]

    private static let logger = Logger(subsystem: "fashion", category: "mach-o")

    init?(_ data: Data) {
        guard data.count >= MemoryLayout<mach_header>.size else {
            return nil
        }

        let magic = data.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }
        let is64: Bool
        let swap: Bool

        switch magic {
        case MH_MAGIC_64: is64 = true; swap = false
        case MH_CIGAM_64: is64 = true; swap = true
        case MH_MAGIC: is64 = false; swap = false
        case MH_CIGAM: is64 = false; swap = true
        default: return nil
        }

        let headerSize = is64 ? MemoryLayout<mach_header_64>.size : MemoryLayout<mach_header>.size
        guard data.count >= headerSize else {
            return nil
        }

        // mach_header and mach_header_64 share their leading fields, so the 32-bit struct reads them all.
        let header = data.withUnsafeBytes { $0.loadUnaligned(as: mach_header.self) }
        func swapped<T: FixedWidthInteger>(_ value: T) -> T {
            swap ? value.byteSwapped : value
        }

        self.data = data
        self.is64 = is64
        self.swap = swap
        self.cpuType = swapped(header.cputype)
        self.filetype = swapped(header.filetype)
        self.sizeofcmds = Int(swapped(header.sizeofcmds))
        self.loadCommands = Self.parseLoadCommands(data: data, headerSize: headerSize, sizeofcmds: self.sizeofcmds, ncmds: swapped(header.ncmds), swap: swap)
    }

    /**
     Byte-swap a raw header field to host order when the slice is foreign-endian.
     */
    func sw<T: FixedWidthInteger>(_ value: T) -> T {
        self.swap ? value.byteSwapped : value
    }

    // MARK: - Executable Segment

    /**
     Executable-segment fields of a CodeDirectory: the `__TEXT` file range, and `CS_EXECSEG_MAIN_BINARY`
     when the image is a main executable. `base`/`limit` are zero when there is no `__TEXT` segment.
     */
    func execSegment() -> (base: UInt64, limit: UInt64, flags: UInt64) {
        let flags: UInt64 = self.filetype == UInt32(MH_EXECUTE) ? 1 : 0

        for cmd in self.loadCommands {
            let d = cmd.data
            if self.is64, cmd.cmd == UInt32(LC_SEGMENT_64), d.count >= MemoryLayout<segment_command_64>.size {
                let seg = d.withUnsafeBytes { $0.loadUnaligned(as: segment_command_64.self) }
                let name = withUnsafeBytes(of: seg.segname) { raw in String(decoding: raw.prefix { $0 != 0 }, as: UTF8.self) }
                if name == "__TEXT" {
                    return (self.sw(seg.fileoff), self.sw(seg.filesize), flags)
                }
            } else if !self.is64, cmd.cmd == UInt32(LC_SEGMENT), d.count >= MemoryLayout<segment_command>.size {
                let seg = d.withUnsafeBytes { $0.loadUnaligned(as: segment_command.self) }
                let name = withUnsafeBytes(of: seg.segname) { raw in String(decoding: raw.prefix { $0 != 0 }, as: UTF8.self) }
                if name == "__TEXT" {
                    return (UInt64(self.sw(seg.fileoff)), UInt64(self.sw(seg.filesize)), flags)
                }
            }
        }
        return (0, 0, flags)
    }

    // MARK: - Code Signature

    /**
     File range `[dataoff, dataoff + datasize)` of an embedded code signature, or nil when unsigned.
     */
    func codeSignatureRange() -> Range<Int>? {
        for cmd in self.loadCommands where cmd.cmd == UInt32(LC_CODE_SIGNATURE) {
            guard cmd.data.count >= MemoryLayout<linkedit_data_command>.size else {
                continue
            }
            let ld = cmd.data.withUnsafeBytes { $0.loadUnaligned(as: linkedit_data_command.self) }
            let start = Int(self.sw(ld.dataoff))
            let end = start + Int(self.sw(ld.datasize))
            guard start > 0, end > start, end <= self.data.count else {
                continue
            }
            return start ..< end
        }
        return nil
    }

    // MARK: - Logical Extent

    /**
     The highest file offset referenced by the header, load commands, segments, and link-edit tables.

     Any bytes beyond this are trailing slack — e.g. attacker-appended padding — that is not part of the Mach-O image.
     Returns `data.count` (no trimming) when an unrecognized load command might reference data we don't model.
     */
    func logicalEnd() -> Int {
        let headerSize = self.is64 ? MemoryLayout<mach_header_64>.size : MemoryLayout<mach_header>.size

        // Trust the declared load-command region only when it fits the file. A hostile, oversized
        // sizeofcmds must not push maxEnd past the data and silently defeat trimming; real extents are
        // still recovered from the parsed load commands below.
        let loadCommandsEnd = headerSize + self.sizeofcmds
        var maxEnd = loadCommandsEnd <= self.data.count ? loadCommandsEnd : headerSize

        // Raise maxEnd to cover a referenced region [offset, offset + count * stride), byte-swapping and
        // widening the raw header fields. Out-of-range or wrapping ends are ignored.
        func extend(offset: some FixedWidthInteger, count: some FixedWidthInteger, stride: Int = 1) {
            let end = UInt64(self.sw(offset)) &+ (UInt64(self.sw(count)) &* UInt64(stride))
            if end <= UInt64(self.data.count), Int(end) > maxEnd {
                maxEnd = Int(end)
            }
        }

        for cmd in self.loadCommands {
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
                extend(offset: symtab.symoff, count: symtab.nsyms, stride: self.is64 ? MemoryLayout<nlist_64>.size : MemoryLayout<nlist>.size)
                extend(offset: symtab.stroff, count: symtab.strsize)
            case .dysymtab:
                guard d.count >= MemoryLayout<dysymtab_command>.size else {
                    continue
                }
                let dysym = d.withUnsafeBytes { $0.loadUnaligned(as: dysymtab_command.self) }
                let moduleSize = self.is64 ? MemoryLayout<dylib_module_64>.size : MemoryLayout<dylib_module>.size
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
                // A known command with no on-disk payload is ignored; anything else may reference bytes we
                // can't account for, so return the whole file rather than risk dropping referenced data.
                guard Self.benignCommands.contains(cmd.cmd) else {
                    Self.logger.warning("Unrecognized load command: \(String(format: "0x%x", cmd.cmd), privacy: .public) -> hashing whole file.")
                    return self.data.count
                }
                continue
            }
        }

        return min(maxEnd, self.data.count)
    }

    // MARK: - Private

    private static func parseLoadCommands(data: Data, headerSize: Int, sizeofcmds: Int, ncmds: UInt32, swap: Bool) -> [MachOParser.LoadCommand] {
        var commands: [MachOParser.LoadCommand] = []
        var offset = headerSize
        let endOffset = headerSize + sizeofcmds

        for _ in 0 ..< ncmds {
            guard offset + 8 <= data.count, offset + 8 <= endOffset else {
                break
            }

            let (cmd, cmdSize) = data.withUnsafeBytes { ptr -> (UInt32, UInt32) in
                let rawCmd = ptr.loadUnaligned(fromByteOffset: offset, as: UInt32.self)
                let rawSize = ptr.loadUnaligned(fromByteOffset: offset + 4, as: UInt32.self)
                return (swap ? rawCmd.byteSwapped : rawCmd, swap ? rawSize.byteSwapped : rawSize)
            }

            guard cmdSize >= 8, offset + Int(cmdSize) <= data.count else {
                break
            }

            commands.append(MachOParser.LoadCommand(cmd: cmd, cmdSize: cmdSize, data: data[offset ..< (offset + Int(cmdSize))]))
            offset += Int(cmdSize)
        }

        return commands
    }

    /**
     Load command ids that reference on-disk data (`LC_REQ_DYLD` high bit folded in where applicable).
     */
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

    /**
     Load commands known to carry no standalone on-disk data: their payload is inline in the command, or
     lives inside a segment we already measure. Any command that is neither measured above nor listed
     here is treated as unknown — `logicalEnd` logs it and declines to trim. Commands that DO reference
     file data we don't model (`LC_TWOLEVEL_HINTS`, `LC_SYMSEG`, `LC_FILESET_ENTRY`, …) are deliberately
     omitted so they fall through to that safe path.
     */
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
}
