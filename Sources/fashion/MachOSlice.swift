import Foundation
import MachO
import os

/**
 A single parsed thin Mach-O slice.

 The header (endianness, architecture, filetype) and the load commands are parsed once at initialization;
 the executable-segment, code-signature, and logical-extent accessors all reuse that single pass.

 `init?(_:)` returns nil for anything that is not a thin Mach-O and throws for one whose load-command table is
 damaged; `init?(lenient:)` keeps whatever prefix of such a table parses, for best-effort inspection.
 For a fat binary, open the container with `MachOParser` and wrap each architecture slice in its own `MachOSlice`.
 */
struct MachOSlice {
    let data: Data
    let is64: Bool
    let swap: Bool
    let cpuType: cpu_type_t
    let cpuSubtype: cpu_subtype_t

    private let filetype: UInt32
    private let headerSize: Int
    private let commandCount: UInt32
    private let sizeofcmds: Int
    let loadCommands: [MachOParser.LoadCommand]

    private static let logger = Logger(subsystem: "fashion", category: "mach-o")

    init?(lenient data: Data) {
        guard
            let layout = Self.layout(of: data),
            data.count >= layout.headerSize
        else {
            return nil
        }

        // mach_header and mach_header_64 share their leading fields, so the 32-bit struct reads them all.
        let header = data.withUnsafeBytes { $0.loadUnaligned(as: mach_header.self) }
        func swapped<T: FixedWidthInteger>(_ value: T) -> T {
            layout.swap ? value.byteSwapped : value
        }

        self.data = data
        self.is64 = layout.is64
        self.swap = layout.swap
        self.cpuType = swapped(header.cputype)
        self.cpuSubtype = swapped(header.cpusubtype)
        self.filetype = swapped(header.filetype)
        self.headerSize = layout.headerSize
        self.commandCount = swapped(header.ncmds)
        self.sizeofcmds = Int(swapped(header.sizeofcmds))
        self.loadCommands = Self.parseLoadCommands(data: data, headerSize: layout.headerSize, sizeofcmds: self.sizeofcmds, ncmds: self.commandCount, swap: layout.swap)
    }

    /**
     Parse a thin Mach-O and require its complete load-command table to be structurally valid.

     Returns nil for data that is not a thin Mach-O at all, and throws for one that is cut short or
     declares a load-command table its commands do not fill, so a malformed command cannot be mistaken
     for an unsigned or shorter binary.
     */
    init?(_ data: Data) throws {
        guard let layout = Self.layout(of: data) else {
            return nil
        }
        guard let slice = MachOSlice(lenient: data) else {
            throw ParserError.truncatedMachHeader(expectedSize: layout.headerSize, fileSize: data.count)
        }

        // parseLoadCommands only keeps commands that lie inside the data, so a table that they fill exactly
        // also fits the file.
        let alignment = slice.is64 ? 8 : 4
        let commandsFillTable = slice.loadCommands.reduce(0) { $0 + $1.data.count } == slice.sizeofcmds
        let commandsHaveValidSizes = slice.loadCommands.allSatisfy { command in
            command.data.count >= Self.minimumSize(of: command.cmd) && command.data.count % alignment == 0
        }
        guard
            slice.loadCommands.count == Int(slice.commandCount),
            commandsFillTable,
            commandsHaveValidSizes
        else {
            throw ParserError.invalidLoadCommandTable(count: slice.commandCount, size: UInt32(slice.sizeofcmds), fileSize: data.count)
        }

        self = slice
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
            if self.is64, cmd.cmd == UInt32(LC_SEGMENT_64), let seg = cmd.payload(as: segment_command_64.self), Self.name(of: seg.segname) == "__TEXT" {
                return (self.sw(seg.fileoff), self.sw(seg.filesize), flags)
            }
            if !self.is64, cmd.cmd == UInt32(LC_SEGMENT), let seg = cmd.payload(as: segment_command.self), Self.name(of: seg.segname) == "__TEXT" {
                return (UInt64(self.sw(seg.fileoff)), UInt64(self.sw(seg.filesize)), flags)
            }
        }
        return (0, 0, flags)
    }

    // MARK: - Code Signature

    /**
     File range `[dataoff, dataoff + datasize)` of an embedded code signature, or nil when unsigned.
     Throws when an `LC_CODE_SIGNATURE` command is present but its range does not fit the slice.
     */
    func codeSignatureRange() throws -> Range<Int>? {
        for cmd in self.loadCommands where cmd.cmd == UInt32(LC_CODE_SIGNATURE) {
            // Every strictly parsed command holds its fixed structure; a lenient slice must still not read
            // a truncated command as "unsigned".
            guard let linkedit = cmd.payload(as: linkedit_data_command.self) else {
                throw ParserError.invalidLoadCommandTable(count: self.commandCount, size: UInt32(self.sizeofcmds), fileSize: self.data.count)
            }

            let offset = self.sw(linkedit.dataoff)
            let size = self.sw(linkedit.datasize)
            let start = Int(offset)
            let length = Int(size)
            guard
                start > 0,
                length > 0,
                start <= self.data.count,
                length <= self.data.count - start
            else {
                throw ParserError.invalidCodeSignatureRange(offset: offset, size: size, fileSize: self.data.count)
            }
            return start ..< (start + length)
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
        // Trust the declared load-command region only when it fits the file. A hostile, oversized
        // sizeofcmds must not push maxEnd past the data and silently defeat trimming; real extents are
        // still recovered from the parsed load commands below.
        let loadCommandsEnd = self.headerSize + self.sizeofcmds
        var maxEnd = loadCommandsEnd <= self.data.count ? loadCommandsEnd : self.headerSize

        // Raise maxEnd to cover a referenced region [offset, offset + count * stride), byte-swapping and
        // widening the raw header fields. Out-of-range or wrapping ends are ignored.
        func extend(offset: some FixedWidthInteger, count: some FixedWidthInteger, stride: Int = 1) {
            let end = UInt64(self.sw(offset)) &+ (UInt64(self.sw(count)) &* UInt64(stride))
            if end <= UInt64(self.data.count), Int(end) > maxEnd {
                maxEnd = Int(end)
            }
        }

        for cmd in self.loadCommands {
            switch ExtentCommand(rawValue: cmd.cmd) {
            case .segment64:
                guard let seg = cmd.payload(as: segment_command_64.self) else {
                    continue
                }
                extend(offset: seg.fileoff, count: seg.filesize)
            case .segment:
                guard let seg = cmd.payload(as: segment_command.self) else {
                    continue
                }
                extend(offset: seg.fileoff, count: seg.filesize)
            case .symtab:
                guard let symtab = cmd.payload(as: symtab_command.self) else {
                    continue
                }
                extend(offset: symtab.symoff, count: symtab.nsyms, stride: self.is64 ? MemoryLayout<nlist_64>.size : MemoryLayout<nlist>.size)
                extend(offset: symtab.stroff, count: symtab.strsize)
            case .dysymtab:
                guard let dysym = cmd.payload(as: dysymtab_command.self) else {
                    continue
                }
                let moduleSize = self.is64 ? MemoryLayout<dylib_module_64>.size : MemoryLayout<dylib_module>.size
                extend(offset: dysym.tocoff, count: dysym.ntoc, stride: MemoryLayout<dylib_table_of_contents>.size)
                extend(offset: dysym.modtaboff, count: dysym.nmodtab, stride: moduleSize)
                extend(offset: dysym.extrefsymoff, count: dysym.nextrefsyms, stride: MemoryLayout<dylib_reference>.size)
                extend(offset: dysym.indirectsymoff, count: dysym.nindirectsyms, stride: MemoryLayout<UInt32>.size)
                extend(offset: dysym.extreloff, count: dysym.nextrel, stride: MemoryLayout<relocation_info>.size)
                extend(offset: dysym.locreloff, count: dysym.nlocrel, stride: MemoryLayout<relocation_info>.size)
            case .dyldInfo, .dyldInfoOnly:
                guard let info = cmd.payload(as: dyld_info_command.self) else {
                    continue
                }
                extend(offset: info.rebase_off, count: info.rebase_size)
                extend(offset: info.bind_off, count: info.bind_size)
                extend(offset: info.weak_bind_off, count: info.weak_bind_size)
                extend(offset: info.lazy_bind_off, count: info.lazy_bind_size)
                extend(offset: info.export_off, count: info.export_size)
            case .codeSignature, .segmentSplitInfo, .functionStarts, .dataInCode,
                 .dylibCodeSignDrs, .linkerOptimizationHint, .atomInfo, .functionVariants,
                 .functionVariantFixups, .dyldExportsTrie, .dyldChainedFixups:
                guard let linkedit = cmd.payload(as: linkedit_data_command.self) else {
                    continue
                }
                extend(offset: linkedit.dataoff, count: linkedit.datasize)
            case .encryptionInfo, .encryptionInfo64:
                // Both layouts place cryptoff and cryptsize at the same offsets.
                guard let enc = cmd.payload(as: encryption_info_command.self) else {
                    continue
                }
                extend(offset: enc.cryptoff, count: enc.cryptsize)
            case .note:
                guard let note = cmd.payload(as: note_command.self) else {
                    continue
                }
                extend(offset: note.offset, count: note.size)
            case .none:
                // A known command with no on-disk payload is ignored; anything else may reference bytes we
                // can't account for, so return the whole file rather than risk dropping referenced data.
                guard Self.benignCommands.contains(cmd.cmd) else {
                    Self.logger.warning("Unrecognized load command: \(String(format: "0x%x", cmd.cmd), privacy: .public) -> hashing whole file.")
                    return self.data.count
                }
            }
        }

        return min(maxEnd, self.data.count)
    }

    // MARK: - Private

    /**
     Header geometry implied by the leading magic number; nil for anything that is not a thin Mach-O.
     */
    private static func layout(of data: Data) -> (is64: Bool, swap: Bool, headerSize: Int)? {
        guard data.count >= MemoryLayout<UInt32>.size else {
            return nil
        }

        switch data.withUnsafeBytes({ $0.loadUnaligned(as: UInt32.self) }) {
        case MH_MAGIC_64: return (true, false, MemoryLayout<mach_header_64>.size)
        case MH_CIGAM_64: return (true, true, MemoryLayout<mach_header_64>.size)
        case MH_MAGIC: return (false, false, MemoryLayout<mach_header>.size)
        case MH_CIGAM: return (false, true, MemoryLayout<mach_header>.size)
        default: return nil
        }
    }

    /**
     The NUL-padded name in a `segname` / `sectname` field.
     */
    private static func name(of field: some Any) -> String {
        withUnsafeBytes(of: field) { raw in String(decoding: raw.prefix { $0 != 0 }, as: UTF8.self) }
    }

    private static func parseLoadCommands(data: Data, headerSize: Int, sizeofcmds: Int, ncmds: UInt32, swap: Bool) -> [MachOParser.LoadCommand] {
        var commands: [MachOParser.LoadCommand] = []
        var offset = headerSize
        let endOffset = headerSize + sizeofcmds

        for _ in 0 ..< ncmds {
            guard
                offset + 8 <= data.count,
                offset + 8 <= endOffset
            else {
                break
            }

            let (cmd, cmdSize) = data.withUnsafeBytes { ptr -> (UInt32, UInt32) in
                let rawCmd = ptr.loadUnaligned(fromByteOffset: offset, as: UInt32.self)
                let rawSize = ptr.loadUnaligned(fromByteOffset: offset + 4, as: UInt32.self)
                return (swap ? rawCmd.byteSwapped : rawCmd, swap ? rawSize.byteSwapped : rawSize)
            }

            let size = Int(cmdSize)
            guard
                cmdSize >= 8,
                size <= data.count - offset,
                size <= endOffset - offset
            else {
                break
            }

            commands.append(MachOParser.LoadCommand(cmd: cmd, data: data[offset ..< (offset + size)]))
            offset += size
        }

        return commands
    }

    /** Minimum fixed size for load commands whose payload affects hashing. */
    private static func minimumSize(of command: UInt32) -> Int {
        switch ExtentCommand(rawValue: command) {
        case .segment64:
            MemoryLayout<segment_command_64>.size
        case .segment:
            MemoryLayout<segment_command>.size
        case .symtab:
            MemoryLayout<symtab_command>.size
        case .dysymtab:
            MemoryLayout<dysymtab_command>.size
        case .dyldInfo, .dyldInfoOnly:
            MemoryLayout<dyld_info_command>.size
        case .codeSignature, .segmentSplitInfo, .functionStarts, .dataInCode,
             .dylibCodeSignDrs, .linkerOptimizationHint, .atomInfo, .functionVariants,
             .functionVariantFixups, .dyldExportsTrie, .dyldChainedFixups:
            MemoryLayout<linkedit_data_command>.size
        case .encryptionInfo:
            MemoryLayout<encryption_info_command>.size
        case .encryptionInfo64:
            MemoryLayout<encryption_info_command_64>.size
        case .note:
            MemoryLayout<note_command>.size
        case .none:
            MemoryLayout<load_command>.size
        }
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

// MARK: -

extension MachOParser.LoadCommand {
    /**
     The command's fixed structure, or nil when the command is too short to hold it.
     */
    func payload<T: BitwiseCopyable>(as type: T.Type) -> T? {
        guard self.data.count >= MemoryLayout<T>.size else {
            return nil
        }
        return self.data.withUnsafeBytes { $0.loadUnaligned(as: type) }
    }
}
