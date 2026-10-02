import Foundation
import MachO

/**
 A single parsed thin Mach-O slice.

 The header (endianness, architecture, filetype) and the load commands are parsed once at initialization;
 the command lookups, code-signature, and logical-extent accessors all reuse that single pass.

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

    let filetype: UInt32
    private let headerSize: Int
    private let commandCount: UInt32
    private let sizeofcmds: Int
    let loadCommands: [MachOParser.LoadCommand]

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

    // MARK: - Commands (Security's MachOBase)

    /// The first load command of type `cmd`, like `MachOBase::findCommand`.
    func findCommand(_ cmd: UInt32) -> MachOParser.LoadCommand? {
        self.loadCommands.first { $0.cmd == cmd }
    }

    /// The first `LC_SEGMENT` or `LC_SEGMENT_64` named `name`, like `MachOBase::findSegment`.
    func findSegment(_ name: String) -> MachOParser.LoadCommand? {
        self.loadCommands.first { command in
            // segname sits at the same offset in both commands.
            [UInt32(LC_SEGMENT), UInt32(LC_SEGMENT_64)].contains(command.cmd) && Self.name(of: command.data.dropFirst(8).prefix(16)) == name
        }
    }

    /**
     The platform and minimum OS version the slice declares, like `MachOBase::version`: the first `LC_BUILD_VERSION`
     (even one naming platform 0), else the first `LC_VERSION_MIN_*`. Nil when it declares neither.
     `minOS` is encoded like the load commands: X.Y.Z as `0xXXXXYYZZ`.
     */
    func version() -> (platform: Int32, minOS: UInt32)? {
        if let command = self.findCommand(UInt32(LC_BUILD_VERSION)) {
            return command.payload(as: build_version_command.self).map { (Int32(bitPattern: self.sw($0.platform)), self.sw($0.minos)) }
        }

        let platforms = [LC_VERSION_MIN_MACOSX: PLATFORM_MACOS, LC_VERSION_MIN_IPHONEOS: PLATFORM_IOS, LC_VERSION_MIN_TVOS: PLATFORM_TVOS, LC_VERSION_MIN_WATCHOS: PLATFORM_WATCHOS]
        for command in self.loadCommands {
            if let platform = platforms[Int32(bitPattern: command.cmd)] {
                return command.payload(as: version_min_command.self).map { (platform, self.sw($0.version)) }
            }
        }
        return nil
    }

    // MARK: - Code Signature

    /**
     File range `[dataoff, dataoff + datasize)` of an embedded code signature, or nil when unsigned.
     Throws when an `LC_CODE_SIGNATURE` command is present but its range does not fit the slice.
     */
    func codeSignatureRange() throws -> Range<Int>? {
        guard let cmd = self.findCommand(UInt32(LC_CODE_SIGNATURE)) else {
            return nil
        }
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

    // MARK: - Logical Extent

    /**
     Where the Mach-O image ends, as Security's `MachO` decides it for strict validation: at the end of the
     `__LINKEDIT` segment or of the `LC_SYMTAB` string table, whichever command comes first. Bytes past it are
     appended to the image, which `codesign` rejects.

     The whole slice when it declares neither, or an end that lies past the slice.
     */
    func logicalEnd() -> Int {
        for command in self.loadCommands {
            let isLinkedit = Self.name(of: command.data.dropFirst(8).prefix(16)) == "__LINKEDIT"
            let range: (offset: UInt64, size: UInt64)? = switch command.cmd {
            case UInt32(LC_SEGMENT) where isLinkedit:
                command.payload(as: segment_command.self).map { (UInt64(self.sw($0.fileoff)), UInt64(self.sw($0.filesize))) }
            case UInt32(LC_SEGMENT_64) where isLinkedit:
                command.payload(as: segment_command_64.self).map { (self.sw($0.fileoff), self.sw($0.filesize)) }
            case UInt32(LC_SYMTAB):
                command.payload(as: symtab_command.self).map { (UInt64(self.sw($0.stroff)), UInt64(self.sw($0.strsize))) }
            default:
                nil
            }

            if let range {
                let count = UInt64(self.data.count)
                return range.size <= count && range.offset <= count - range.size ? Int(range.offset + range.size) : self.data.count
            }
        }
        return self.data.count
    }

    // MARK: - Filetype

    /**
     The `<mach-o/loader.h>` name of the slice's filetype, `unknown(n)` for a value it does not define.
     */
    var filetypeName: String {
        Self.filetypeNames.indices.contains(Int(self.filetype) - 1) ? Self.filetypeNames[Int(self.filetype) - 1] : "unknown(\(self.filetype))"
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
     The NUL-padded name in a 16-byte `segname` / `sectname` field.
     */
    static func name(of field: some Collection<UInt8>) -> String {
        String(decoding: field.prefix { $0 != 0 }, as: UTF8.self)
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

    // `<mach-o/loader.h>` filetypes, numbered from MH_OBJECT (1).
    private static let filetypeNames = [
        "MH_OBJECT",
        "MH_EXECUTE",
        "MH_FVMLIB",
        "MH_CORE",
        "MH_PRELOAD",
        "MH_DYLIB",
        "MH_DYLINKER",
        "MH_BUNDLE",
        "MH_DYLIB_STUB",
        "MH_DSYM",
        "MH_KEXT_BUNDLE",
        "MH_FILESET",
        "MH_GPU_EXECUTE",
        "MH_GPU_DYLIB",
    ]
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
