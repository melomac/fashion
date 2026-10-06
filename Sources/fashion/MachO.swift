import CMachOCompat // the load commands macOS 26 added, on older SDKs
import Foundation
import MachO

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

/**
 A single parsed thin Mach-O image, named after Security's `MachO`: a thin file, or one architecture of a universal one.

 Like Security's, it reads the header and the load commands once, at initialization, into a buffer whose offsets count
 from the image's start; the command lookups, code-signature, and logical-extent accessors all reuse that single pass,
 and anything else is read at its offset when asked for (`dataAt`, `stream`).

 `init?(_:offset:length:)` returns nil for anything that is not a thin Mach-O and throws for one Security refuses;
 `init?(lenient:offset:length:)` keeps whatever prefix of a damaged load-command table parses, for best-effort inspection.
 For a fat binary, open the container with `Universal` and read each architecture as its own `MachO`.
 */
struct MachO {
    /// The file the image lies in.
    let file: File
    /// Where the image starts in its file: zero for a thin file, an architecture's offset in a universal one.
    let offset: Int
    /// The image's size: the whole of a thin file, or an architecture of a universal one.
    let length: Int
    let is64: Bool
    let swap: Bool
    let cpuType: cpu_type_t
    let cpuSubtype: cpu_subtype_t

    let filetype: UInt32
    private let sizeofcmds: Int
    let loadCommands: [LoadCommand]
    /// Whether the commands fill the table the way `MachOBase::nextCommand` requires.
    private let tableIsValid: Bool

    /**
     The image `length` bytes long at `offset` in `file` (the rest of the file by default). Nil for anything that is not
     a thin Mach-O; throws for one too short for its header.
     */
    init?(lenient file: File, offset: Int = 0, length: Int? = nil) throws {
        let length = length ?? file.size - offset
        // Enough for either header, and as little as a peek at the magic of a file that is not Mach-O.
        let head = try file.read(at: offset, count: min(length, MemoryLayout<mach_header_64>.size))
        guard let layout = Self.layout(of: head) else {
            return nil
        }
        guard head.count >= layout.headerSize else {
            throw ParserError.truncatedMachHeader(expectedSize: layout.headerSize, fileSize: length)
        }

        // mach_header and mach_header_64 share their leading fields, so the 32-bit struct reads them all.
        let header = head.withUnsafeBytes { $0.loadUnaligned(as: mach_header.self) }
        func swapped<T: FixedWidthInteger>(_ value: T) -> T {
            layout.swap ? value.byteSwapped : value
        }

        self.file = file
        self.offset = offset
        self.length = length
        self.is64 = layout.is64
        self.swap = layout.swap
        self.cpuType = swapped(header.cputype)
        self.cpuSubtype = swapped(header.cpusubtype)
        self.filetype = swapped(header.filetype)
        self.sizeofcmds = Int(swapped(header.sizeofcmds))

        // The header and the load commands in one buffer, as `MachO::MachO` reads them, when the image holds them.
        let end = layout.headerSize + self.sizeofcmds
        let table = end <= length ? try file.read(at: offset, count: end) : head
        (self.loadCommands, self.tableIsValid) = Self.parseLoadCommands(data: table, headerSize: layout.headerSize, sizeofcmds: self.sizeofcmds, swap: layout.swap)
    }

    /**
     Parse a thin Mach-O as Security's `MachO` constructor does, and throw where it does: for a header the image cannot
     hold, for a load-command table that `sizeofcmds` does not hold (`ncmds` plays no part, as in
     `MachOBase::nextCommand`), and for a segment or symbol table command too short for its structure before the image's
     end (`MachO::validateStructure`).

     Returns nil for data that is not a thin Mach-O at all.
     */
    init?(_ file: File, offset: Int = 0, length: Int? = nil) throws {
        guard let image = try MachO(lenient: file, offset: offset, length: length) else {
            return nil
        }
        guard image.tableIsValid else {
            throw ParserError.invalidLoadCommandTable(size: UInt32(image.sizeofcmds), fileSize: image.length)
        }

        // validateStructure stops at the first __LINKEDIT segment or LC_SYMTAB, where it finds the end of the image;
        // an image that does not end there only fails strict validation.
        for command in image.loadCommands {
            switch command.cmd {
            case UInt32(LC_SEGMENT):
                _ = try command.load(segment_command.self)
            case UInt32(LC_SEGMENT_64):
                _ = try command.load(segment_command_64.self)
            case UInt32(LC_SYMTAB):
                _ = try command.load(symtab_command.self)
            default:
                continue
            }
            if command.cmd == UInt32(LC_SYMTAB) || command.segmentName == "__LINKEDIT" {
                break
            }
        }

        self = image
    }

    /**
     The `count` bytes at `offset` in the image, like `MachO::dataAt`; the caller has checked them against `length`.
     */
    func dataAt(_ offset: Int, count: Int) throws -> Data {
        try self.file.read(at: self.offset + offset, count: count)
    }

    /**
     Stream `range` of the image through `consume`; returns the count read, short only when the file ends first.
     */
    func stream(_ range: Range<Int>, _ consume: (UnsafeRawBufferPointer) throws -> Void) throws -> Int {
        try self.file.stream(self.offset + range.lowerBound ..< self.offset + range.upperBound, consume)
    }

    /**
     Byte-swap a raw header field to host order when the slice is foreign-endian.
     */
    func sw<T: FixedWidthInteger>(_ value: T) -> T {
        self.swap ? value.byteSwapped : value
    }

    // MARK: - Commands (Security's MachOBase)

    /// The first load command of type `cmd`, like `MachOBase::findCommand`.
    func findCommand(_ cmd: UInt32) -> LoadCommand? {
        self.loadCommands.first { $0.cmd == cmd }
    }

    /**
     The first `LC_SEGMENT` or `LC_SEGMENT_64` named `name`, like `MachOBase::findSegment`, which throws for a segment
     command it passes that cannot hold even a 32-bit `segment_command`.
     */
    func findSegment(_ name: String) throws -> LoadCommand? {
        for command in self.loadCommands where [UInt32(LC_SEGMENT), UInt32(LC_SEGMENT_64)].contains(command.cmd) {
            _ = try command.load(segment_command.self)
            if command.segmentName == name {
                return command
            }
        }
        return nil
    }

    /**
     The platform and minimum OS version the slice declares, like `MachOBase::version`: the first `LC_BUILD_VERSION`
     (even one naming platform 0), else the first `LC_VERSION_MIN_*`. Nil when it declares neither, and throws when the
     command it reads is too short for its structure. `minOS` is encoded like the load commands: X.Y.Z as `0xXXXXYYZZ`.
     */
    func version() throws -> (platform: Int32, minOS: UInt32)? {
        if let command = self.findCommand(UInt32(LC_BUILD_VERSION)) {
            let build = try command.load(build_version_command.self)
            return (Int32(bitPattern: self.sw(build.platform)), self.sw(build.minos))
        }

        let platforms = [LC_VERSION_MIN_MACOSX: PLATFORM_MACOS, LC_VERSION_MIN_IPHONEOS: PLATFORM_IOS, LC_VERSION_MIN_TVOS: PLATFORM_TVOS, LC_VERSION_MIN_WATCHOS: PLATFORM_WATCHOS]
        for command in self.loadCommands {
            if let platform = platforms[Int32(bitPattern: command.cmd)] {
                return try (platform, self.sw(command.load(version_min_command.self).version))
            }
        }
        return nil
    }

    // MARK: - Code Signature

    /**
     Where `LC_CODE_SIGNATURE` places the embedded signature, like `MachOBase::findCodeSignature`: its offset and size,
     or nil when unsigned. Throws when the command is too short to hold them.
     */
    func findCodeSignature() throws -> (offset: Int, size: Int)? {
        guard let command = self.findCommand(UInt32(LC_CODE_SIGNATURE)) else {
            return nil
        }

        let linkedit = try command.load(linkedit_data_command.self)
        return (Int(self.sw(linkedit.dataoff)), Int(self.sw(linkedit.datasize)))
    }

    // MARK: - Logical Extent

#if SECURITY_STRICT_VALIDATION
    /**
     Where the Mach-O image ends, as Security's `MachO` decides it for strict validation: at the end of the
     `__LINKEDIT` segment or of the `LC_SYMTAB` string table, whichever command comes first. Bytes past it are
     appended to the image, which `codesign` rejects. `Package.swift` defines `SECURITY_STRICT_VALIDATION` unless
     the environment sets it to `NO`.

     The whole slice when it declares neither, or an end that lies past the slice.
     */
    func logicalEnd() -> Int {
        for command in self.loadCommands {
            let isLinkedit = command.segmentName == "__LINKEDIT"
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
                let count = UInt64(self.length)
                return range.size <= count && range.offset <= count - range.size ? Int(range.offset + range.size) : self.length
            }
        }
        return self.length
    }
#else
    /**
     Where the Mach-O image ends: past the header, the load commands, and every byte its segments and link-edit tables
     reference, so a dSYM keeps the `__DWARF` segment that follows `__LINKEDIT`. Bytes past it are appended to the image.
     Built with `SECURITY_STRICT_VALIDATION=NO` in the environment; otherwise the image ends where `codesign`'s
     strict validation expects it to.

     The whole slice when a command references bytes past the slice, is too short for its structure, or might
     reference bytes not modeled here.
     */
    func logicalEnd() -> Int {
        let headerSize = self.is64 ? MemoryLayout<mach_header_64>.size : MemoryLayout<mach_header>.size
        let count = UInt64(self.length)
        var end = min(headerSize + self.sizeofcmds, self.length)

        for command in self.loadCommands {
            guard let ranges = self.fileRanges(of: command) else {
                return self.length
            }
            for range in ranges where range.size > 0 {
                guard
                    range.size <= count,
                    range.offset <= count - range.size
                else {
                    return self.length
                }
                end = max(end, Int(range.offset + range.size))
            }
        }
        return end
    }

    /**
     The file ranges a load command references: none for a command whose data is inline, nil for one too short for its
     structure or that might reference bytes not modeled here.
     */
    private func fileRanges(of command: LoadCommand) -> [(offset: UInt64, size: UInt64)]? {
        // `count` entries of `stride` bytes at `offset`: a 32-bit count times a structure size fits in 64 bits.
        func range(_ offset: some FixedWidthInteger, _ count: some FixedWidthInteger, stride: Int = 1) -> (offset: UInt64, size: UInt64) {
            (UInt64(self.sw(offset)), UInt64(self.sw(count)) * UInt64(stride))
        }

        switch command.cmd {
        case UInt32(LC_SEGMENT):
            return command.payload(as: segment_command.self).map { [range($0.fileoff, $0.filesize)] }
        case UInt32(LC_SEGMENT_64):
            return command.payload(as: segment_command_64.self).map { [range($0.fileoff, $0.filesize)] }
        case UInt32(LC_SYMTAB):
            let entry = self.is64 ? MemoryLayout<nlist_64>.size : MemoryLayout<nlist>.size
            return command.payload(as: symtab_command.self).map { [range($0.symoff, $0.nsyms, stride: entry), range($0.stroff, $0.strsize)] }
        case UInt32(LC_DYSYMTAB):
            let module = self.is64 ? MemoryLayout<dylib_module_64>.size : MemoryLayout<dylib_module>.size
            return command.payload(as: dysymtab_command.self).map { [
                range($0.tocoff, $0.ntoc, stride: MemoryLayout<dylib_table_of_contents>.size),
                range($0.modtaboff, $0.nmodtab, stride: module),
                range($0.extrefsymoff, $0.nextrefsyms, stride: MemoryLayout<dylib_reference>.size),
                range($0.indirectsymoff, $0.nindirectsyms, stride: MemoryLayout<UInt32>.size),
                range($0.extreloff, $0.nextrel, stride: MemoryLayout<relocation_info>.size),
                range($0.locreloff, $0.nlocrel, stride: MemoryLayout<relocation_info>.size),
            ] }
        case UInt32(LC_DYLD_INFO), UInt32(LC_DYLD_INFO_ONLY):
            return command.payload(as: dyld_info_command.self).map { [
                range($0.rebase_off, $0.rebase_size),
                range($0.bind_off, $0.bind_size),
                range($0.weak_bind_off, $0.weak_bind_size),
                range($0.lazy_bind_off, $0.lazy_bind_size),
                range($0.export_off, $0.export_size),
            ] }
        case UInt32(LC_CODE_SIGNATURE), UInt32(LC_SEGMENT_SPLIT_INFO), UInt32(LC_FUNCTION_STARTS), UInt32(LC_DATA_IN_CODE),
             UInt32(LC_DYLIB_CODE_SIGN_DRS), UInt32(LC_LINKER_OPTIMIZATION_HINT), UInt32(LC_DYLD_EXPORTS_TRIE),
             UInt32(LC_DYLD_CHAINED_FIXUPS), UInt32(LC_ATOM_INFO), UInt32(LC_FUNCTION_VARIANTS),
             UInt32(LC_FUNCTION_VARIANT_FIXUPS), UInt32(LC_LAZY_LOAD_DYLIB_INFO):
            return command.payload(as: linkedit_data_command.self).map { [range($0.dataoff, $0.datasize)] }
        case UInt32(LC_ENCRYPTION_INFO), UInt32(LC_ENCRYPTION_INFO_64):
            // Both layouts place cryptoff and cryptsize at the same offsets.
            return command.payload(as: encryption_info_command.self).map { [range($0.cryptoff, $0.cryptsize)] }
        case UInt32(LC_NOTE):
            return command.payload(as: note_command.self).map { [range($0.offset, $0.size)] }
        default:
            return Self.inlineCommands.contains(command.cmd) ? [] : nil
        }
    }

    /**
     The load commands whose data is inline, or lies in a segment measured anyway. Commands that reference data not
     modeled here, like `LC_TWOLEVEL_HINTS`, `LC_SYMSEG` or `LC_FILESET_ENTRY`, are left out so the slice stays whole.
     */
    private static let inlineCommands = Set([
        LC_THREAD,
        LC_UNIXTHREAD,
        LC_LOAD_DYLIB,
        LC_ID_DYLIB,
        LC_LAZY_LOAD_DYLIB,
        LC_PREBOUND_DYLIB,
        LC_LOAD_DYLINKER,
        LC_ID_DYLINKER,
        LC_DYLD_ENVIRONMENT,
        LC_SUB_FRAMEWORK,
        LC_SUB_UMBRELLA,
        LC_SUB_CLIENT,
        LC_SUB_LIBRARY,
        LC_ROUTINES,
        LC_ROUTINES_64,
        LC_PREBIND_CKSUM,
        LC_LINKER_OPTION,
        LC_UUID,
        LC_SOURCE_VERSION,
        LC_VERSION_MIN_MACOSX,
        LC_VERSION_MIN_IPHONEOS,
        LC_VERSION_MIN_TVOS,
        LC_VERSION_MIN_WATCHOS,
        LC_BUILD_VERSION,
        LC_TARGET_TRIPLE,
    ].map { UInt32(bitPattern: $0) } + [
        LC_LOAD_WEAK_DYLIB,
        LC_REEXPORT_DYLIB,
        LC_LOAD_UPWARD_DYLIB,
        LC_RPATH,
        LC_MAIN,
    ])
#endif

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

    /**
     The load commands as Security walks them: `MachO::MachO` reads the `sizeofcmds`-byte table, which must hold at least
     one command header, and `MachOBase::nextCommand` steps by each `cmdsize`, which must not be zero, until it reaches the
     end of the table; a command it steps onto must fit the table. `ncmds` plays no part. The walk is valid when it ends
     there, and stops at the first command that breaks those rules otherwise.

     `nextCommand` never checks the first command, which Security then reads past its copy of the table when it overruns
     it: that is refused here too.
     */
    private static func parseLoadCommands(data: Data, headerSize: Int, sizeofcmds: Int, swap: Bool) -> (commands: [LoadCommand], valid: Bool) {
        let end = headerSize + sizeofcmds
        guard
            sizeofcmds >= MemoryLayout<load_command>.size,
            end <= data.count
        else {
            return ([], false)
        }

        func header(at offset: Int) -> (cmd: UInt32, size: Int) {
            data.withUnsafeBytes { ptr in
                let cmd = ptr.loadUnaligned(fromByteOffset: offset, as: UInt32.self)
                let size = ptr.loadUnaligned(fromByteOffset: offset + 4, as: UInt32.self)
                return (swap ? cmd.byteSwapped : cmd, Int(swap ? size.byteSwapped : size))
            }
        }

        var commands: [LoadCommand] = []
        var offset = headerSize
        while true {
            let (cmd, size) = header(at: offset)
            guard
                size > 0,
                size <= end - offset
            else {
                return (commands, false)
            }
            commands.append(LoadCommand(cmd: cmd, data: data.bytes(in: offset ..< offset + size)))

            offset += size
            guard offset < end else {
                return (commands, true)
            }
            guard offset + MemoryLayout<load_command>.size <= end else {
                return (commands, false)
            }
        }
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

extension MachO {
    /**
     A load command as laid out on disk: `data` spans the whole command, 8-byte header included, so its
     count is the command's `cmdsize`.
     */
    struct LoadCommand {
        let cmd: UInt32
        let data: Data
    }
}

extension MachO.LoadCommand {
    /**
     The command's fixed structure, or nil when the command is too short to hold it.
     */
    func payload<T: BitwiseCopyable>(as type: T.Type) -> T? {
        guard self.data.count >= MemoryLayout<T>.size else {
            return nil
        }
        return self.data.withUnsafeBytes { $0.loadUnaligned(as: type) }
    }

    /**
     The command's fixed structure, throwing like Security (`ENOEXEC`) when the command is too short to hold it.
     */
    func load<T: BitwiseCopyable>(_ type: T.Type) throws -> T {
        guard let value = self.payload(as: type) else {
            throw ParserError.truncatedLoadCommand(cmd: self.cmd, size: self.data.count, expectedSize: MemoryLayout<T>.size)
        }
        return value
    }

    /**
     The name of an `LC_SEGMENT` or `LC_SEGMENT_64` (`segname` sits at the same offset in both), nil for any other command.
     */
    var segmentName: String? {
        [UInt32(LC_SEGMENT), UInt32(LC_SEGMENT_64)].contains(self.cmd) ? MachO.name(of: self.data.dropFirst(8).prefix(16)) : nil
    }
}
