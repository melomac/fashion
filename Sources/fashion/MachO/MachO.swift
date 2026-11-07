import CMachOCompat // the load commands macOS 26 added, on older SDKs
import Foundation
import MachO

enum ParserError: MalformedInput, Equatable {
    case truncatedMachHeader(expectedSize: Int, fileSize: Int)
    case invalidLoadCommandTable(size: UInt32, fileSize: Int)
    case truncatedLoadCommand(cmd: UInt32, size: Int, expectedSize: Int)
    case invalidFatArchitectureTable(count: UInt32, fileSize: Int)
    case invalidFatArchitectureRange(offset: UInt64, size: UInt64, fileSize: Int)
    case invalidSymbolTableRange(offset: UInt32, count: UInt32, fileSize: Int)
    case invalidStringTableRange(offset: UInt32, size: UInt32, fileSize: Int)
    case invalidStringTableIndex(index: UInt32, tableSize: UInt32)
    case invalidSegmentRange(name: String, offset: UInt64, size: UInt64, fileSize: Int)
    case symbolNamesTooLong(limit: Int)
    case tooManyExternalSymbols(limit: Int)
    case loadCommandsTooLarge(size: Int, limit: Int)
}

extension ParserError: LocalizedError {
    var errorDescription: String? {
        switch self {
        case let .truncatedMachHeader(expectedSize, fileSize):
            "Invalid Mach-O: expected a \(expectedSize)-byte header in a \(fileSize)-byte slice"
        case let .invalidLoadCommandTable(size, fileSize):
            "Invalid Mach-O: sizeofcmds \(size) does not hold a load-command table in the \(fileSize)-byte slice"
        case let .truncatedLoadCommand(cmd, size, expectedSize):
            "Invalid Mach-O: load command \(cmd.hex) is only \(String(size, pluralizing: "byte")); its structure requires \(expectedSize)"
        case let .invalidFatArchitectureTable(count, fileSize):
            "Invalid Mach-O: nfat_arch \(count) does not fit in the \(fileSize)-byte file"
        case let .invalidFatArchitectureRange(offset, size, fileSize):
            "Invalid Mach-O: fat architecture range at offset \(offset.hex) with size \(size.hex) is outside the \(fileSize.hex)-byte file"
        case let .invalidSymbolTableRange(offset, count, fileSize):
            "Invalid Mach-O: symbol table at offset \(offset.hex) with \(String(Int(count), pluralizing: "entry", plural: "entries")) is outside the \(fileSize.hex)-byte slice"
        case let .invalidStringTableRange(offset, size, fileSize):
            "Invalid Mach-O: string table at offset \(offset.hex) with size \(size.hex) is outside the \(fileSize.hex)-byte slice"
        case let .symbolNamesTooLong(limit):
            "Mach-O too large: its external symbol names add up to more than \(limit) bytes"
        case let .tooManyExternalSymbols(limit):
            "Mach-O too large: its symbol table holds more than \(limit) external symbols"
        case let .loadCommandsTooLarge(size, limit):
            "Mach-O too large: its load commands add up to \(size) bytes, more than \(limit)"
        case let .invalidStringTableIndex(index, tableSize):
            "Invalid Mach-O: string table index \(index.hex) is outside the \(tableSize.hex)-byte table"
        case let .invalidSegmentRange(name, offset, size, fileSize):
            "Invalid Mach-O: segment \(name) at offset \(offset.hex) with size \(size.hex) is outside the \(fileSize.hex)-byte slice"
        }
    }
}

/**
 A single parsed thin Mach-O image, named after Security's `MachO`: a thin file, or one architecture of a universal one,
 which `Universal` locates.

 Like Security's, it reads the header and the load commands once, at initialization, into a buffer whose offsets count
 from the image's start; the command lookups, code-signature, and logical-extent accessors all reuse that single pass,
 and anything else is read at its offset when asked for (`dataAt`, `stream`).
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
    /// The header's size, `mach_header_64`'s or `mach_header`'s, where the load commands start.
    let headerSize: Int
    let cpuType: cpu_type_t
    let cpuSubtype: cpu_subtype_t

    let filetype: UInt32
    /// The count the header declares, which the kernel and dyld walk, where Security and this parser walk the table.
    let ncmds: Int
    let sizeofcmds: Int
    let flags: UInt32
    /// The 64-bit header's last field, which no loader reads; zero in a 32-bit header.
    let reserved: UInt32
    /// The most bytes one read takes for a header and its load commands (4 KiB), which hold both for most images.
    static let headSize = 4096
    /**
     The most bytes of load commands an image may declare (64 MiB), a limit of this tool's, as `maxSymbolNamesLength`
     is: no loader has one, the kernel maps what `sizeofcmds` says, and the largest tables the toolchain writes are
     some hundreds of kilobytes, where a crafted table of gigabytes would be read whole and walked into an array three
     times its size.
     */
    static let maxLoadCommandsSize = 64 << 20
    let loadCommands: [LoadCommand]
    /// Whether the table holds its commands the way the loaders and `MachOBase::nextCommand` require.
    private let tableIsValid: Bool
    /**
     The bytes inside `sizeofcmds` past the last load command that no command covers: none for a table the commands
     fill, as the linker writes it. The kernel and dyld walk `ncmds` commands and never read them; Security's walk
     is lazy and stops at what it looks for, so codesign verifies the image, while codesign cannot re-sign it and
     Rosetta refuses it.
     */
    let loadCommandsTail: Int

    /**
     The image `length` bytes long at `offset` in `file` (the rest of the file by default), whose first bytes the caller
     may have read already as `head`, keeping whatever prefix of a damaged load-command table parses. Nil for anything
     that is not a thin Mach-O; throws for one too short for its header.
     */
    init?(lenient file: File, offset: Int = 0, length: Int? = nil, head given: Data? = nil) throws {
        let length = length ?? file.size - offset
        // A peek at the magic of a file that is not Mach-O, and the header and load commands of most images.
        let head = try given ?? file.read(at: offset, count: min(length, Self.headSize))
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
        self.headerSize = layout.headerSize
        self.cpuType = swapped(header.cputype)
        self.cpuSubtype = swapped(header.cpusubtype)
        self.filetype = swapped(header.filetype)
        self.ncmds = Int(swapped(header.ncmds))
        self.sizeofcmds = Int(swapped(header.sizeofcmds))
        self.flags = swapped(header.flags)
        self.reserved = layout.is64 ? swapped(head.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: MemoryLayout<mach_header>.size, as: UInt32.self) }) : 0

        // The header and the load commands in one buffer, as `MachO::MachO` reads them, when the image holds them
        // and they stay under the limit.
        let end = layout.headerSize + self.sizeofcmds
        let table = try self.sizeofcmds <= Self.maxLoadCommandsSize && end <= length ? (end <= head.count ? head.prefix(end) : file.read(at: offset, count: end)) : head
        (self.loadCommands, self.tableIsValid, self.loadCommandsTail) = Self.parseLoadCommands(data: table, headerSize: layout.headerSize, ncmds: self.ncmds, sizeofcmds: self.sizeofcmds, swap: layout.swap)
    }

    /**
     Parse a thin Mach-O as Security's `MachO` constructor does, throwing for a load-command table `parseLoadCommands`
     rejects and for a segment or symbol table command too short for its structure before the image's end
     (`MachO::validateStructure`), and as the kernel does for a segment it reads lying past the image
     (`load_segment`). Nil for data that is not a thin Mach-O at all.
     */
    init?(_ file: File, offset: Int = 0, length: Int? = nil, head: Data? = nil) throws {
        guard let image = try MachO(lenient: file, offset: offset, length: length, head: head) else {
            return nil
        }
        // The limit is for a table the slice holds: one past the slice is a table it does not hold, whatever its size.
        guard image.sizeofcmds <= Self.maxLoadCommandsSize || image.headerSize + image.sizeofcmds > image.length else {
            throw ParserError.loadCommandsTooLarge(size: image.sizeofcmds, limit: Self.maxLoadCommandsSize)
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
            if command.cmd == UInt32(LC_SYMTAB) || command.isSegment(named: "__LINKEDIT") {
                break
            }
        }

        // The kernel refuses a segment lying past the image, whatever its size, "to make sure what we get from the
        // file is really ours": LOAD_BADMACHO, and the file never loads. It walks `ncmds` commands, as dyld does: a
        // segment hidden past them is read by no loader, and verify names it. Security's MachO does not look.
        for command in image.loadCommands.prefix(image.ncmds) {
            let range: (offset: UInt64, size: UInt64)? = switch command.cmd {
            case UInt32(LC_SEGMENT):
                command.payload(as: segment_command.self).map { (UInt64(image.sw($0.fileoff)), UInt64(image.sw($0.filesize))) }
            case UInt32(LC_SEGMENT_64):
                command.payload(as: segment_command_64.self).map { (image.sw($0.fileoff), image.sw($0.filesize)) }
            default:
                nil
            }
            if let range, range.size > UInt64(image.length) || range.offset > UInt64(image.length) - range.size {
                throw ParserError.invalidSegmentRange(name: command.segmentName, offset: range.offset, size: range.size, fileSize: image.length)
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
     Stream `range` of the image through `consume`; throws when the file no longer holds it.
     */
    func stream(_ range: Range<Int>, _ consume: (UnsafeRawBufferPointer) throws -> Void) throws {
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
    /// Whether dyld manages the image (`Header::isDyldManaged`): a dylib, a bundle, a dynamically linked executable.
    var isDyldManaged: Bool {
        [UInt32(MH_DYLIB), UInt32(MH_BUNDLE)].contains(self.filetype) || self.filetype == UInt32(MH_EXECUTE) && self.flags & UInt32(MH_DYLDLINK) != 0
    }

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
            if command.isSegment(named: name) {
                return command
            }
        }
        return nil
    }

    /**
     The platform, minimum OS version and SDK the slice declares, like `MachOBase::version`: the first
     `LC_BUILD_VERSION` (even one naming platform 0), else the first `LC_VERSION_MIN_*`. Nil when it declares neither,
     and throws when the command it reads is too short for its structure. `minOS` and `sdk` are encoded like the load
     commands: X.Y.Z as `0xXXXXYYZZ`.
     */
    func version() throws -> (platform: Int32, minOS: UInt32, sdk: UInt32)? {
        if let command = self.findCommand(UInt32(LC_BUILD_VERSION)) {
            let build = try command.load(build_version_command.self)
            return (Int32(bitPattern: self.sw(build.platform)), self.sw(build.minos), self.sw(build.sdk))
        }

        let platforms = [LC_VERSION_MIN_MACOSX: PLATFORM_MACOS, LC_VERSION_MIN_IPHONEOS: PLATFORM_IOS, LC_VERSION_MIN_TVOS: PLATFORM_TVOS, LC_VERSION_MIN_WATCHOS: PLATFORM_WATCHOS]
        for command in self.loadCommands {
            if let platform = platforms[Int32(bitPattern: command.cmd)] {
                let versionMin = try command.load(version_min_command.self)
                return (platform, self.sw(versionMin.version), self.sw(versionMin.sdk))
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
     appended to the image, which `codesign` rejects. `Package.swift` defines `SECURITY_STRICT_VALIDATION` unless the
     environment sets it to `NO`, for the other ending below.

     The whole slice when it declares neither, or an end that lies past the slice.
     */
    func logicalEnd() -> Int {
        for command in self.loadCommands {
            let isLinkedit = command.isSegment(named: "__LINKEDIT")
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

     The whole slice when a command references bytes past the slice, is too short for its structure, or might
     reference bytes not modeled here.
     */
    func logicalEnd() -> Int {
        let count = UInt64(self.length)
        var end = min(self.headerSize + self.sizeofcmds, self.length)

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

#endif

    /// A range of the file a load command references, named as dyld's `isValidLinkeditLayout` names its blobs.
    struct FileRange {
        let name: String
        let offset: UInt64
        let size: UInt64
    }

    /**
     The file ranges a load command references, each named: none for a command whose data is inline, nil for one too
     short for its structure or that might reference bytes not modeled here.
     */
    func fileRanges(of command: LoadCommand) -> [FileRange]? {
        // `count` entries of `stride` bytes at `offset`: a 32-bit count times a structure size fits in 64 bits.
        func range(_ name: String, _ offset: some FixedWidthInteger, _ count: some FixedWidthInteger, stride: Int = 1) -> FileRange {
            FileRange(name: name, offset: UInt64(self.sw(offset)), size: UInt64(self.sw(count)) * UInt64(stride))
        }

        switch command.cmd {
        case UInt32(LC_SEGMENT):
            return command.payload(as: segment_command.self).map { [range("segment \(command.segmentName)", $0.fileoff, $0.filesize)] }
        case UInt32(LC_SEGMENT_64):
            return command.payload(as: segment_command_64.self).map { [range("segment \(command.segmentName)", $0.fileoff, $0.filesize)] }
        case UInt32(LC_SYMTAB):
            let entry = self.is64 ? MemoryLayout<nlist_64>.size : MemoryLayout<nlist>.size
            return command.payload(as: symtab_command.self).map { [range("symbol table", $0.symoff, $0.nsyms, stride: entry), range("string table", $0.stroff, $0.strsize)] }
        case UInt32(LC_DYSYMTAB):
            let module = self.is64 ? MemoryLayout<dylib_module_64>.size : MemoryLayout<dylib_module>.size
            return command.payload(as: dysymtab_command.self).map { [
                range("table of contents", $0.tocoff, $0.ntoc, stride: MemoryLayout<dylib_table_of_contents>.size),
                range("module table", $0.modtaboff, $0.nmodtab, stride: module),
                range("referenced symbol table", $0.extrefsymoff, $0.nextrefsyms, stride: MemoryLayout<dylib_reference>.size),
                range("indirect symbol table", $0.indirectsymoff, $0.nindirectsyms, stride: MemoryLayout<UInt32>.size),
                range("external relocations", $0.extreloff, $0.nextrel, stride: MemoryLayout<relocation_info>.size),
                range("local relocations", $0.locreloff, $0.nlocrel, stride: MemoryLayout<relocation_info>.size),
            ] }
        case UInt32(LC_DYLD_INFO), UInt32(LC_DYLD_INFO_ONLY):
            return command.payload(as: dyld_info_command.self).map { [
                range("rebase opcodes", $0.rebase_off, $0.rebase_size),
                range("bind opcodes", $0.bind_off, $0.bind_size),
                range("weak bind opcodes", $0.weak_bind_off, $0.weak_bind_size),
                range("lazy bind opcodes", $0.lazy_bind_off, $0.lazy_bind_size),
                range("exports trie", $0.export_off, $0.export_size),
            ] }
        case UInt32(LC_CODE_SIGNATURE), UInt32(LC_SEGMENT_SPLIT_INFO), UInt32(LC_FUNCTION_STARTS), UInt32(LC_DATA_IN_CODE),
             UInt32(LC_DYLIB_CODE_SIGN_DRS), UInt32(LC_LINKER_OPTIMIZATION_HINT), UInt32(LC_DYLD_EXPORTS_TRIE),
             UInt32(LC_DYLD_CHAINED_FIXUPS), UInt32(LC_ATOM_INFO), UInt32(LC_FUNCTION_VARIANTS),
             UInt32(LC_FUNCTION_VARIANT_FIXUPS), UInt32(LC_LAZY_LOAD_DYLIB_INFO):
            return command.payload(as: linkedit_data_command.self).map { [range(command.name, $0.dataoff, $0.datasize)] }
        case UInt32(LC_ENCRYPTION_INFO), UInt32(LC_ENCRYPTION_INFO_64):
            // Both layouts place cryptoff and cryptsize at the same offsets.
            return command.payload(as: encryption_info_command.self).map { [range("encrypted range", $0.cryptoff, $0.cryptsize)] }
        case UInt32(LC_NOTE):
            return command.payload(as: note_command.self).map { [range("note", $0.offset, $0.size)] }
        default:
            return Self.inlineCommands.contains(command.cmd) ? [] : nil
        }
    }

    /**
     The load commands whose data is inline, or lies in a segment measured anyway. Commands that reference data not
     modeled here, like `LC_TWOLEVEL_HINTS`, `LC_SYMSEG` or `LC_FILESET_ENTRY`, are left out so the slice stays whole.
     */
    static let inlineCommands = Set([
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

    // MARK: - Filetype

    /**
     The `<mach-o/loader.h>` name of the slice's filetype, `unknown(n)` for a value it does not define.
     */
    var filetypeName: String {
        Self.filetypeNames.indices.contains(Int(self.filetype) - 1) ? Self.filetypeNames[Int(self.filetype) - 1] : "unknown(\(self.filetype))"
    }

    // MARK: - Page

    /**
     Whether the loaders map the image on 16 KiB pages, as `lipo` has it (`uses16KPages`): the arm64 family, and
     armv7k, the 32-bit ARM of watchOS; 4 KiB for every other architecture.
     */
    var uses16KPages: Bool {
        switch self.cpuType {
        case CPU_TYPE_ARM64, CPU_TYPE_ARM64_32:
            true
        case CPU_TYPE_ARM:
            self.cpuSubtype & ~cpu_subtype_t(bitPattern: CPU_SUBTYPE_MASK) == CPU_SUBTYPE_ARM_V7K
        default:
            false
        }
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
     Whether a NUL-padded 16-byte `segname` / `sectname` field holds `name`, byte for byte as Security's `strncmp`
     compares them: a name that only reads alike, with a Kelvin sign for the K of `__LINKEDIT`, is another name.
     */
    static func field(_ field: some Collection<UInt8>, is name: String) -> Bool {
        field.prefix { $0 != 0 }.elementsEqual(name.utf8)
    }

    /**
     The load commands as Security walks them: `MachO::MachO` reads the `sizeofcmds`-byte table, which must hold at least
     one command header, and `MachOBase::nextCommand` steps by each `cmdsize` until it reaches the end of the table; a
     command it steps onto must fit the table. The walk is valid when it ends there, whatever `ncmds` says, and when
     it has walked the `ncmds` commands the loaders read and what is left of the table holds no command: a tail the
     kernel and dyld never read, and Security reaches only when nothing it looks for comes first, which `codesign
     --verify` never does. It stops at the first command that breaks those rules otherwise.

     A `cmdsize` must hold the command's own header, as the kernel (`parse_machfile`) and dyld (`forEachLoadCommand`)
     require, where Security refuses zero alone and reads the next header inside a shorter command: a table of 4-byte
     commands would make twice the commands of its bytes. `nextCommand` never checks the first command, which Security
     then reads past its copy of the table when it overruns it: that is refused here too.

     The table is walked once to count its commands and judge it, then read into an array of that size: a crafted
     table of millions of commands costs their array and nothing more.
     */
    private static func parseLoadCommands(data: Data, headerSize: Int, ncmds: Int, sizeofcmds: Int, swap: Bool) -> (commands: [LoadCommand], valid: Bool, tail: Int) {
        let end = headerSize + sizeofcmds
        guard
            sizeofcmds >= MemoryLayout<load_command>.size,
            end <= data.count
        else {
            return ([], false, 0)
        }

        func header(at offset: Int) -> (cmd: UInt32, size: Int) {
            data.withUnsafeBytes { ptr in
                let cmd = ptr.loadUnaligned(fromByteOffset: offset, as: UInt32.self)
                let size = ptr.loadUnaligned(fromByteOffset: offset + 4, as: UInt32.self)
                return (swap ? cmd.byteSwapped : cmd, Int(swap ? size.byteSwapped : size))
            }
        }

        var count = 0
        var valid = false
        var offset = headerSize
        while true {
            let size = header(at: offset).size
            guard
                size >= MemoryLayout<load_command>.size,
                size <= end - offset
            else {
                break
            }
            count += 1
            offset += size
            if offset == end {
                valid = true
                break
            }
            guard offset + MemoryLayout<load_command>.size <= end else {
                break
            }
        }
        // The table's tail, past the commands the loaders read, holds no command.
        let tail = valid ? 0 : end - offset
        if tail > 0, count >= max(ncmds, 1) {
            valid = true
        }

        var commands: [LoadCommand] = []
        commands.reserveCapacity(count)
        offset = headerSize
        for _ in 0 ..< count {
            let (cmd, size) = header(at: offset)
            commands.append(LoadCommand(cmd: cmd, data: data.bytes(in: offset ..< offset + size)))
            offset += size
        }
        return (commands, valid, valid ? tail : 0)
    }

    /// `<mach-o/loader.h>` filetypes, numbered from `MH_OBJECT` (1).
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
     Whether the command is an `LC_SEGMENT` or `LC_SEGMENT_64` named `name` (`segname` sits at the same offset in both).
     */
    func isSegment(named name: String) -> Bool {
        [UInt32(LC_SEGMENT), UInt32(LC_SEGMENT_64)].contains(self.cmd) && MachO.field(self.data.dropFirst(8).prefix(16), is: name)
    }

    /// A segment command's name, up to its first NUL.
    var segmentName: String {
        String(decoding: self.data.dropFirst(8).prefix(16).prefix { $0 != 0 }, as: UTF8.self)
    }

    /// Where the `lc_str` of a dylib, dylinker, rpath or environment command says its string starts, from the
    /// command's start, byte-swapped when `swap`; nil for a command too short to say.
    func stringOffset(swap: Bool) -> Int? {
        guard self.data.count >= 12 else {
            return nil
        }
        let raw = self.data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 8, as: UInt32.self) }
        return Int(swap ? raw.byteSwapped : raw)
    }

    /// The `lc_str` a dylib, dylinker, rpath or environment command carries, its offset byte-swapped when `swap`:
    /// nil unless it starts past the command's `fixed` fields, 12 bytes unless the command has more, as a dylib
    /// command's 24, and ends inside the command, as dyld requires ("string start offset too small", "string extends
    /// beyond end of load command").
    func string(swap: Bool, fixed: Int = 12) -> String? {
        guard let offset = self.stringOffset(swap: swap), offset >= fixed, offset < self.data.count, let end = self.data.dropFirst(offset).firstIndex(of: 0) else {
            return nil
        }
        return String(decoding: self.data.dropFirst(offset).prefix(upTo: end), as: UTF8.self)
    }

    /// The command's name, as `<mach-o/loader.h>` spells it, or its number.
    var name: String {
        Self.name(self.cmd)
    }

    static func name(_ cmd: UInt32) -> String {
        self.names[cmd] ?? "load command \(cmd.hex)"
    }

    /// Whether `<mach-o/loader.h>` defines the command.
    var isKnown: Bool {
        Self.names[self.cmd] != nil
    }

    private static let names: [UInt32: String] = Dictionary(uniqueKeysWithValues: [
        (LC_SEGMENT, "LC_SEGMENT"),
        (LC_SYMTAB, "LC_SYMTAB"),
        (LC_SYMSEG, "LC_SYMSEG"),
        (LC_THREAD, "LC_THREAD"),
        (LC_UNIXTHREAD, "LC_UNIXTHREAD"),
        (LC_DYSYMTAB, "LC_DYSYMTAB"),
        (LC_LOAD_DYLIB, "LC_LOAD_DYLIB"),
        (LC_ID_DYLIB, "LC_ID_DYLIB"),
        (LC_LOAD_DYLINKER, "LC_LOAD_DYLINKER"),
        (LC_ID_DYLINKER, "LC_ID_DYLINKER"),
        (LC_PREBOUND_DYLIB, "LC_PREBOUND_DYLIB"),
        (LC_ROUTINES, "LC_ROUTINES"),
        (LC_SUB_FRAMEWORK, "LC_SUB_FRAMEWORK"),
        (LC_SUB_UMBRELLA, "LC_SUB_UMBRELLA"),
        (LC_SUB_CLIENT, "LC_SUB_CLIENT"),
        (LC_SUB_LIBRARY, "LC_SUB_LIBRARY"),
        (LC_TWOLEVEL_HINTS, "LC_TWOLEVEL_HINTS"),
        (LC_PREBIND_CKSUM, "LC_PREBIND_CKSUM"),
        (LC_SEGMENT_64, "LC_SEGMENT_64"),
        (LC_ROUTINES_64, "LC_ROUTINES_64"),
        (LC_UUID, "LC_UUID"),
        (LC_CODE_SIGNATURE, "LC_CODE_SIGNATURE"),
        (LC_SEGMENT_SPLIT_INFO, "LC_SEGMENT_SPLIT_INFO"),
        (LC_LAZY_LOAD_DYLIB, "LC_LAZY_LOAD_DYLIB"),
        (LC_ENCRYPTION_INFO, "LC_ENCRYPTION_INFO"),
        (LC_DYLD_INFO, "LC_DYLD_INFO"),
        (LC_VERSION_MIN_MACOSX, "LC_VERSION_MIN_MACOSX"),
        (LC_VERSION_MIN_IPHONEOS, "LC_VERSION_MIN_IPHONEOS"),
        (LC_FUNCTION_STARTS, "LC_FUNCTION_STARTS"),
        (LC_DYLD_ENVIRONMENT, "LC_DYLD_ENVIRONMENT"),
        (LC_DATA_IN_CODE, "LC_DATA_IN_CODE"),
        (LC_SOURCE_VERSION, "LC_SOURCE_VERSION"),
        (LC_DYLIB_CODE_SIGN_DRS, "LC_DYLIB_CODE_SIGN_DRS"),
        (LC_ENCRYPTION_INFO_64, "LC_ENCRYPTION_INFO_64"),
        (LC_LINKER_OPTION, "LC_LINKER_OPTION"),
        (LC_LINKER_OPTIMIZATION_HINT, "LC_LINKER_OPTIMIZATION_HINT"),
        (LC_VERSION_MIN_TVOS, "LC_VERSION_MIN_TVOS"),
        (LC_VERSION_MIN_WATCHOS, "LC_VERSION_MIN_WATCHOS"),
        (LC_NOTE, "LC_NOTE"),
        (LC_BUILD_VERSION, "LC_BUILD_VERSION"),
        (LC_ATOM_INFO, "LC_ATOM_INFO"),
        (LC_FUNCTION_VARIANTS, "LC_FUNCTION_VARIANTS"),
        (LC_FUNCTION_VARIANT_FIXUPS, "LC_FUNCTION_VARIANT_FIXUPS"),
        (LC_TARGET_TRIPLE, "LC_TARGET_TRIPLE"),
        (LC_LAZY_LOAD_DYLIB_INFO, "LC_LAZY_LOAD_DYLIB_INFO"),
    ].map { (UInt32(bitPattern: $0.0), $0.1) } + [
        (LC_LOAD_WEAK_DYLIB, "LC_LOAD_WEAK_DYLIB"),
        (LC_RPATH, "LC_RPATH"),
        (LC_REEXPORT_DYLIB, "LC_REEXPORT_DYLIB"),
        (LC_DYLD_INFO_ONLY, "LC_DYLD_INFO_ONLY"),
        (LC_LOAD_UPWARD_DYLIB, "LC_LOAD_UPWARD_DYLIB"),
        (LC_MAIN, "LC_MAIN"),
        (LC_DYLD_EXPORTS_TRIE, "LC_DYLD_EXPORTS_TRIE"),
        (LC_DYLD_CHAINED_FIXUPS, "LC_DYLD_CHAINED_FIXUPS"),
        (LC_FILESET_ENTRY, "LC_FILESET_ENTRY"),
    ])
}
