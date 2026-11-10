import Foundation
import MachO

/**
 What `verify` names about a Mach-O, as `MachOEditor` is what `unsign` and `unpack` do to one: a verifier over one
 image, which reads the image's layout once and names what is odd about it, one line each, in the order the headers
 are read.

 Five readers decide what a Mach-O is, and they disagree. The kernel maps an executable and its dylinker
 (`parse_machfile`, `load_segment`, `load_dylinker`, `pie_required`); dyld maps everything else (`forEachLoadCommand`,
 `validSegments`, `validMain`, `validEmbeddedPaths`, `isValidLinkeditLayout`); Security signs and verifies
 (`Universal`, `MachO::validateStructure`, `SecStaticCode::validateExecutable`, `verifySignature`); Gatekeeper and AMFI
 decide whose signature may run (syspolicyd's `PolicyScanner`, libmis's `AMFIPathValidator`, which `Signer` mirrors);
 Rosetta has rules of its own. A sixth reader is every static tool, this one included. What the kernel refuses, the
 parser refuses in red before this verifier sees the image. What another loader refuses and the parser does not is a
 line here, in that loader's words.
 What no loader refuses but a researcher wants named is a line too: what this tool's other flags undo, bytes appended,
 a signature that came out, UPX; and what one reader of the file believes that another does not, `ncmds` against the
 table, a section's file offset against its address, a name a prefix reads one way and a `strncmp` another, bytes no
 section or table covers, which no loader reads and codesign signs over.

 Everything is read from the headers, but for three things: the bytes nobody references, read to see whether they are
 zero; the signature's pages, read once as `codesign --verify` reads them; and the superblob's blobs, checked against
 the special slots that seal them. The groups below follow dyld's own validators, so a rule is found where dyld would
 have it, and a new one goes in the group it belongs to: a guard and a sentence, and a test that crafts the condition.

 A universal file has rules of its own, about the table and the slices as a whole, which `anomalies(universal:)`
 names, and a slice has two against its entry in the table, which `anomalies(slice:)` names.

 ```
 Verify.lines(for: file)                   one line per finding, "path[ (arch)]: finding", red for what is refused
   |
   Universal.open(file)
   |-- .thin(image) ------> MachOVerifier(image, in: file).anomalies()
   |-- .fat(table) -------> MachOVerifier.anomalies(universal: file, table)       the table: a hidden slice,
   |     for each arch:                                                           duplicates, overlaps, alignment,
   |       MachO(file, offset, length)?  nil -> MachOVerifier.anomaly(slice:)     padding, bytes past the last
   |       MachOVerifier(image, in: file)      .anomalies(slice: arch)            the entry against the header, the page
   |                                           .anomalies()
   `-- .notMachO ---------> nothing

 MachOVerifier(image, in: file)             parses the segments and their sections once, then, in header order:
   tableAnomalies       headers             ncmds against the table, sizes, ABI, commands taken once, filetype, reserved
   segmentAnomalies     headers             order, overlaps, sizes, the page, protections, __TEXT, __LINKEDIT, names
   sectionAnomalies     headers             address inside the segment, file offset against address, extent, names
   entryAnomalies       headers             LC_MAIN, LC_UNIXTHREAD's pc: a segment, executable, __TEXT, a section
   linkAnomalies        headers             lc_str strings, the dylinker, LC_DYLD_ENVIRONMENT, UUID, dylibs, flags
   extentAnomalies      headers             bytes appended, a signature's residue, UPX (PackMach, MachOEditor)
   linkeditAnomalies    reads the padding   tables inside __LINKEDIT, overlapping, bytes no table references
   paddingAnomalies     reads the padding   bytes no section covers, bytes between segments
   signatureAnomalies   reads the pages     pages against slots, code limit, special slots, the signer, entitlements
     -> Anomalies: found, and refused       what Security refuses of the superblob, red after the lines
 ```
 */
struct MachOVerifier {
    private let image: MachO
    /// The file the image lies in, which an edit of the image reads through.
    private let file: File
    /// The commands the loaders read, `ncmds` of them, which the loaders' rules run over: the kernel and dyld walk
    /// that many, where Security and the parser walk `sizeofcmds`; the table rules alone name what lies past them.
    private let commands: ArraySlice<MachO.LoadCommand>
    /// The segments, with their sections, parsed once for every group below.
    private let segments: [Segment]

    init(_ image: MachO, in file: File) {
        self.image = image
        self.file = file
        self.commands = image.loadCommands.prefix(image.ncmds)
        self.segments = Self.segments(of: image, among: self.commands)
    }

    /**
     What is odd about the image, one line each and none for an image with nothing to say: the load-command table,
     the segments, their sections, the entry point, what the image links, its version, bytes appended past it, a
     signature that came out, UPX, the `__LINKEDIT` layout, the bytes no section or table covers, then its signature.

     An image no loader maps has nothing to say: a dSYM companion, which dsymutil lays out with `__TEXT` empty and
     `__DWARF` after `__LINKEDIT`, an object file, whose one segment has no name and holds every section, a core, a
     dylib stub, which the SDKs lay out with sections at address 0, a GPU image, which Metal lays out in its own way.

     `refused` is what Security refuses of the signature, which the lines before it stand beside: a superblob it
     cannot read, reported red as hash mode reports it.
     */
    func anomalies() -> Anomalies {
        guard !self.isUnmapped else {
            return Anomalies(found: [], refused: nil)
        }
        var found = self.tableAnomalies()
        found += self.segmentAnomalies()
        found += self.sectionAnomalies()
        found += self.entryAnomalies()
        found += self.linkAnomalies()
        found += self.extentAnomalies()
        found += self.linkeditAnomalies()
        found += self.paddingAnomalies()
        do {
            found += try self.signatureAnomalies()
        } catch {
            return Anomalies(found: found, refused: error)
        }
        return Anomalies(found: found, refused: nil)
    }

    /// What is odd about an image, a line each, and what Security refuses of its signature, if anything.
    struct Anomalies {
        let found: [String]
        let refused: Error?
    }

    // MARK: - Layout

    /// A segment command's fields, in the image's byte order, with the sections its command holds.
    private struct Segment {
        /// The name as a line shows it: as it is when printable ASCII, quoted and escaped otherwise (see `shown`).
        let name: String
        /// The 16 bytes of `segname`.
        let field: Data
        let vmaddr: UInt64
        let vmsize: UInt64
        let fileoff: UInt64
        let filesize: UInt64
        let maxprot: Int32
        let initprot: Int32
        let nsects: UInt32
        let flags: UInt32
        let cmdsize: Int
        /// Whether the command is an `LC_SEGMENT_64`, whose structures are the wide ones whatever the image's.
        let wide: Bool
        let sections: [Section]

        var protection: String {
            Self.protection(self.initprot)
        }

        /// `prot` as `vmmap` spells it, `rwx`, a dash for each right it lacks.
        static func protection(_ prot: Int32) -> String {
            [(VM_PROT_READ, "r"), (VM_PROT_WRITE, "w"), (VM_PROT_EXECUTE, "x")].map { prot & $0.0 != 0 ? $0.1 : "-" }.joined()
        }

        var isExecutable: Bool {
            self.initprot & VM_PROT_EXECUTE != 0
        }

        var isWritable: Bool {
            self.initprot & VM_PROT_WRITE != 0
        }

        /// Whether the segment's address and vmsize add up past the address space, which no loader maps.
        var wraps: Bool {
            self.vmaddr.addingReportingOverflow(self.vmsize).overflow
        }

        /// Where the segment ends in memory, the address space's end where its range wraps around.
        var vmend: UInt64 {
            self.wraps ? UInt64.max : self.vmaddr + self.vmsize
        }

        /// Where the segment's content ends in the file, which the parser has checked lies inside the image.
        var fileend: UInt64 {
            self.fileoff + self.filesize
        }
    }

    /// A section's fields, in the image's byte order.
    private struct Section {
        /// The name as a line shows it (see `shown`).
        let name: String
        /// The 16 bytes of `sectname`, then the 16 of `segname`.
        let field: Data
        let segname: String
        let addr: UInt64
        let size: UInt64
        let offset: UInt32
        /// As a power of two.
        let align: UInt32
        let flags: UInt32

        /// Whether the section is of a zero-fill type, which the loader maps from no bytes of the file.
        var isZeroFill: Bool {
            [UInt32(S_ZEROFILL), UInt32(S_GB_ZEROFILL), UInt32(S_THREAD_LOCAL_ZEROFILL)].contains(self.flags & UInt32(SECTION_TYPE))
        }

        /// Whether the section has bytes in the file: not a zero-fill section, and not empty.
        var hasContent: Bool {
            !self.isZeroFill && self.size > 0
        }

        var fileend: UInt64 {
            UInt64(self.offset) &+ self.size
        }

        /// Whether an entry point belongs here: `__text`, a stub section, which an app extension enters through when
        /// its `_NSExtensionMain` is imported, or GCC's `__text_startup`.
        var holdsEntries: Bool {
            self.name == "__text" || self.name == "__text_startup" || self.flags & UInt32(SECTION_TYPE) == UInt32(S_SYMBOL_STUBS)
        }
    }

    /// The image's segments among `commands`, each with the sections its command holds.
    private static func segments(of image: MachO, among commands: ArraySlice<MachO.LoadCommand>) -> [Segment] {
        commands.compactMap { command in
            switch command.cmd {
            case UInt32(LC_SEGMENT):
                command.payload(as: segment_command.self).map {
                    Segment(name: Self.shown(command.data.bytes(in: 8 ..< 24)), field: command.data.bytes(in: 8 ..< 24), vmaddr: UInt64(image.sw($0.vmaddr)), vmsize: UInt64(image.sw($0.vmsize)), fileoff: UInt64(image.sw($0.fileoff)), filesize: UInt64(image.sw($0.filesize)), maxprot: image.sw($0.maxprot), initprot: image.sw($0.initprot), nsects: image.sw($0.nsects), flags: image.sw($0.flags), cmdsize: command.data.count, wide: false, sections: self.sections(of: command, in: image, header: MemoryLayout<segment_command>.size, count: Int(image.sw($0.nsects)), wide: false))
                }
            case UInt32(LC_SEGMENT_64):
                command.payload(as: segment_command_64.self).map {
                    Segment(name: Self.shown(command.data.bytes(in: 8 ..< 24)), field: command.data.bytes(in: 8 ..< 24), vmaddr: image.sw($0.vmaddr), vmsize: image.sw($0.vmsize), fileoff: image.sw($0.fileoff), filesize: image.sw($0.filesize), maxprot: image.sw($0.maxprot), initprot: image.sw($0.initprot), nsects: image.sw($0.nsects), flags: image.sw($0.flags), cmdsize: command.data.count, wide: true, sections: self.sections(of: command, in: image, header: MemoryLayout<segment_command_64>.size, count: Int(image.sw($0.nsects)), wide: true))
                }
            default:
                nil
            }
        }
    }

    /// The sections a segment command holds: as many of the `count` it declares as fit after its `header` bytes.
    private static func sections(of command: MachO.LoadCommand, in image: MachO, header: Int, count: Int, wide: Bool) -> [Section] {
        let stride = wide ? MemoryLayout<section_64>.size : MemoryLayout<section>.size
        let held = min(count, max(0, (command.data.count - header) / stride))
        return (0 ..< held).map { index in
            let at = header + index * stride
            let data = command.data.bytes(in: at ..< at + stride)
            /// The bytes of the entry at `range`, as a line shows a name.
            func name(_ range: Range<Int>) -> String {
                Self.shown(data.bytes(in: range))
            }
            return data.withUnsafeBytes { raw in
                if wide {
                    let section = raw.loadUnaligned(as: section_64.self)
                    return Section(name: name(0 ..< 16), field: data.prefix(32), segname: name(16 ..< 32), addr: image.sw(section.addr), size: image.sw(section.size), offset: image.sw(section.offset), align: image.sw(section.align), flags: image.sw(section.flags))
                }
                let section = raw.loadUnaligned(as: section.self)
                return Section(name: name(0 ..< 16), field: data.prefix(32), segname: name(16 ..< 32), addr: UInt64(image.sw(section.addr)), size: UInt64(image.sw(section.size)), offset: image.sw(section.offset), align: image.sw(section.align), flags: image.sw(section.flags))
            }
        }
    }

    /**
     A 16-byte name field as a line shows it: the bytes up to its NUL as they are when they are printable ASCII, and
     quoted and escaped otherwise, so that a name with a newline or a quote in it stays on its line.
     */
    private static func shown(_ field: Data) -> String {
        let name = field.prefix { $0 != 0 }
        let decoded = String(decoding: name, as: UTF8.self)
        return name.allSatisfy { 0x20 ... 0x7e ~= $0 } ? decoded : Self.escaped(decoded)
    }

    /**
     A string the image carries, a dylib's name, a certificate's, an entitlement's key, as a line shows it: as it is
     when printable ASCII, quoted and escaped otherwise, so that a newline in it cannot make a line of its own.
     */
    private static func shown(_ string: String) -> String {
        string.utf8.allSatisfy { 0x20 ... 0x7e ~= $0 } ? string : self.escaped(string)
    }

    /// `string` quoted and escaped as Swift's debug description writes it, the format characters it leaves as they
    /// are, a right-to-left override that would reorder the line say, escaped as `\u{202E}` too.
    private static func escaped(_ string: String) -> String {
        String(String.UnicodeScalarView(string.debugDescription.unicodeScalars.flatMap { scalar in
            Console.isPrintable(scalar) ? [scalar] : Array("\\u{\(String(scalar.value, radix: 16, uppercase: true))}".unicodeScalars)
        }))
    }

    /// The filetypes dyld loads and the kernel runs, whose layout its rules are about.
    private static let loadableFiletypes = [MH_EXECUTE, MH_DYLIB, MH_BUNDLE, MH_DYLINKER].map(UInt32.init)

    private var isLoadable: Bool {
        Self.loadableFiletypes.contains(self.image.filetype)
    }

    /// The major version of the SDK the image was built against, as its version command records it; nil without one.
    private var sdkMajor: UInt32? {
        (try? self.image.version()).map { $0.sdk >> 16 }
    }

    /// Whether no loader maps the image as a file (see `anomalies()`).
    private var isUnmapped: Bool {
        [MH_OBJECT, MH_CORE, MH_DYLIB_STUB, MH_DSYM, MH_GPU_EXECUTE, MH_GPU_DYLIB].map(UInt32.init).contains(self.image.filetype)
    }

    // MARK: - Load-command table

    /// The commands dyld's `Header::validLoadCommands` and `getLinkEditLoadCommands`, the kernel's `parse_machfile` and
    /// Rosetta take once ("multiple LC_… load commands found").
    private static let singleCommands: [UInt32] = [
        LC_SYMTAB,
        LC_DYSYMTAB,
        LC_DYLD_INFO,
        LC_SEGMENT_SPLIT_INFO,
        LC_FUNCTION_STARTS,
        LC_DATA_IN_CODE,
        LC_CODE_SIGNATURE,
        LC_UUID,
        LC_ENCRYPTION_INFO,
        LC_ENCRYPTION_INFO_64,
        LC_LOAD_DYLINKER,
        LC_UNIXTHREAD,
        LC_ID_DYLIB,
        LC_ROUTINES,
        LC_ROUTINES_64,
        LC_ATOM_INFO,
        LC_FUNCTION_VARIANTS,
        LC_FUNCTION_VARIANT_FIXUPS,
        LC_TARGET_TRIPLE,
    ].map { UInt32(bitPattern: $0) } + [
        LC_DYLD_INFO_ONLY,
        LC_DYLD_EXPORTS_TRIE,
        LC_DYLD_CHAINED_FIXUPS,
        LC_MAIN,
    ]

    private static let versionMinCommands = [LC_VERSION_MIN_MACOSX, LC_VERSION_MIN_IPHONEOS, LC_VERSION_MIN_TVOS, LC_VERSION_MIN_WATCHOS].map { UInt32(bitPattern: $0) }

    /// The commands of a fixed structure, and its size, which dyld's `validStructureLoadCommands` asks exactly
    /// ("load command size wrong") where the parser asks that the structure fit.
    private static let fixedSizes: [UInt32: Int] = Dictionary(uniqueKeysWithValues: [
        (LC_SYMTAB, MemoryLayout<symtab_command>.size),
        (LC_DYSYMTAB, MemoryLayout<dysymtab_command>.size),
        (LC_UUID, MemoryLayout<uuid_command>.size),
        (LC_DYLD_INFO, MemoryLayout<dyld_info_command>.size),
        (LC_ENCRYPTION_INFO, MemoryLayout<encryption_info_command>.size),
        (LC_ENCRYPTION_INFO_64, MemoryLayout<encryption_info_command_64>.size),
        (LC_ROUTINES, MemoryLayout<routines_command>.size),
        (LC_ROUTINES_64, MemoryLayout<routines_command_64>.size),
        (LC_SOURCE_VERSION, MemoryLayout<source_version_command>.size),
        (LC_VERSION_MIN_MACOSX, MemoryLayout<version_min_command>.size),
        (LC_VERSION_MIN_IPHONEOS, MemoryLayout<version_min_command>.size),
        (LC_VERSION_MIN_TVOS, MemoryLayout<version_min_command>.size),
        (LC_VERSION_MIN_WATCHOS, MemoryLayout<version_min_command>.size),
        (LC_CODE_SIGNATURE, MemoryLayout<linkedit_data_command>.size),
        (LC_SEGMENT_SPLIT_INFO, MemoryLayout<linkedit_data_command>.size),
        (LC_FUNCTION_STARTS, MemoryLayout<linkedit_data_command>.size),
        (LC_DATA_IN_CODE, MemoryLayout<linkedit_data_command>.size),
        (LC_DYLIB_CODE_SIGN_DRS, MemoryLayout<linkedit_data_command>.size),
        (LC_LINKER_OPTIMIZATION_HINT, MemoryLayout<linkedit_data_command>.size),
        (LC_ATOM_INFO, MemoryLayout<linkedit_data_command>.size),
        (LC_FUNCTION_VARIANTS, MemoryLayout<linkedit_data_command>.size),
        (LC_FUNCTION_VARIANT_FIXUPS, MemoryLayout<linkedit_data_command>.size),
    ].map { (UInt32(bitPattern: $0.0), $0.1) } + [
        (LC_DYLD_INFO_ONLY, MemoryLayout<dyld_info_command>.size),
        (LC_MAIN, MemoryLayout<entry_point_command>.size),
        (LC_DYLD_EXPORTS_TRIE, MemoryLayout<linkedit_data_command>.size),
        (LC_DYLD_CHAINED_FIXUPS, MemoryLayout<linkedit_data_command>.size),
    ])

    /// How many commands a line names one by one, where a crafted table holds millions: the rest are counted.
    private static let listed = 8

    /**
     The table as the loaders walk it: `ncmds` commands, where Security and this parser walk `sizeofcmds` (the
     kernel's `parse_machfile`, dyld's `forEachLoadCommand`), so `ncmds` short of the table hides commands from the
     loaders alone, and bytes past the last command inside `sizeofcmds` are read by none of them; a command size that
     is not pointer sized, which dyld's `Header::validLoadCommands` refuses (the
     published `forEachLoadCommand` asks a multiple of 4 alone); a command dyld does not know, flagged `LC_REQ_DYLD`,
     where one without the flag is skipped; a command of a fixed structure sized otherwise, whose extra bytes no
     loader reads, or `LC_BUILD_VERSION` sized other than its tools; a segment command of the other ABI, which the
     kernel refuses; a command the loaders take once, twice; `LC_DYSYMTAB` without `LC_SYMTAB`, or partitioning the
     symbol table other than as the linker lays it, locals, then externals, then undefined; `LC_LINKER_OPTION`
     outside an object; two fixup encodings, two entry points, two version commands in an executable; a filetype no
     loader knows; the header field no loader reads.
     */
    private func tableAnomalies() -> [String] {
        let image = self.image
        var found: [String] = []
        let held = image.loadCommands.count
        if image.ncmds < held {
            // The hidden commands named, up to a few: a crafted table hides millions.
            let hidden = image.loadCommands[image.ncmds...]
            let unread = hidden.prefix(Self.listed).map(\.name).joined(separator: ", ") + (hidden.count > Self.listed ? "…" : "")
            found.append("ncmds \(image.ncmds) hides the last \(String(held - image.ncmds, pluralizing: "command")) of \(held) from the loaders: \(unread)")
        } else if image.ncmds > held {
            found.append("ncmds \(image.ncmds) exceeds the \(String(held, pluralizing: "command")) the table holds")
        }
        if image.loadCommandsTail > 0 {
            found.append("sizeofcmds holds \(image.loadCommandsTail.hex) bytes past the last load command, which the loaders never read and Security's walk stops short of: codesign verifies the image and cannot re-sign it, Rosetta refuses it")
        }
        let pointer = image.is64 ? 8 : 4
        let unaligned = self.commands.enumerated().filter { $0.element.data.count % pointer != 0 }
        for (index, command) in unaligned.prefix(Self.listed) {
            found.append("load command #\(index), \(command.name), has a size \(command.data.count.hex) that is not a multiple of \(pointer)")
        }
        if unaligned.count > Self.listed {
            found.append("and \(String(unaligned.count - Self.listed, pluralizing: "more load command")) with a size that is not a multiple of \(pointer)")
        }

        // dyld's validStructureLoadCommands: a command it does not know is skipped, unless the command is flagged
        // LC_REQ_DYLD ("unknown required load command"); a command of a fixed structure is exactly that size ("load
        // command size wrong"), as is LC_BUILD_VERSION for its tools: the bytes past the structure are a place no
        // loader reads, as the header pad is.
        let required = self.commands.enumerated().filter { !$0.element.isKnown && $0.element.cmd & UInt32(LC_REQ_DYLD) != 0 }
        for (index, command) in required.prefix(Self.listed) {
            found.append("load command #\(index), \(command.name), is unknown and flagged LC_REQ_DYLD, which dyld refuses")
        }
        if required.count > Self.listed {
            found.append("and \(String(required.count - Self.listed, pluralizing: "more unknown load command")) flagged LC_REQ_DYLD")
        }
        // A command shorter than its structure is one too: LC_BUILD_VERSION without room for its tool count, a
        // segment command without room for its header, which the segment rules then never see.
        let sized = self.commands.enumerated().compactMap { index, command -> (Int, MachO.LoadCommand, Int)? in
            let expected: Int? = switch command.cmd {
            case UInt32(LC_BUILD_VERSION):
                MemoryLayout<build_version_command>.size + (command.payload(as: build_version_command.self).map { Int(image.sw($0.ntools)) } ?? 0) * MemoryLayout<build_tool_version>.size
            case UInt32(LC_SEGMENT):
                command.data.count < MemoryLayout<segment_command>.size ? MemoryLayout<segment_command>.size : nil
            case UInt32(LC_SEGMENT_64):
                command.data.count < MemoryLayout<segment_command_64>.size ? MemoryLayout<segment_command_64>.size : nil
            default:
                Self.fixedSizes[command.cmd]
            }
            return expected.flatMap { $0 == command.data.count ? nil : (index, command, $0) }
        }
        for (index, command, expected) in sized.prefix(Self.listed) {
            found.append("load command #\(index), \(command.name), is \(command.data.count.hex) bytes, not its structure's \(expected.hex), which dyld refuses")
        }
        if sized.count > Self.listed {
            found.append("and \(String(sized.count - Self.listed, pluralizing: "more load command")) sized other than their structure")
        }
        let counts = Dictionary(self.commands.map { ($0.cmd, 1) }, uniquingKeysWith: +)
        if image.is64, counts[UInt32(LC_SEGMENT)] != nil {
            found.append("LC_SEGMENT in a 64-bit image")
        }
        if !image.is64, counts[UInt32(LC_SEGMENT_64)] != nil {
            found.append("LC_SEGMENT_64 in a 32-bit image")
        }
        for cmd in Self.singleCommands {
            if let count = counts[cmd], count > 1 {
                found.append("\(count) \(MachO.LoadCommand.name(cmd)) commands")
            }
        }
        // dyld's validStructureLoadCommands counts LC_DYLD_INFO_ONLY with LC_DYLD_INFO and LC_ROUTINES_64 with
        // LC_ROUTINES ("multiple LC_DYLD_INFO load commands found"): one of each is two to it.
        for (one, other) in [(UInt32(LC_DYLD_INFO), LC_DYLD_INFO_ONLY), (UInt32(LC_ROUTINES), UInt32(LC_ROUTINES_64))] where counts[one] != nil && counts[other] != nil {
            found.append("\(MachO.LoadCommand.name(one)) beside \(MachO.LoadCommand.name(other)), which dyld counts as two \(MachO.LoadCommand.name(one)) commands")
        }
        // The kernel takes one version command of an executable (`found_version_cmd`); a zippered dylib carries two
        // LC_BUILD_VERSION, which dyld reads both of.
        let versionMins = Self.versionMinCommands.reduce(0) { $0 + counts[$1, default: 0] }
        if image.filetype == UInt32(MH_EXECUTE) {
            if let count = counts[UInt32(LC_BUILD_VERSION)], count > 1 {
                found.append("\(count) LC_BUILD_VERSION commands")
            }
            if versionMins > 1 {
                found.append("\(versionMins) LC_VERSION_MIN_* commands")
            }
            if versionMins > 0, counts[UInt32(LC_BUILD_VERSION)] != nil {
                found.append("LC_BUILD_VERSION and LC_VERSION_MIN_* both")
            }
        }
        // ld64 always writes an LC_SYMTAB and strip keeps it; a UPX stub has none, and symhash has nothing to hash.
        // dyld loads an image without one all the same.
        if counts[UInt32(LC_SYMTAB)] == nil {
            found.append("no external symbol table")
        }
        if counts[UInt32(LC_DYSYMTAB)] != nil, counts[UInt32(LC_SYMTAB)] == nil {
            found.append("LC_DYSYMTAB without LC_SYMTAB")
        }
        // dyld's parse_dysymtab_command: the symbol table partitioned as the linker lays it, the locals first, the
        // externals where they end, the undefined where those end ("ilocalsym != 0", "iextdefsym != nlocalsym",
        // "iundefsym != iextdefsym+nextdefsym"), which an edit of the table after linking breaks.
        if let dysymtab = image.findCommand(UInt32(LC_DYSYMTAB))?.payload(as: dysymtab_command.self) {
            let (ilocalsym, nlocalsym, iextdefsym, nextdefsym, iundefsym) = (image.sw(dysymtab.ilocalsym), image.sw(dysymtab.nlocalsym), image.sw(dysymtab.iextdefsym), image.sw(dysymtab.nextdefsym), image.sw(dysymtab.iundefsym))
            if ilocalsym != 0 {
                found.append("LC_DYSYMTAB's local symbols start at \(ilocalsym), not 0, which dyld refuses")
            }
            if iextdefsym != nlocalsym {
                found.append("LC_DYSYMTAB's external symbols start at \(iextdefsym), not after the \(String(Int(nlocalsym), pluralizing: "local")) at \(ilocalsym), which dyld refuses")
            }
            if iundefsym != iextdefsym &+ nextdefsym {
                found.append("LC_DYSYMTAB's undefined symbols start at \(iundefsym), not after the \(String(Int(nextdefsym), pluralizing: "external")) at \(iextdefsym), which dyld refuses")
            }
            // dyld's validStructureLinkedit, one fixup encoding per image: relocation tables beside chained fixups or
            // LC_DYLD_INFO_ONLY ("malformed mach-o contains LC_DYLD_CHAINED_FIXUPS and local relocations").
            if let fixups = counts[LC_DYLD_CHAINED_FIXUPS] != nil ? "LC_DYLD_CHAINED_FIXUPS" : counts[LC_DYLD_INFO_ONLY] != nil ? "LC_DYLD_INFO_ONLY" : nil {
                for (what, count) in [("local", dysymtab.nlocrel), ("external", dysymtab.nextrel)] where image.sw(count) != 0 {
                    found.append("LC_DYSYMTAB holds \(String(Int(image.sw(count)), pluralizing: "\(what) relocation")) beside \(fixups), which dyld refuses")
                }
            }
        }
        if image.filetype != UInt32(MH_OBJECT), counts[UInt32(LC_LINKER_OPTION)] != nil {
            found.append("LC_LINKER_OPTION in an \(image.filetypeName), which dyld refuses: the compiler writes it in an object, for the linker")
        }
        if counts[UInt32(LC_DYLD_INFO)] != nil || counts[LC_DYLD_INFO_ONLY] != nil, counts[LC_DYLD_CHAINED_FIXUPS] != nil {
            found.append("LC_DYLD_INFO and LC_DYLD_CHAINED_FIXUPS both")
        }
        if counts[LC_MAIN] != nil, counts[UInt32(LC_UNIXTHREAD)] != nil {
            found.append("LC_MAIN and LC_UNIXTHREAD both")
        }
        if image.filetypeName.hasPrefix("unknown") {
            found.append("filetype \(image.filetypeName), which no loader knows")
        }
        if image.reserved != 0 {
            found.append("the header's reserved field holds \(image.reserved.hex)")
        }
        return found
    }

    // MARK: - Segments

    /**
     Segments as dyld's `validSegments` and the kernel's `load_segment` take them: out of order or overlapping, in the
     file or in memory, a file size past a vmsize, an address range that wraps around, a command that does not hold
     its sections, a file offset off the page the platform maps, protection bits beyond rwx or past the maximum, a
     name twice or empty,
     `__TEXT` not at the file's start or too small for the load commands, `__LINKEDIT` not last, protections other
     than r-x, r-- and rw- on the three, `__DATA_CONST` other than rw- in an image dyld manages, more than the 255
     segments dyld takes, any other segment writable and executable or executable at all, `__TEXT`
     with room past its file size, as a packer leaves it, or without sections, a segment flagged Apple-protected,
     whose pages the kernel decrypts as it maps them, and names that read as one thing to a prefix and another to a
     `strncmp`.
     */
    private func segmentAnomalies() -> [String] {
        let image = self.image
        let segments = self.segments
        var found: [String] = []
        let loaded = segments.filter { $0.filesize > 0 }
        let mapped = segments.filter { $0.vmsize > 0 }
        for (before, after) in zip(loaded, loaded.dropFirst()) where after.fileoff < before.fileoff {
            found.append("segment \(after.name)'s file offset \(after.fileoff.hex) is out of order after \(before.name)'s \(before.fileoff.hex)")
        }
        for (before, after) in zip(mapped, mapped.dropFirst()) where after.vmaddr < before.vmaddr {
            found.append("segment \(after.name)'s address \(after.vmaddr.hex) is out of order after \(before.name)'s \(before.vmaddr.hex)")
        }
        for (one, other) in Self.overlapping(loaded, from: \.fileoff, to: \.fileend) {
            found.append("segments \(one.name) and \(other.name) overlap in the file")
        }
        for (one, other) in Self.overlapping(mapped, from: \.vmaddr, to: \.vmend) {
            found.append("segments \(one.name) and \(other.name) overlap in memory")
        }
        for segment in segments where segment.filesize > segment.vmsize {
            found.append("segment \(segment.name)'s file size \(segment.filesize.hex) exceeds its vmsize \(segment.vmsize.hex)")
        }
        for segment in mapped where segment.wraps {
            found.append("segment \(segment.name)'s address \(segment.vmaddr.hex) and vmsize \(segment.vmsize.hex) wrap around the address space")
        }

        // dyld's validSegments: the command's size is its sections' exactly; the kernel's load_segment: a file offset
        // it can map, which is on a page of the platform's, 4 KiB for iOS before 16 and tvOS, where the kernel maps an
        // arm64 image on 4 KiB pages, as codesign's MachORep::pageSize has it; dyld: protection bits it knows; the kernel
        // maps a segment with no more than its maximum.
        let page = UInt64(image.segmentAlignment)
        let mappedPage = (try? image.pageSizeLog()).map { UInt64(1) << UInt64($0) } ?? page
        for segment in segments {
            // Measured by the command's own structures, which a command of the other ABI keeps.
            if segment.sections.count != Int(segment.nsects) || (segment.cmdsize - (segment.wide ? MemoryLayout<segment_command_64>.size : MemoryLayout<segment_command>.size)) % (segment.wide ? MemoryLayout<section_64>.size : MemoryLayout<section>.size) != 0 {
                found.append("segment \(segment.name)'s command size \(segment.cmdsize.hex) does not hold its \(String(Int(segment.nsects), pluralizing: "section"))")
            }
            if self.isLoadable, segment.fileoff % mappedPage != 0 {
                found.append("segment \(segment.name)'s file offset \(segment.fileoff.hex) is not page aligned")
            }
            if (segment.initprot | segment.maxprot) & ~(VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE) != 0 {
                found.append("segment \(segment.name)'s protection has bits beyond rwx: \(segment.initprot.hex) within \(segment.maxprot.hex)")
            } else if segment.initprot & ~segment.maxprot != 0 {
                found.append("segment \(segment.name)'s protection \(segment.protection) exceeds its maximum \(Segment.protection(segment.maxprot))")
            }
        }
        for (name, count) in Dictionary(segments.map { ($0.name, 1) }, uniquingKeysWith: +).sorted(by: { $0.key < $1.key }) where count > 1 {
            found.append(name.isEmpty ? "\(count) segments with an empty name" : "\(count) segments named \(name)")
        }
        if segments.count == 1 + segments.filter({ !$0.name.isEmpty }).count {
            found.append("a segment with an empty name")
        }
        // dyld's validSemanticsSegments: "too many segments".
        if self.isLoadable, segments.count > 255 {
            found.append("\(segments.count) segments, more than the 255 dyld takes")
        }

        let headerSize = image.headerSize
        let text = segments.first { $0.name == "__TEXT" }
        if let text {
            if text.fileoff != 0 {
                found.append("__TEXT starts at file offset \(text.fileoff.hex), not 0")
            }
            if text.filesize < UInt64(headerSize + image.sizeofcmds) {
                found.append("the load commands, \((headerSize + image.sizeofcmds).hex) bytes, do not fit in __TEXT's \(text.filesize.hex)")
            }
            if text.protection != "r-x" {
                found.append("__TEXT's protection is \(text.protection), not r-x")
            }
            // The linker rounds __TEXT's vmsize up to the page; a packer leaves the room it unpacks into.
            let rounded = (text.filesize + page - 1) & ~(page - 1)
            if text.vmsize > rounded {
                found.append("__TEXT's vmsize \(text.vmsize.hex) exceeds its file size \(text.filesize.hex) by more than a page")
            }
            if self.isLoadable, text.nsects == 0 {
                found.append("__TEXT has no sections")
            }
        } else if [MH_EXECUTE, MH_DYLIB, MH_BUNDLE].map(UInt32.init).contains(image.filetype) {
            found.append("no __TEXT segment")
        }
        if let index = segments.lastIndex(where: { $0.name == "__LINKEDIT" }) {
            if index != segments.count - 1 {
                found.append("__LINKEDIT is not the last segment")
            }
            if segments[index].protection != "r--" {
                found.append("__LINKEDIT's protection is \(segments[index].protection), not r--")
            }
        }
        for segment in segments where segment.name == "__DATA" && segment.protection != "rw-" {
            found.append("__DATA's protection is \(segment.protection), not rw-")
        }
        // dyld's validSemanticsSingleSegment, of an image it manages: __DATA_CONST maps rw- too, as a dyld-managed
        // image's __DATA_CONST is written before it is made read-only.
        if self.image.isDyldManaged {
            for segment in segments where segment.name == "__DATA_CONST" && segment.protection != "rw-" {
                found.append("__DATA_CONST's protection is \(segment.protection), not rw-, which dyld refuses")
            }
        }
        // __IMPORT, the i386 linker's segment of self-modifying symbol stubs, is rwx by design, and __TEXT_EXEC is a
        // kext's code. The kernel's vm_map_enter maps a writable and executable segment with execute off on arm64
        // ("curprot cannot be write+execute. turning off execute"): the segment's code faults when entered.
        let wx = [CPU_TYPE_ARM64, CPU_TYPE_ARM64_32].contains(image.cpuType) ? ", which the kernel maps without execute as arm64" : ""
        let own = ["__TEXT", "__DATA", "__LINKEDIT", "__IMPORT"] + (image.filetype == UInt32(MH_KEXT_BUNDLE) ? ["__TEXT_EXEC"] : [])
        for segment in segments where !own.contains(segment.name) && segment.isExecutable {
            found.append(segment.isWritable ? "segment \(segment.name) is writable and executable\(wx)" : "segment \(segment.name) is executable")
        }

        // The kernel's load_segment hands a segment flagged SG_PROTECTED_VERSION_1 to unprotect_dsmos_segment, which
        // decrypts its pages as it maps them, but for the image's first three pages, APPLE_UNPROTECTED_HEADER_SIZE,
        // counted from the image's start and not the segment's: Apple's own protection of a few 10.4 to 10.6
        // binaries, which a third party's image can claim too, so that its code reads encrypted on disk.
        for segment in segments where segment.flags & UInt32(SG_PROTECTED_VERSION_1) != 0 {
            let clear = segment.fileoff < 0x3000 ? 0x3000 - segment.fileoff : 0
            found.append("segment \(segment.name) is Apple-protected (SG_PROTECTED_VERSION_1): the kernel decrypts it \(clear > 0 ? "past its first \(clear.hex) bytes" : "whole") as it maps it, the image's first 0x3000 bytes left clear")
        }

        for segment in segments {
            found += Self.nameAnomalies(segment.field, of: "segment \(segment.name)")
        }
        return found
    }

    /**
     The pairs of `segments` whose ranges, `from` their start `to` their end, overlap: each segment against the one
     before it, in the order of their starts, that reaches furthest, which is the one it overlaps when any does. One
     pass over the segments, however many a crafted table holds, where every pair would cost the square of their
     count.
     */
    private static func overlapping(_ segments: [Segment], from start: KeyPath<Segment, UInt64>, to end: KeyPath<Segment, UInt64>) -> [(Segment, Segment)] {
        var found: [(Segment, Segment)] = []
        var furthest: Segment?
        let sorted = segments.indices.sorted { (segments[$0][keyPath: start], $0) < (segments[$1][keyPath: start], $1) }.map { segments[$0] }
        for segment in sorted {
            if let furthest, segment[keyPath: start] < furthest[keyPath: end] {
                found.append((furthest, segment))
            }
            if furthest.map({ segment[keyPath: end] > $0[keyPath: end] }) ?? true {
                furthest = segment
            }
        }
        return found
    }

    /**
     What a 16-byte name field holds that one reader sees and another does not: bytes after its NUL, which a prefix
     reader never sees and a `strncmp` reader compares, and bytes that are not printable ASCII, which print as another
     name than they are.
     */
    private static func nameAnomalies(_ field: Data, of what: String) -> [String] {
        var found: [String] = []
        let name = field.prefix { $0 != 0 }
        if field.drop(while: { $0 != 0 }).contains(where: { $0 != 0 }) {
            found.append("\(what)'s name has bytes after its NUL")
        }
        if !name.allSatisfy({ 0x20 ... 0x7e ~= $0 }) {
            found.append("\(what)'s name is not printable ASCII")
        }
        return found
    }

    // MARK: - Sections

    /**
     A section as dyld's `validSegments` and `Header::validSections` read it: its address range outside its
     segment's, or not aligned as its align field declares, in a segment that is mapped (Go's `__DWARF` has no
     vmsize, and dyld maps none of it); no file offset though it is not zero-fill; a file offset though it is
     zero-fill, or no name, which the live dyld refuses of an image it manages built against the SDK of fall 2026
     or later (`validSemanticsSingleSegment`); two sections sharing addresses or bytes; the segment name it carries
     not its segment's. And as a disassembler reads it: its file offset not where
     its address lays it, so the tool reads other bytes than the loader maps; its bytes past the image; its name.
     */
    private func sectionAnomalies() -> [String] {
        var found: [String] = []
        // The lines of a few sections, or pairs of them, named one by one, the rest counted: a crafted table holds
        // hundreds of thousands of sections, each tripping every rule.
        var named = 0
        var more = 0
        var moreLines = 0
        /// `lines` for one section, taken while few sections were named, counted after that.
        func add(_ lines: [String]) {
            guard !lines.isEmpty else {
                return
            }
            if named < Self.listed {
                found += lines
                named += 1
            } else {
                more += 1
                moreLines += lines.count
            }
        }
        let recent = self.image.isDyldManaged && (self.sdkMajor ?? 0) >= 27
        for segment in self.segments {
            for section in segment.sections {
                var lines: [String] = []
                let what = "section \(segment.name),\(section.name)"
                let end = section.addr.addingReportingOverflow(section.size)
                if segment.vmsize == 0 {
                    // Not mapped: its addresses are the linker's own business.
                } else if end.overflow || section.addr < segment.vmaddr || end.partialValue > segment.vmend {
                    lines.append("\(what)'s address range \(section.addr.hex)...\(end.partialValue.hex) lies outside its segment's \(segment.vmaddr.hex)...\(segment.vmend.hex)")
                } else if section.hasContent, segment.filesize > 0 {
                    // Where the address lays it may lie past 2^64, in a segment that maps most of the address space.
                    let expected = segment.fileoff.addingReportingOverflow(section.addr - segment.vmaddr)
                    if expected.overflow || UInt64(section.offset) != expected.partialValue {
                        lines.append("\(what)'s file offset \(section.offset.hex) is not where its address lays it, \(expected.overflow ? "past 2^64" : expected.partialValue.hex)")
                    }
                }
                if section.hasContent, section.fileend < UInt64(section.offset) || section.fileend > UInt64(self.image.length) {
                    lines.append("\(what) at \(section.offset.hex) with size \(section.size.hex) lies outside the image")
                }
                if segment.vmsize > 0, section.addr % (1 << UInt64(min(section.align, 63))) != 0 {
                    lines.append("\(what)'s address \(section.addr.hex) is not aligned to the 2^\(section.align) its align field declares")
                }
                if section.offset == 0, section.hasContent {
                    lines.append("\(what) has no file offset though it is not zero-fill")
                }
                // The live dyld's validSemanticsSingleSegment, of an image it manages built against the SDK of
                // fall 2026 or later: a zero-fill section has no file offset, and every section a name.
                if recent {
                    if section.isZeroFill, section.offset != 0 {
                        lines.append("\(what) is zero-fill with a file offset \(section.offset.hex), which dyld refuses")
                    }
                    if section.field.prefix(16).allSatisfy({ $0 == 0 }) {
                        lines.append("a section of \(segment.name) with an empty name, which dyld refuses")
                    }
                }
                if section.segname != segment.name {
                    lines.append("\(what) carries the segment name \(section.segname)")
                }
                lines += Self.nameAnomalies(section.field.prefix(16), of: what)
                add(lines)
            }
            let placed = segment.sections.filter(\.hasContent).sorted { $0.offset < $1.offset }
            for (before, after) in zip(placed, placed.dropFirst()) where UInt64(after.offset) < before.fileend {
                add(["sections \(segment.name),\(before.name) and \(segment.name),\(after.name) overlap in the file"])
            }
            let mapped = segment.sections.filter { $0.size > 0 }.sorted { $0.addr < $1.addr }
            for (before, after) in zip(mapped, mapped.dropFirst()) where after.addr < before.addr &+ before.size {
                add(["sections \(segment.name),\(before.name) and \(segment.name),\(after.name) overlap in memory"])
            }
        }
        if more > 0 {
            found.append("and \(String(moreLines, pluralizing: "more line")) on \(String(more, pluralizing: "more section")) or pair of them")
        }
        return found
    }

    // MARK: - Entry point

    /**
     An executable's entry point as dyld's `validMain` finds it: `LC_MAIN`'s `entryoff` from `__TEXT`'s address,
     `LC_UNIXTHREAD`'s pc register, in a segment that is executable, which should be `__TEXT`, and in its `__text`
     section, a stub section, which an app extension enters through, or GCC's `__text_startup`, rather than in no
     section or in another, as a protector or a crafted entry lands; a thread state that is not the architecture's,
     which the kernel refuses; `LC_UNIXTHREAD` alone in an arm64 executable, which dyld takes no entry from (it
     halts "main executable has no entry point", where it enters an `x86_64` executable by the command, as a 10.7
     linker wrote it); `x86_64`'s full thread state, which the kernel takes on an Intel Mac and refuses under Rosetta;
     or neither command.
     */
    private func entryAnomalies() -> [String] {
        let image = self.image
        guard image.filetype == UInt32(MH_EXECUTE) else {
            return []
        }
        var found: [String] = []
        let main = image.findCommand(LC_MAIN)
        let thread = image.findCommand(UInt32(LC_UNIXTHREAD))
        if let entry = main?.payload(as: entry_point_command.self), let text = self.segments.first(where: { $0.name == "__TEXT" }) {
            found += self.entryAnomalies("LC_MAIN's entry", at: text.vmaddr &+ image.sw(entry.entryoff))
        }
        if let thread {
            switch self.threadEntry(thread) {
            case let .address(address, states, first, translated):
                if states > 1 {
                    found.append("LC_UNIXTHREAD holds \(states) thread states: the kernel enters by the last, dyld reads the first")
                }
                if let dyld = Self.threadStates(for: image.cpuType)?.first, first.flavor != dyld.flavor || first.count != dyld.count {
                    found.append("LC_UNIXTHREAD's first thread state, flavor \(first.flavor) of \(String(Int(first.count), pluralizing: "word")), is not the one dyld reads, flavor \(dyld.flavor) of \(dyld.count): the kernel enters by it, dyld finds no entry")
                }
                if let translated {
                    found.append("LC_UNIXTHREAD holds a thread state, flavor \(translated.flavor) of \(String(Int(translated.count), pluralizing: "word")), which the kernel takes on an Intel Mac and refuses under Rosetta")
                }
                if main == nil, [CPU_TYPE_ARM64, CPU_TYPE_ARM64_32].contains(image.cpuType) {
                    found.append("LC_UNIXTHREAD alone enters an arm64 executable, which dyld takes no entry from")
                }
                found += self.entryAnomalies("LC_UNIXTHREAD's pc", at: address)
            case let .flavor(flavor, count):
                found.append("LC_UNIXTHREAD's thread state, flavor \(flavor) of \(String(Int(count), pluralizing: "word")), is not \(Universal.archName(cpuType: image.cpuType, cpuSubtype: image.cpuSubtype))'s")
            case .short:
                found.append("LC_UNIXTHREAD is too short for its thread state")
            case nil:
                break
            }
        }
        if main == nil, thread == nil {
            found.append("no LC_MAIN nor LC_UNIXTHREAD for an executable")
        }
        return found
    }

    /// Where `address`, the entry `what` sets, lands: in no segment, in one that is not executable, outside `__TEXT`,
    /// in no section of it, or in a section other than `__text`.
    private func entryAnomalies(_ what: String, at address: UInt64) -> [String] {
        guard let segment = self.segments.first(where: { $0.vmsize > 0 && $0.vmaddr <= address && address < $0.vmend }) else {
            return ["\(what) \(address.hex) lies in no segment"]
        }
        guard segment.isExecutable else {
            return ["\(what) \(address.hex) lies in \(segment.name), which is not executable"]
        }
        guard segment.name == "__TEXT" else {
            return ["\(what) \(address.hex) lies in \(segment.name), not __TEXT"]
        }
        guard !segment.sections.isEmpty else {
            return []
        }
        guard let section = segment.sections.first(where: { $0.addr <= address && address < $0.addr &+ $0.size }) else {
            return ["\(what) \(address.hex) lies in no section of __TEXT"]
        }
        if !section.holdsEntries {
            return ["\(what) \(address.hex) lies in __TEXT,\(section.name), not __text"]
        }
        return []
    }

    private enum ThreadEntry {
        /// The pc, how many thread states the command holds, the first one, and a state the kernel refuses for a
        /// translated process, if one is held.
        case address(UInt64, states: Int, first: ThreadState, translated: ThreadState?)
        case flavor(UInt32, UInt32)
        case short
    }

    /// A thread state as `LC_UNIXTHREAD` holds it: its flavor and its count of words.
    private struct ThreadState {
        let flavor: UInt32
        let count: UInt32
    }

    /// A thread state the kernel's `thread_entrypoint` takes: its flavor and count, the index of the pc among the
    /// registers, and whether the kernel on Apple silicon takes it for a translated process too.
    private struct ThreadStateKind {
        let flavor: UInt32
        let count: UInt32
        let index: Int
        let translated: Bool
    }

    /// The thread states the kernel's `thread_entrypoint` takes for `cpuType`, each a flavor, a count of words, the
    /// index of the pc among the registers and whether the kernel on Apple silicon takes it for a translated
    /// process too (its `load_unixthread` refuses every `x86_64` state but the thread state, and reads no entry
    /// from it, which Rosetta's runtime finds); the first the one dyld's `entryAddrFromThreadCmd` reads; nil for
    /// an architecture neither knows.
    private static func threadStates(for cpuType: cpu_type_t) -> [ThreadStateKind]? {
        switch cpuType {
        case CPU_TYPE_I386: [ThreadStateKind(flavor: 1, count: 16, index: 10, translated: true)] // x86_THREAD_STATE32, eip
        case CPU_TYPE_X86_64: [ThreadStateKind(flavor: 4, count: 42, index: 16, translated: true), ThreadStateKind(flavor: 23, count: 50, index: 16, translated: false)] // x86_THREAD_STATE64 and x86_THREAD_FULL_STATE64, rip
        case CPU_TYPE_ARM: [ThreadStateKind(flavor: 1, count: 17, index: 15, translated: true)] // ARM_THREAD_STATE, pc
        case CPU_TYPE_ARM64, CPU_TYPE_ARM64_32: [ThreadStateKind(flavor: 6, count: 68, index: 32, translated: true)] // ARM_THREAD_STATE64, pc
        default: nil
        }
    }

    /**
     The entry `LC_UNIXTHREAD` sets, as the kernel's `load_threadentry` reads it: every thread state in the command,
     a flavor and a count of words then the registers, each a flavor and count the architecture's `thread_entrypoint`
     takes, the last one's pc the entry; any other flavor, a float state say, fails the load. x86_64 takes its thread
     state and its full one (`x86_THREAD_FULL_STATE64`, the segment registers after the others), the pc at the same
     register of both. dyld's `entryAddrFromThreadCmd` reads the first state alone, and takes the architecture's
     own flavor and count for it, `x86_64`'s thread state and not its full one: a command whose first state is
     another is one dyld finds no entry in. Nil for an architecture neither knows.
     */
    private func threadEntry(_ command: MachO.LoadCommand) -> ThreadEntry? {
        let image = self.image
        guard let states = Self.threadStates(for: image.cpuType) else {
            return nil
        }
        let wide = image.is64 || image.cpuType == CPU_TYPE_ARM64_32
        let data = command.data
        var address: UInt64?
        var first: ThreadState?
        var translated: ThreadState?
        var held = 0
        var at = 8
        while at < data.count {
            guard data.count >= at + 8 else {
                return .short
            }
            let flavor = image.sw(data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: at, as: UInt32.self) })
            let count = image.sw(data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: at + 4, as: UInt32.self) })
            guard let state = states.first(where: { $0.flavor == flavor && $0.count == count }) else {
                return .flavor(flavor, count)
            }
            if first == nil {
                first = ThreadState(flavor: flavor, count: count)
            }
            if !state.translated, translated == nil {
                translated = ThreadState(flavor: flavor, count: count)
            }
            let registers = at + 8
            let pc = registers + state.index * (wide ? 8 : 4)
            guard data.count >= registers + Int(count) * 4, data.count >= pc + (wide ? 8 : 4) else {
                return .short
            }
            address = data.withUnsafeBytes { raw in
                wide ? image.sw(raw.loadUnaligned(fromByteOffset: pc, as: UInt64.self)) : UInt64(image.sw(raw.loadUnaligned(fromByteOffset: pc, as: UInt32.self)))
            }
            held += 1
            at = registers + Int(count) * 4
        }
        guard let address, let first else {
            return .short
        }
        return .address(address, states: held, first: first, translated: translated)
    }

    // MARK: - What the image links

    /// The commands that carry a path or a name as an `lc_str`, 8 bytes in.
    private static let stringCommands: [UInt32] = [
        LC_ID_DYLIB, LC_LOAD_DYLIB, LC_LAZY_LOAD_DYLIB, LC_LOAD_DYLINKER, LC_ID_DYLINKER, LC_DYLD_ENVIRONMENT,
        LC_SUB_FRAMEWORK, LC_SUB_UMBRELLA, LC_SUB_CLIENT, LC_SUB_LIBRARY,
    ].map { UInt32(bitPattern: $0) } + [LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB, LC_LOAD_UPWARD_DYLIB, LC_RPATH]

    private static let dylibCommands: [UInt32] = [LC_LOAD_DYLIB, LC_LAZY_LOAD_DYLIB].map { UInt32(bitPattern: $0) } + [LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB, LC_LOAD_UPWARD_DYLIB]

    /**
     What dyld's `validEmbeddedPaths` and `validLinkedit` and the kernel's `parse_machfile` and `load_dylinker` want of
     an image's commands and flags: every name terminated inside its command; a dylinker, which must be `/usr/lib/dyld`
     on a release kernel; `LC_DYLD_ENVIRONMENT`, which dyld honors; an `LC_UUID`; a dylib's `LC_ID_DYLIB` and no
     other's; at least one dylib linked; an executable dynamically linked, or static, which the kernel runs only as
     x86_64, and position independent, which the kernel requires of arm64; an executable stack; a flat namespace;
     encryption, as the kernel's `set_code_unprotect` takes it; and a version command.
     */
    private func linkAnomalies() -> [String] {
        let image = self.image
        var found: [String] = []
        var installName: String?
        var dylibs = 0
        for command in self.commands where Self.stringCommands.contains(command.cmd) {
            // The fixed fields the name must start past: a dylib command's 24 bytes, the others' 12.
            let fixed = Self.dylibCommands.contains(command.cmd) || command.cmd == UInt32(LC_ID_DYLIB) ? MemoryLayout<dylib_command>.size : MemoryLayout<dylinker_command>.size
            guard let string = command.string(swap: image.swap, fixed: fixed) else {
                if let offset = command.stringOffset(swap: image.swap), offset < fixed {
                    found.append("\(command.name)'s name starts \(offset.hex) bytes in, inside the command's \(fixed.hex) fixed bytes, which dyld refuses")
                } else {
                    found.append("\(command.name)'s name is not terminated inside the command")
                }
                continue
            }
            switch command.cmd {
            case UInt32(LC_LOAD_DYLINKER) where string != "/usr/lib/dyld":
                found.append("LC_LOAD_DYLINKER names \(Self.shown(string)), not /usr/lib/dyld")
            case UInt32(LC_DYLD_ENVIRONMENT):
                // Apple's own set DYLD_DLSYM_RESULT to thousands of bytes; a library's path fits.
                found.append("LC_DYLD_ENVIRONMENT sets \(string.utf8.count > 128 ? "\(Self.shown(String(String.UnicodeScalarView(string.unicodeScalars.prefix(80)))))… (\(String(string.utf8.count, pluralizing: "byte")))" : Self.shown(string))")
            case UInt32(LC_ID_DYLIB):
                installName = string
            case let cmd where Self.dylibCommands.contains(cmd):
                dylibs += 1
            default:
                break
            }
        }

        let dynamic = image.flags & UInt32(MH_DYLDLINK) != 0
        if self.isLoadable {
            if image.findCommand(UInt32(LC_UUID)) == nil {
                found.append("no LC_UUID")
            }
            if image.filetype == UInt32(MH_DYLIB), installName == nil {
                found.append("no LC_ID_DYLIB for a dylib")
            }
            if image.filetype != UInt32(MH_DYLIB), let installName {
                found.append("LC_ID_DYLIB \(Self.shown(installName)) in an \(image.filetypeName)")
            }
            // Only libSystem's own libraries link nothing: they are the bottom.
            if dylibs == 0, image.filetype != UInt32(MH_DYLINKER), image.filetype != UInt32(MH_EXECUTE) || dynamic, !(installName?.hasPrefix("/usr/lib/system/") ?? false) {
                found.append("links no dylib")
            }
            if dynamic, image.flags & UInt32(MH_TWOLEVEL) == 0 {
                found.append("flat namespace: no MH_TWOLEVEL")
            }
        }
        if image.filetype == UInt32(MH_EXECUTE) {
            if dynamic {
                if image.findCommand(UInt32(LC_LOAD_DYLINKER)) == nil {
                    found.append("no LC_LOAD_DYLINKER for a dynamically linked executable")
                }
                if image.flags & UInt32(MH_PIE) == 0 {
                    let required = image.cpuType == CPU_TYPE_ARM64 || (image.cpuType == CPU_TYPE_ARM && image.cpuSubtype & ~cpu_subtype_t(bitPattern: CPU_SUBTYPE_MASK) == CPU_SUBTYPE_ARM_V7K)
                    found.append(required ? "no MH_PIE on an \(Universal.archName(cpuType: image.cpuType, cpuSubtype: image.cpuSubtype)) executable, which the kernel refuses" : "no MH_PIE: loaded without ASLR")
                }
            } else {
                found.append("no MH_DYLDLINK: a static executable" + (image.cpuType == CPU_TYPE_X86_64 ? "" : ", which the kernel runs only as x86_64"))
            }
            if image.flags & UInt32(MH_ALLOW_STACK_EXECUTION) != 0 {
                found.append("MH_ALLOW_STACK_EXECUTION: an executable stack")
            }
        }

        // The kernel's set_code_unprotect: cryptid 0 is an empty command; 1 names its FairPlay crypter, com.apple.unfree,
        // and 0x10 its null one, com.apple.null, any other is LOAD_BADMACHO; a cryptsize of 0 it logs and ignores; the
        // range must lie inside one segment's file bytes, LC_SEGMENT or LC_SEGMENT_64 whatever the image, or
        // LOAD_BADMACHO, a rule it reaches once the crypter has the keys, so a crafted file dies for the keys first.
        for command in self.commands {
            let wide = command.cmd == UInt32(LC_ENCRYPTION_INFO_64)
            guard wide || command.cmd == UInt32(LC_ENCRYPTION_INFO), let info = command.payload(as: encryption_info_command.self) else {
                continue
            }
            if wide != image.is64 {
                found.append("\(command.name) in a \(image.is64 ? 64 : 32)-bit image")
            }
            let cryptid = image.sw(info.cryptid)
            let offset = UInt64(image.sw(info.cryptoff))
            let size = UInt64(image.sw(info.cryptsize))
            guard cryptid != 0 else {
                continue
            }
            let crypter = cryptid == 0x10 ? "cryptid 0x10, the kernel's null crypter com.apple.null," : "cryptid \(cryptid)"
            var line = "encrypted: \(crypter) over \(size.hex) bytes at \(offset.hex)"
            if cryptid != 1, cryptid != 0x10 {
                line += ", which the kernel refuses: 1 names its FairPlay crypter, 0x10 its null one"
            } else if size == 0 {
                line += ", which the kernel ignores"
            } else if !self.segments.contains(where: { $0.fileoff <= offset && offset + size <= $0.fileend }) {
                line += ", which no one segment's file bytes hold: the kernel refuses it"
            }
            found.append(line)
        }
        // A version command too short to read is named by the table rules, not as none.
        if !self.commands.contains(where: { $0.cmd == UInt32(LC_BUILD_VERSION) || Self.versionMinCommands.contains($0.cmd) }) {
            found.append("no LC_BUILD_VERSION nor LC_VERSION_MIN_* dates it")
        }
        return found
    }

    // MARK: - Extent, residue, packer

    /**
     What this tool's other flags undo: bytes appended past the image's end, a `__LINKEDIT` vmsize a signature rounded
     on an image that has none, and UPX, packed as is, by a modified UPX, or signed after packing.
     */
    private func extentAnomalies() -> [String] {
        let image = self.image
        var found: [String] = []
        let end = image.logicalEnd()
        if end < image.length {
            found.append("\((image.length - end).hex) bytes appended past the image's end at \(end.hex)")
        }
        // Security's validateStructure ends the image at the first __LINKEDIT or LC_SYMTAB it meets, and an image with
        // neither is "invalid structure" to it, which codesign's strict validation, its default, refuses.
        if !image.loadCommands.contains(where: { $0.isSegment(named: "__LINKEDIT") || $0.cmd == UInt32(LC_SYMTAB) }) {
            found.append("neither a __LINKEDIT segment nor an LC_SYMTAB ends the image, which codesign's strict validation refuses")
        }

        // codesign rounds __LINKEDIT's vmsize up to 16 KiB when it signs, and leaves it so when it removes the
        // signature, where ld64 and strip round it as `linkeditSizeRounding` says: more than that, on an image without a
        // signature, is a signature's residue. Nothing is said where the rounding cannot be told, of a stripped image
        // that records no linker, whose strip may have rounded to 16 KiB itself.
        if image.findCommand(UInt32(LC_CODE_SIGNATURE)) == nil, let linkedit = self.segments.last(where: { $0.name == "__LINKEDIT" }), linkedit.filesize > 0, let rounding = image.linkeditSizeRounding.map(UInt64.init) {
            let expected = (linkedit.filesize + rounding - 1) & ~(rounding - 1)
            if linkedit.vmsize % 0x4000 == 0, linkedit.vmsize > expected {
                found.append("__LINKEDIT's vmsize \(linkedit.vmsize.hex) is a signature's 16 KiB rounding on an image without one: a signature came out")
            }
        }

        // UPX: as it is, or behind a signature added after packing, which hides the 16-byte __LINKEDIT UPX left,
        // with or without bytes appended after signing; a pack header found that does not hold, or none before the
        // 16-byte __LINKEDIT UPX writes, is named, as unpack refuses it, behind the signature too, where unpack looks
        // for it as well.
        switch Result(catching: { try PackMach(image) }) {
        case let .success(packed?):
            found.append(packed.packer)
            found += Self.sizeClaim(packed)
        case .success(nil):
            if image.findCommand(UInt32(LC_CODE_SIGNATURE)) != nil, let pieces = try? MachOEditor.unsigned(image, end: end), let unsigned = try? MachO(File(editing: self.file, pieces: pieces)) {
                switch Result(catching: { try PackMach(unsigned) }) {
                case let .success(packed?):
                    found.append("\(packed.packer), signed after packing")
                    found += Self.sizeClaim(packed)
                case .success(nil):
                    break
                case let .failure(error):
                    found.append("\(File.message(for: error)), signed after packing, which unpack refuses")
                }
            }
        case let .failure(error):
            found.append("\(File.message(for: error)), which unpack refuses")
        }
        return found
    }

    /**
     UPX writes the original's size in its pack header, under the header's checksum, and in the `p_info` before the
     blocks, under nothing, which its stub never reads: the two disagreeing, the file was edited after packing. One
     line, or none.
     */
    private static func sizeClaim(_ packed: PackMach) -> [String] {
        guard let sizes = try? packed.claimedSizes(), sizes.pInfo != sizes.header else {
            return []
        }
        return ["UPX's p_info claims \(sizes.pInfo) bytes for the original where its pack header, under its checksum, says \(sizes.header)"]
    }

    // MARK: - __LINKEDIT

    /// The commands whose tables live in `__LINKEDIT`, as dyld's `isValidLinkeditLayout` lists them.
    private static let linkeditCommands: [UInt32] = [
        LC_SYMTAB,
        LC_DYSYMTAB,
        LC_DYLD_INFO,
        LC_CODE_SIGNATURE,
        LC_SEGMENT_SPLIT_INFO,
        LC_FUNCTION_STARTS,
        LC_DATA_IN_CODE,
        LC_DYLIB_CODE_SIGN_DRS,
        LC_LINKER_OPTIMIZATION_HINT,
        LC_ATOM_INFO,
        LC_FUNCTION_VARIANTS,
        LC_FUNCTION_VARIANT_FIXUPS,
        LC_LAZY_LOAD_DYLIB_INFO,
    ].map { UInt32(bitPattern: $0) } + [
        LC_DYLD_INFO_ONLY,
        LC_DYLD_EXPORTS_TRIE,
        LC_DYLD_CHAINED_FIXUPS,
    ]

    /**
     The tables as dyld's `isValidLinkeditLayout` lays them: each inside `__LINKEDIT`, the last of that name as dyld
     takes it, so a decoy before it silences nothing, none overlapping another; and the bytes of `__LINKEDIT` no table
     references, which the linker and codesign leave as zeros: a payload otherwise, signed over when the image was
     signed after.
     */
    private func linkeditAnomalies() -> [String] {
        let image = self.image
        guard let linkedit = self.segments.last(where: { $0.name == "__LINKEDIT" }), linkedit.filesize > 0 else {
            return []
        }
        var found: [String] = []
        let tables = self.commands.filter { Self.linkeditCommands.contains($0.cmd) }.flatMap { image.fileRanges(of: $0) ?? [] }.filter { $0.size > 0 }
        var inside: [MachO.FileRange] = []
        for table in tables {
            let end = table.offset.addingReportingOverflow(table.size)
            if end.overflow || table.offset < linkedit.fileoff || end.partialValue > linkedit.fileend {
                found.append("the \(table.name) at \(table.offset.hex) with size \(table.size.hex) lies outside __LINKEDIT")
            } else {
                inside.append(table)
            }
        }
        inside.sort { $0.offset < $1.offset }
        for (before, after) in zip(inside, inside.dropFirst()) where after.offset < before.offset + before.size {
            found.append("the \(before.name) and the \(after.name) overlap in __LINKEDIT")
        }

        var gaps: [Range<Int>] = []
        var cursor = linkedit.fileoff
        for table in inside {
            if table.offset > cursor {
                gaps.append(Int(cursor) ..< Int(table.offset))
            }
            cursor = max(cursor, table.offset + table.size)
        }
        if linkedit.fileend > cursor {
            gaps.append(Int(cursor) ..< Int(linkedit.fileend))
        }
        if let nonZero = self.nonZero(in: gaps) {
            found.append("\(nonZero.count.hex) bytes of __LINKEDIT that no table references are not zero, the first at \(nonZero.first.hex)")
        }
        return found
    }

    /// How many bytes of `ranges` of the image are not zero, and where the first is: `File.nonZero(in:)` of the image.
    private func nonZero(in ranges: [Range<Int>]) -> File.NonZero? {
        let offset = self.image.offset
        return self.file.nonZero(in: ranges.map { $0.lowerBound + offset ..< $0.upperBound + offset }).map { File.NonZero(count: $0.count, first: $0.first - offset) }
    }

    /// A blob the special slots seal: its slot, what it is called, and the blob the signature holds, if it does.
    private struct Sealed {
        let slot: UInt32
        let what: String
        let bytes: MachO.Sealable
    }

    /// The name a line gives to what each special slot seals, for the slots Security visits.
    private static let sealedNames: [UInt32: String] = [
        2: "the requirements blob",
        4: "the top directory",
        5: "the entitlements blob",
        6: "the blob the file's kind keeps at slot 6",
        7: "the DER entitlements blob",
        8: "the launch constraint on the process",
        9: "the launch constraint on its parent",
        10: "the launch constraint on its responsible process",
        11: "the library constraint",
    ]

    /// The slices of one architecture, by its name, as the kernel compares entries: how many there are.
    private struct Counted {
        let name: String
        var count: Int
    }

    /// A segment's bytes no section covers: its name, and the gaps, each a range of the image.
    private struct Uncovered {
        let name: String
        let gaps: [Range<Int>]
    }

    /// The bytes between one segment's content and the next's: their names, and the gap, a range of the image.
    private struct Between {
        let before: String
        let after: String
        let gap: Range<Int>
    }

    /// The segment reaching furthest into the file so far, by name, and where it ends.
    private struct Furthest {
        let name: String
        let end: UInt64
    }

    // MARK: - Padding

    /**
     The bytes of a segment no section covers, past the header and load commands, and the bytes between one segment's
     content and the next's: page padding the linker writes as zeros, which no loader reads and codesign signs over. A
     gap shorter than the alignment of the section that follows is that section's alignment padding, which an older
     ld64 fills with no-ops on `x86_64`, so it is not looked at. The gaps are read once each: a crafted table lays
     thousands of segments over the same bytes, and reading each segment's gaps on its own would read the file as
     many times. The bytes between segments are taken from the furthest end so far, so that a segment laid inside
     another names none of the outer one's content as lying between them.
     */
    private func paddingAnomalies() -> [String] {
        let image = self.image
        var found: [String] = []
        let headerEnd = UInt64(image.headerSize + image.sizeofcmds)
        var uncovered: [Uncovered] = []
        for segment in self.segments where segment.filesize > 0 && segment.name != "__LINKEDIT" && !segment.sections.isEmpty {
            var gaps: [Range<Int>] = []
            var cursor = segment.fileoff == 0 ? min(headerEnd, segment.fileend) : segment.fileoff
            for section in segment.sections.filter(\.hasContent).sorted(by: { $0.offset < $1.offset }) {
                let start = min(max(UInt64(section.offset), segment.fileoff), segment.fileend)
                // The linker's padding before a section, up to its alignment, a page at most: the field is the
                // image's own, and a larger one would hide a payload behind it.
                if start > cursor, start - cursor >= 1 << min(section.align, 14) {
                    gaps.append(Int(cursor) ..< Int(start))
                }
                cursor = max(cursor, min(section.fileend, segment.fileend))
            }
            if segment.fileend > cursor {
                gaps.append(Int(cursor) ..< Int(segment.fileend))
            }
            uncovered.append(Uncovered(name: segment.name, gaps: gaps))
        }

        var between: [Between] = []
        var furthest: Furthest?
        for segment in self.segments.filter({ $0.filesize > 0 }).sorted(by: { $0.fileoff < $1.fileoff }) {
            if let furthest, segment.fileoff > furthest.end {
                between.append(Between(before: furthest.name, after: segment.name, gap: Int(furthest.end) ..< Int(segment.fileoff)))
            }
            if furthest == nil || segment.fileend > furthest!.end {
                furthest = Furthest(name: segment.name, end: segment.fileend)
            }
        }

        // The gaps may lie over one another: a crafted table lays thousands of them over the same bytes, each to
        // the file's end. So they are cut into pieces at every gap's bounds, and each piece is read once. Sums
        // kept ahead over the pieces then answer a gap by one subtraction, with no walk over its pieces:
        //
        //   pieces   |  p0  |  p1  |  p2  |  p3  |
        //   gap A    |-------------|                  counts[2] - counts[0]
        //   gap B           |--------------------|    counts[4] - counts[1]
        let pieces = Self.pieces(of: uncovered.flatMap(\.gaps) + between.map(\.gap))
        let read = pieces.map { self.nonZero(in: [$0]) }

        // counts[i]: the bytes not zero in the pieces before piece i. The last entry counts them all.
        var counts = [0]
        for nonZero in read {
            counts.append(counts[counts.count - 1] + (nonZero?.count ?? 0))
        }

        // next[i]: the first piece from i on that holds a byte not zero, the count of pieces when none does.
        var next = [Int](repeating: pieces.count, count: pieces.count + 1)
        for index in pieces.indices.reversed() {
            next[index] = read[index] == nil ? next[index + 1] : index
        }

        /// The first piece that starts at `bound` or after it, the count of pieces when none does.
        func piece(at bound: Int) -> Int {
            var (low, high) = (0, pieces.count)
            while low < high {
                let middle = (low + high) / 2
                if pieces[middle].lowerBound < bound {
                    low = middle + 1
                } else {
                    high = middle
                }
            }
            return low
        }

        /// What of `gaps` is not zero, by the pieces read: how many bytes, and the first.
        func nonZero(in gaps: [Range<Int>]) -> File.NonZero? {
            var count = 0
            var first = Int.max
            for gap in gaps {
                let (from, to) = (piece(at: gap.lowerBound), piece(at: gap.upperBound))
                guard from < to else {
                    continue
                }
                count += counts[to] - counts[from]
                if next[from] < to, let nonZero = read[next[from]] {
                    first = min(first, nonZero.first)
                }
            }
            return count > 0 ? File.NonZero(count: count, first: first) : nil
        }
        for segment in uncovered {
            if let nonZero = nonZero(in: segment.gaps) {
                found.append("\(nonZero.count.hex) bytes of \(segment.name) that no section covers are not zero, the first at \(nonZero.first.hex)")
            }
        }
        for pair in between {
            if let nonZero = nonZero(in: [pair.gap]) {
                found.append("\(nonZero.count.hex) bytes between \(pair.before) and \(pair.after) are not zero, the first at \(nonZero.first.hex)")
            }
        }
        return found
    }

    /// `ranges` cut at every bound of every range into pieces that overlap none, in order, each inside at least one.
    private static func pieces(of ranges: [Range<Int>]) -> [Range<Int>] {
        let bounds = Set(ranges.flatMap { [$0.lowerBound, $0.upperBound] }).sorted()
        var opens: [Int: Int] = [:]
        for range in ranges where !range.isEmpty {
            opens[range.lowerBound, default: 0] += 1
            opens[range.upperBound, default: 0] -= 1
        }
        var pieces: [Range<Int>] = []
        var covering = 0
        for (bound, next) in zip(bounds, bounds.dropFirst()) {
            covering += opens[bound, default: 0]
            if covering > 0 {
                pieces.append(bound ..< next)
            }
        }
        return pieces
    }

    // MARK: - Signature

    /// `CS_ENFORCE_EXPIRATION` (`codesign -o expires`): an expired signer refused, where Security tolerates one otherwise.
    private static let csEnforceExpiration: UInt32 = 0x400

    /// The entitlements that opt out of the hardened runtime's protections, or let another process in.
    private static let weakeningEntitlements = [
        "com.apple.security.cs.allow-unsigned-executable-memory",
        "com.apple.security.cs.allow-jit",
        "com.apple.security.cs.allow-dyld-environment-variables",
        "com.apple.security.cs.disable-library-validation",
        "com.apple.security.cs.disable-executable-page-protection",
        "com.apple.security.cs.debugger",
        "com.apple.security.get-task-allow",
    ]

    /**
     The signature as Security verifies it and the kernel takes it. Named:

     - an arm64 image without a signature, which the kernel does not run;
     - a signature Security loads no code directory from;
     - for each directory: the first page of code that does not hash to it (`validateExecutable`); a code limit
       short of the signature's offset, which leaves the pages before it unsigned (the kernel's `csb_end_offset`),
       or past it; a scatter vector, which Security does not read; a page size the kernel refuses;
     - no CMS blob behind a directory not flagged ad hoc;
     - a special slot that does not seal the blob it should: the requirements, the top directory, the entitlements
       and their DER form, the launch and library constraints. The kernel checks the entitlements' slots, Security
       all of them, by its best directory;
     - entitlements that opt out of hardening;
     - who signed, as `Signer` has it: a CMS blob that does not verify over the directory, a chain that ends
       outside Apple's roots, which codesign and the kernel take and Gatekeeper refuses, a development or
       submission certificate, a Developer ID signature old enough to run without a ticket, a team identifier the
       developer's certificate does not bear, a CMS blob Security ignores behind an ad-hoc directory, and
       entitlements AMFI reserves to Apple's own signature.

     The Info.plist slot is not checked: for a bundle's executable it seals the bundle's Info.plist, not the
     section's.

     Bytes past the superblob inside `LC_CODE_SIGNATURE`'s range are not named: Apple's own arm64e slices keep a stale
     signature's hashes there, where the x86_64 slice's larger signature sized the range. Nor are an ad-hoc or a
     linker-signed signature, which every arm64 build has.

     Throws what `signingData` refuses: a superblob Security cannot read.
     */
    private func signatureAnomalies() throws -> [String] {
        let image = self.image
        guard MachO.codeFiletypes.contains(image.filetype) else {
            return []
        }
        guard let signature = try image.findCodeSignature() else {
            return [CPU_TYPE_ARM64, CPU_TYPE_ARM64_32].contains(image.cpuType) ? ["not signed, which the kernel refuses to run as \(Universal.archName(cpuType: image.cpuType, cpuSubtype: image.cpuSubtype))"] : []
        }
        var found: [String] = []
        let superblob = try image.signingData(signature)
        let directories = try MachO.loadCodeDirectories(superblob)
        guard let primary = directories.first else {
            return found + ["a signature Security loads no code directory from"]
        }
        // Security verifies the CMS blob over the first directory, slot 0, and reads the flags and the team from the
        // best of them, the kernel's choice too (`SecStaticCode::codeDirectory`, `bestHashOf`).
        let best = directories.max { $0.hashType.rank < $1.hashType.rank } ?? primary

        // Security cuts every directory's pages by one directory's code limit and page size, the lowest hash type's;
        // the kernel cuts by the directory it ranks first, with that one's own.
        let geometry = MachO.geometry(of: directories) ?? primary
        for (directory, checked) in try zip(directories, image.validateExecutables(directories)) {
            let type = "the \(directory.hashType.name) code directory"
            if let slot = checked.failedSlot {
                found.append("page \(slot) of the code does not hash to \(type)")
            } else if !checked.valid {
                found.append("\(type) covers \(directory.codeLimit.hex) bytes, past the image's \(image.length.hex)")
            }
            if directory.hashType != geometry.hashType, directory.pageSize != geometry.pageSize || directory.codeLimit != geometry.codeLimit {
                found.append("\(type) cuts \(directory.codeLimit.hex) bytes of code into pages of \(directory.pageSize.hex), where the \(geometry.hashType.name) code directory cuts \(geometry.codeLimit.hex) into \(geometry.pageSize.hex): Security checks every directory by the latter, the kernel by the directory it ranks first")
            }
            // Strict validation wants the code limit at the signature exactly (`SingleDiskRep::strictValidate`),
            // in the directory Security judges by, the best. It does not read an alternate's limit.
            let judged = directory.hashType == best.hashType
            if directory.codeLimit < UInt64(signature.offset) {
                found.append("\(type) covers \(directory.codeLimit.hex) bytes, \((UInt64(signature.offset) - directory.codeLimit).hex) short of the signature at \(signature.offset.hex): the rest is unsigned" + (judged ? ", and strict validation refuses the signature" : ""))
            } else if checked.valid, directory.codeLimit > UInt64(signature.offset) {
                found.append("\(type) covers \(directory.codeLimit.hex) bytes, past the signature at \(signature.offset.hex)" + (judged ? ", which strict validation refuses the signature for" : ""))
            }
            if directory.scattered {
                found.append("\(type) is scattered, which Security does not read: its slots are checked in order")
            }
            if ![12, 14].contains(directory.pageSizeLog) {
                found.append("\(type)'s page size, 2^\(directory.pageSizeLog), is neither the 4 KiB nor the 16 KiB the kernel takes")
            }
            // Security ranks SHA-512 first and reads the signature by it; the kernel knows no such hash type and
            // refuses the signature whole (`cs_validate_codedirectory`).
            if directory.hashType == .sha512 {
                found.append("\(type) is of a hash type the kernel does not know: Security reads the signature by it, the kernel refuses the signature")
            }
        }

        found += Self.kernelIndexAnomalies(of: superblob)

        // The special slots Security visits, up to the library constraint's (`validateNonResourceComponents`), each
        // with the bytes it seals: the whole blob, or the bytes under its wrapper (`MachO.sealable`). Security
        // reads the seals of the directory it judges by, the best. The kernel reads the entitlements' seals, in
        // the directory it ranks first.
        let sealed = (1 ... MachO.csslotMax).filter { !MachO.csslotsLeftOut.contains($0) }.map { Sealed(slot: $0, what: Self.sealedNames[$0] ?? "the blob of slot \($0)", bytes: MachO.sealable($0, in: superblob)) }

        // A blob that should lie under a wrapper and does not is refused where Security fetches it: for a slot
        // the best directory has, and for the top directory whether the directory has its slot or not.
        for seal in sealed where seal.slot == MachO.csslotTopDirectory || Int(seal.slot) <= best.nSpecialSlots {
            if case .unwrapped = seal.bytes {
                found.append("\(seal.what) does not lie under a wrapper, which Security refuses the signature for")
            }
        }

        for directory in directories {
            let type = "the \(directory.hashType.name) code directory"
            let unread = directory.hashType == best.hashType ? "" : ", which Security does not read: it judges the signature by the \(best.hashType.name) one"
            for seal in sealed {
                let hash = directory.specialSlot(Int(seal.slot))
                let zero = hash?.allSatisfy { $0 == 0 } ?? true
                switch seal.bytes {
                case let .bytes(bytes):
                    // A slot the signer left empty seals nothing, which the kernel refuses of entitlements.
                    if zero {
                        found.append("\(seal.what) is not sealed by \(type)")
                    } else if directory.hashType.digest(bytes).prefix(directory.hashType.slotSize) != hash {
                        found.append("\(seal.what) does not hash to its slot in \(type)" + unread)
                    }
                case .none:
                    if !zero {
                        found.append("\(type) seals \(seal.what), which the signature does not hold" + unread)
                    }
                case .unwrapped:
                    break
                }
            }
        }

        // The entitlements: the XML plist, and its DER form, which codesign writes beside it since macOS 12 and
        // which AMFI and the kernel read where it is. The verdicts below are read from the DER form when there is one.
        // The kernel's cs_validate_csblob takes each under its magic alone, 0xfade7171 and 0xfade7172, and refuses
        // the signature whole otherwise: what such a blob says is granted to nothing.
        var entitled: [String: Any]?
        var refusedBlob = false
        if let entitlements = MachO.component(MachO.csslotEntitlements, of: superblob) {
            if let magic = Self.magic(of: entitlements), magic != 0xfade_7171 {
                found.append("the entitlements blob's magic is \(magic.hex), not 0xfade7171, which the kernel refuses the signature for; codesign warns of an invalid entitlements blob")
                refusedBlob = true
            } else if let plist = try? PropertyListSerialization.propertyList(from: Data(entitlements.dropFirst(8)), format: nil) as? [String: Any] {
                entitled = plist
            } else {
                found.append("entitlements that do not parse as a plist")
            }
        }
        if let der = MachO.component(MachO.csslotDEREntitlements, of: superblob) {
            if let magic = Self.magic(of: der), magic != 0xfade_7172 {
                found.append("the DER entitlements blob's magic is \(magic.hex), not 0xfade7172, which the kernel refuses the signature for")
                refusedBlob = true
            } else {
                do {
                    let decoded = try DEREntitlements.decode(Data(der.dropFirst(8)))
                    if let plist = entitled {
                        let differing = Set(plist.keys).union(decoded.keys).filter { !Self.equal(plist[$0], decoded[$0]) }
                        if !differing.isEmpty {
                            found.append("the entitlements and their DER form, which AMFI reads, disagree on \(differing.sorted().map(Self.shown).joined(separator: ", "))")
                        }
                    }
                    entitled = decoded
                } catch {
                    found.append("DER entitlements holding \(error.what), which AMFI refuses the code for")
                    refusedBlob = true
                }
            }
        }
        if refusedBlob {
            entitled = nil
        }
        if let entitled {
            let weakening = Self.weakeningEntitlements.filter { (entitled[$0] as? Bool) == true }
            if !weakening.isEmpty {
                found.append("entitled to opt out of hardening: \(weakening.joined(separator: ", "))")
            }
        }

        // The CMS blob, past its 8-byte header, which Security takes under its magic alone (`EmbeddedSignatureBlob`,
        // errSecCSSignatureInvalid otherwise), and reads only behind a directory not flagged ad hoc.
        // codesign writes an empty wrapper, its header alone, behind an ad-hoc signature.
        let signatureBlob = MachO.component(MachO.csslotSignature, of: superblob)
        let wrapped = signatureBlob.flatMap { $0.count > 8 ? $0 : nil }
        var cms = Data()
        // The magic is checked of a wrapper that is its header alone too, as codesign leaves it behind an ad-hoc
        // signature.
        if let signatureBlob, let magic = Self.magic(of: signatureBlob), magic != 0xfade_0b01 {
            found.append("the CMS blob's magic is \(magic.hex), not 0xfade0b01, which Security refuses the signature for")
        } else if let wrapped {
            cms = Data(wrapped.dropFirst(8))
        }
        if best.flags & MachO.csAdhoc != 0 {
            if wrapped != nil {
                found.append("a CMS signature behind a code directory flagged ad hoc, which Security ignores")
            }
            found += self.restrictedEntitlements(entitled, signedBy: nil)
        } else if wrapped == nil {
            found.append("no CMS signature behind a code directory not flagged ad hoc")
            found += self.restrictedEntitlements(entitled, signedBy: nil)
        } else if cms.isEmpty {
            found += self.restrictedEntitlements(entitled, signedBy: nil)
        } else {
            found += self.signerAnomalies(cms, over: primary, team: best, among: directories, entitled: entitled)
        }
        return found
    }

    /// The magic a blob of the superblob begins with, big-endian; nil for one too short to hold its header.
    private static func magic(of blob: Data) -> UInt32? {
        blob.count >= 8 ? blob.withUnsafeBytes { UInt32(bigEndian: $0.loadUnaligned(as: UInt32.self)) } : nil
    }

    /// The big-endian word `offset` bytes into `data`, as the signature's blobs lay their fields.
    private static func bigEndian(_ data: Data, at offset: Int) -> UInt32 {
        data.withUnsafeBytes { UInt32(bigEndian: $0.loadUnaligned(fromByteOffset: offset, as: UInt32.self)) }
    }

    /**
     The index as the kernel's `cs_validate_csblob` walks it. Security reads slot 0 and the alternates up to the
     first one missing; the kernel reads every entry, and refuses the signature whole for any of:

     - an entry of a code directory's slot, 0 or 0x1000 to 0x1004, wherever it lies, that fails
       `cs_validate_codedirectory`. The checks made here are those Security does not make: the directory's
       length, its magic, its identifier's offset, its linkage;
     - two entries of an entitlements slot, or of a constraint slot;
     - a constraint under another magic than its own;
     - an entry at offset 0, the superblob's own header.

     A directory past a gap in the alternates is one Security never loads and the kernel ranks with the others.

     Two directories of one hash type. The kernel ranks each directory as it comes (`hash_rank`) and keeps the
     highest as its best so far:

     ```
     rank    1 SHA-1    2 truncated SHA-256    3 SHA-256    4 SHA-384

     a directory that ranks      is
     -------------------------   ----------------------------------------------------------------------
     above the best so far       the new best
     as the best so far          refused: "multiple hash=%d CodeDirectories in signature; rejecting"
     below the best so far       passed over
     ```

     So the second directory of a hash type is refused only while the first is still the best. After a stronger
     one, both are passed over and the signature is taken.
     */
    private static func kernelIndexAnomalies(of superblob: Data) -> [String] {
        var found: [String] = []
        var hashTypes: [UInt8: Int] = [:]
        var entered: [UInt32: Int] = [:]
        // The rank of the directory the kernel holds as its best so far, and the hash types it refuses a second of.
        var best: Int?
        var refused: Set<UInt8> = []
        var mismagicked: Set<UInt32> = []
        // The slots Security loads a directory from: 0, then the alternates up to the first one missing.
        var loaded: Set<UInt32> = [0]
        while MachO.component(0x1000 + UInt32(loaded.count - 1), of: superblob) != nil {
            loaded.insert(0x1000 + UInt32(loaded.count - 1))
        }

        for entry in 0 ..< Int(Self.bigEndian(superblob, at: 8)) {
            let slot = Self.bigEndian(superblob, at: 12 + 8 * entry)
            let offset = Int(Self.bigEndian(superblob, at: 12 + 8 * entry + 4))
            if [MachO.csslotEntitlements, MachO.csslotDEREntitlements].contains(slot) || Self.constraintSlots.contains(slot) {
                entered[slot, default: 0] += 1
            }
            if Self.constraintSlots.contains(slot), offset != 0, Self.bigEndian(superblob, at: offset) != Self.constraintMagic, mismagicked.insert(slot).inserted {
                found.append("the magic of \(Self.sealedNames[slot] ?? "slot \(slot)") is \(Self.bigEndian(superblob, at: offset).hex), not \(Self.constraintMagic.hex), which the kernel refuses the signature for")
            }
            guard slot == 0 || (0x1000 ... 0x1004).contains(slot) else {
                continue
            }
            var name: String {
                "the code directory the index places at slot \(slot.hex)"
            }
            guard offset != 0 else {
                found.append("\(name) at offset 0, the superblob's own header, which the kernel refuses the signature for")
                continue
            }

            // The index was checked as `signingData` checks it: the blob lies inside, header included. The fields
            // the kernel checks lie in the blob's first 0x70 bytes, so those alone are copied out: an index may
            // name one directory of megabytes thousands of times.
            let length = Int(Self.bigEndian(superblob, at: offset + 4))
            let head = Data(superblob.bytes(in: offset ..< offset + min(length, 0x70)))
            if let refusal = Self.kernelRefusal(of: head, length: length) {
                found.append("\(name) is one the kernel refuses the signature for: \(refusal)")
                continue
            }

            hashTypes[head[37], default: 0] += 1
            let rank = Self.kernelRank(head[37])
            if let held = best, rank == held {
                refused.insert(head[37])
            }
            best = max(best ?? rank, rank)
            if !loaded.contains(slot) {
                found.append("\(name) lies past a gap in the alternates: Security never loads it, the kernel validates it and may read the signature by it")
            }
        }

        for (type, count) in hashTypes.sorted(by: { $0.key < $1.key }) where count > 1 {
            found.append("\(count) code directories of hash type \(HashType(rawValue: type)?.name ?? "\(type)") in the index, " + (refused.contains(type) ? "which the kernel refuses the signature for" : "which the kernel takes: a stronger one is entered before the second"))
        }
        for (slot, count) in entered.sorted(by: { $0.key < $1.key }) where count > 1 {
            found.append("\(count) entries for slot \(slot) in the index, which the kernel refuses the signature for")
        }
        return found
    }

    /// The launch and library constraints' slots, and the magic the kernel wants of a blob there
    /// (`CSMAGIC_EMBEDDED_LAUNCH_CONSTRAINT`).
    private static let constraintSlots: Set<UInt32> = [8, 9, 10, 11]
    private static let constraintMagic: UInt32 = 0xfade_8181

    /// The kernel's rank of a hash type (`hash_rank`): higher is better, 0 for one it does not know.
    private static func kernelRank(_ type: UInt8) -> Int {
        switch type {
        case 1: 1 // SHA-1
        case 3: 2 // truncated SHA-256
        case 2: 3 // SHA-256
        case 4: 4 // SHA-384
        default: 0
        }
    }

    /// Why the kernel's `cs_validate_codedirectory` refuses a code directory of `length` bytes, among the checks
    /// Security does not make; nil when it passes them. `blob` is its first 0x70 bytes, or all of a shorter one.
    private static func kernelRefusal(of blob: Data, length: Int) -> String? {
        guard length >= 0x70 else {
            return "it is \(length.hex) bytes, shorter than the 0x70 the kernel reads"
        }
        let magic = Self.bigEndian(blob, at: 0)
        guard magic == 0xfade_0c02 else {
            return "its magic is \(magic.hex), not 0xfade0c02"
        }
        let identOffset = Self.bigEndian(blob, at: 20)
        guard identOffset != 0, Int(identOffset) < length else {
            return identOffset == 0 ? "its identifier offset is 0" : "its identifier offset \(identOffset.hex) is past its end"
        }
        if Self.bigEndian(blob, at: 8) > 0x205ff, blob[0x60] != 0 {
            let (linkageOffset, linkageSize) = (Self.bigEndian(blob, at: 0x64), Self.bigEndian(blob, at: 0x68))
            if UInt64(linkageOffset) + UInt64(linkageSize) > UInt64(length) {
                return "its linkage at \(linkageOffset.hex) with size \(linkageSize.hex) lies past its end"
            }
        }
        return nil
    }

    /// Whether two entitlement values are one, compared as the property list classes compare them.
    private static func equal(_ lhs: Any?, _ rhs: Any?) -> Bool {
        switch (lhs, rhs) {
        case (nil, nil): true
        case let (lhs?, rhs?): (lhs as AnyObject).isEqual(rhs)
        default: false
        }
    }

    /**
     Who signed, as `Signer` verifies and classes the CMS blob over `primary`, bound to every one of `directories`
     by the signer's hash-agility attributes: what fails to verify, in one line, else
     the chain Gatekeeper refuses or runs without a ticket, and a team identifier in `best`, the directory Security
     reads it from, that the certificate does not bear, which Security refuses (`errSecCSBadTeamIdentifier`); then the
     entitlements AMFI reserves, given who signed.
     */
    private func signerAnomalies(_ cms: Data, over primary: EmbeddedCodeDirectory, team best: EmbeddedCodeDirectory, among directories: [EmbeddedCodeDirectory], entitled: [String: Any]?) -> [String] {
        let type = "the \(primary.hashType.name) code directory"
        let signer: Signer
        do {
            signer = try Signer(cms: cms, over: primary.data, binding: directories.map { Signer.Binding(hashType: $0.hashType, cdhash: $0.hashType.digest($0.data)) }, best: best.hashType, enforcingExpiration: best.flags & Self.csEnforceExpiration != 0)
        } catch {
            let line = switch error {
            case let .malformed(fault): "a CMS signature that is not DER to its end, \(fault), which Security's decoder would allocate for as it streams"
            case .undecodable: "a CMS signature Security cannot decode"
            case .unsigned: "a CMS signature with no signer"
            case let .signers(count): "a CMS signature with \(count) signers, where Security requires exactly one, an invalid signature to it"
            case .invalidSignature: "the CMS signature does not verify over \(type)"
            case let .chain(reason): "the signer's certificate chain does not build: \(Self.shown(reason))"
            case let .expired(reason): "the signer's certificate chain does not hold at the date it claims: \(Self.shown(reason)), which the code directory's CS_ENFORCE_EXPIRATION flag refuses where Security tolerates it"
            case let .agility(reason): "the CMS signature does not bind the code directories as Security requires: \(reason), an invalid signature to it"
            case .timestampChain: "the secure timestamp's chain ends outside Apple's roots where the signer's ends at one, which Security refuses the signature for"
            }
            return [line] + self.restrictedEntitlements(entitled, signedBy: nil)
        }

        var found: [String] = []
        let summary = Self.shown(signer.summary)
        switch signer.kind {
        case .apple, .appStore:
            break
        case .developerID:
            if signer.isLegacyDeveloperID, let timestamp = signer.timestamp {
                found.append("a Developer ID signature by \(summary) timestamped \(timestamp.formatted(.iso8601.year().month().day())), before notarization: Gatekeeper runs it without a ticket")
            }
        case .development:
            found.append("signed with a development or App Store submission certificate, \(summary), which Gatekeeper refuses")
        case .otherApple:
            found.append("signed with an Apple-issued certificate not for code, \(summary), which AMFI refuses")
        case .outsideApple:
            found.append("signed outside Apple's chains by \(summary), which Gatekeeper refuses")
        }
        // Security checks the team only behind the certificates Apple issues to developers (`isAppleDeveloperCert`).
        if [.developerID, .development].contains(signer.kind), let team = best.teamID, let unit = signer.teamID, team != unit {
            found.append("team identifier \(Self.shown(team)) in the \(best.hashType.name) code directory is not the certificate's \(Self.shown(unit)), which Security refuses")
        }
        return found + self.restrictedEntitlements(entitled, signedBy: signer.kind)
    }

    /**
     The entitlements AMFI lets any signer claim (libmis's `unrestrictedEntitlements` and `softRestrictedEntitlements`
     lists): every other one it validates against `anchor apple`, or the provisioning profile of a bundle signed under
     Apple's developer CAs, and refuses the code otherwise, whatever the kernel would make of it.
     */
    private static let unrestrictedEntitlements = ["com.apple.private.signing-identifier", "com.apple.developer.hardened-process", "com.apple.application-identifier"]
    private static let unrestrictedEntitlementPrefixes = ["com.apple.security.", "com.apple.developer.hardened-process."]

    /**
     The entitlements AMFI reserves among `entitled`: all the restricted ones when no provisioning profile can grant
     them, the signature being ad hoc, absent, failed or outside Apple's chains; under Apple's developer CAs, where a
     profile in the bundle may, only the private ones, which Apple provisions no developer. None under Apple's own
     signature, nor the App Store's: Apple's own apps come through it with private entitlements (Keynote, Final Cut
     Pro, Apple Configurator), provisioned by Apple.
     */
    private func restrictedEntitlements(_ entitled: [String: Any]?, signedBy kind: Signer.Kind?) -> [String] {
        guard let entitled, kind != .apple, kind != .appStore else {
            return []
        }
        var restricted = entitled.keys.filter { key in !Self.unrestrictedEntitlements.contains(key) && !Self.unrestrictedEntitlementPrefixes.contains { key.hasPrefix($0) } }
        if let kind, [.developerID, .development].contains(kind) {
            restricted = restricted.filter { $0.hasPrefix("com.apple.private.") }
        }
        guard !restricted.isEmpty else {
            return []
        }
        return ["entitled to \(restricted.sorted().map(Self.shown).joined(separator: ", ")), which AMFI reserves to Apple-signed code"]
    }

    // MARK: - Universal files

    /**
     What is odd about a universal file itself: one the kernel runs no slice of (`FAT_MAGIC_64`); a slice hidden past
     the table's count, which codesign finds and the kernel does not, and dyld finds when the entry names arm64 with
     no subtype and the table counts fewer than 16 (`forEachSlice`, `Architecture::operator==`); two slices of one
     architecture, which the kernel refuses (`fatfile_validate_fatarches`); slices that overlap; a slice not aligned as its entry declares;
     padding before a slice that is not zero, which Security calls suspicious (`Universal::Universal`); and bytes past
     the last slice.
     */
    static func anomalies(universal file: File, _ table: Universal.Table) -> [String] {
        let (archs, is64) = (table.archs, table.is64)
        var found: [String] = []
        if is64 {
            found.append("a 64-bit universal file, which the kernel does not run and codesign signs as a generic file")
        }
        let counted = archs.filter { !$0.hidden }.count
        for arch in archs where arch.hidden {
            let dyld = arch.cpuSubtype == CPU_SUBTYPE_ARM64_ALL && counted < Universal.maxSliceCount
            found.append("slice \(arch.name) is hidden past the table's \(String(counted, pluralizing: "entry", plural: "entries")): \(dyld ? "dyld and codesign find it, the kernel does not" : "codesign finds it, dyld and the kernel do not")")
        }
        // The kernel compares the entries' cputype and cpusubtype as they are, capability bits included.
        var slices: [String: Counted] = [:]
        for arch in archs {
            slices["\(arch.cpuType),\(arch.cpuSubtype)", default: Counted(name: arch.name, count: 0)].count += 1
        }
        for counted in slices.values.sorted(by: { $0.name < $1.name }) where counted.count > 1 {
            found.append("\(counted.count) slices of \(counted.name), which the kernel refuses")
        }
        let placed = archs.sorted { $0.offset < $1.offset }
        for (before, after) in zip(placed, placed.dropFirst()) where after.offset < before.offset + before.length {
            found.append("slices \(before.name) and \(after.name) overlap")
        }
        for arch in archs where arch.offset % (1 << min(Int(arch.align), 30)) != 0 {
            found.append("slice \(arch.name) at \(arch.offset.hex) is not aligned to the 2^\(arch.align) its entry declares")
        }
        var cursor = MemoryLayout<fat_header>.size + archs.count * (is64 ? MemoryLayout<fat_arch_64>.size : MemoryLayout<fat_arch>.size)
        for arch in placed {
            if arch.offset > cursor, let nonZero = file.nonZero(in: [cursor ..< arch.offset]) {
                found.append("\(nonZero.count.hex) bytes of padding before slice \(arch.name) are not zero, the first at \(nonZero.first.hex)")
            }
            cursor = max(cursor, arch.offset + arch.length)
        }
        if let last = placed.last, last.offset + last.length < file.size {
            found.append("\((file.size - last.offset - last.length).hex) bytes past the last slice, \(last.name)'s end at \((last.offset + last.length).hex)")
        }
        return found
    }

    /**
     What is odd about the image against its entry in a universal file's table, as dyld's `isValidSlice` reads them:
     the entry naming another cputype or cpusubtype than the image's header, and the image off its own page, 16 KiB
     for the arm64 family and armv7k, as `lipo` has it (`uses16KPages`), 4 KiB otherwise. An image no loader maps
     says nothing of its page, as a Metal library packs its GPU slices as it likes; `lipo` asks the page of what dyld
     maps alone, a dylib, a bundle, a dynamically linked executable, where the kernel maps a static executable's
     slice too.
     */
    func anomalies(slice arch: Universal.Architecture) -> [String] {
        let image = self.image
        var found: [String] = []
        let mask = ~cpu_subtype_t(bitPattern: CPU_SUBTYPE_MASK)
        if image.cpuType != arch.cpuType || image.cpuSubtype & mask != arch.cpuSubtype & mask {
            found.append("slice \(arch.name) by the table is \(Universal.archName(cpuType: image.cpuType, cpuSubtype: image.cpuSubtype)) by its header")
        }
        let page = image.uses16KPages ? 0x4000 : 0x1000
        if !self.isUnmapped, arch.offset % page != 0 {
            found.append("slice \(arch.name) at \(arch.offset.hex) is not page aligned")
        }
        return found
    }

    /**
     What a universal file with more entries than `Universal.open` reads is: a file hash mode and verify take for no
     Mach-O, whose slices are neither hashed nor looked at, where the kernel reads as many entries as its page holds
     and runs the best of them.
     */
    static func anomaly(oversized table: Universal.Table) -> String {
        "a universal file of \(String(table.count, pluralizing: "slice")), more than the \(Universal.maxSliceCount) read here: the kernel reads as many as fit in its page, 204 or 818, and runs one; the slices are neither hashed nor verified"
    }

    /**
     What a slice that is not a thin Mach-O is: nothing for an archive, which `lipo` puts in a universal static library,
     nor for a slice of a CPU no loader knows, as a Metal library's, a universal file inside the universal file, which
     no loader opens, or neither.
     */
    static func anomaly(slice arch: Universal.Architecture, in file: File) throws -> String? {
        let head = try file.read(at: arch.offset, count: min(arch.length, 8))
        if head.starts(with: "!<arch>\n".utf8) || arch.name.hasPrefix("unknown(") {
            return nil
        }
        if head.count >= 4, [FAT_MAGIC, FAT_MAGIC_64].contains(head.withUnsafeBytes { UInt32(bigEndian: $0.loadUnaligned(as: UInt32.self)) }) {
            return "slice \(arch.name) is itself a universal file"
        }
        return "slice \(arch.name) is neither Mach-O nor an archive"
    }
}

extension File {
    /**
     How many bytes of `ranges` of the file are not zero, and where the first is; nil when they all are, or cannot be
     read.
     */
    func nonZero(in ranges: [Range<Int>]) -> NonZero? {
        var count = 0
        var first: Int?
        for range in ranges where !range.isEmpty {
            var offset = range.lowerBound
            guard (try? self.stream(range) { chunk in
                for (index, byte) in chunk.enumerated() where byte != 0 {
                    count += 1
                    if first == nil {
                        first = offset + index
                    }
                }
                offset += chunk.count
            }) != nil else {
                return nil
            }
        }
        return first.map { NonZero(count: count, first: $0) }
    }

    /// What of some ranges is not zero: how many bytes, and where the first is.
    struct NonZero {
        let count: Int
        let first: Int
    }
}
