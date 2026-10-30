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
 Verify.lines(for: path)                   one line per finding, "path[ (arch)]: finding", red for what is refused
   |
   Universal.open(file)
   |-- .thin(image) ------> MachOVerifier(image, in: file).anomalies()
   |-- .fat(archs) -------> MachOVerifier.anomalies(universal: file, archs)       the table: a hidden slice,
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
     -> (found: [String], refused: Error?)  what Security refuses of the superblob, red after the lines
 ```
 */
struct MachOVerifier {
    private let image: MachO
    /// The file the image lies in, which an edit of the image reads through.
    private let file: File
    /// The segments, with their sections, parsed once for every group below.
    private let segments: [Segment]

    init(_ image: MachO, in file: File) {
        self.image = image
        self.file = file
        self.segments = Self.segments(of: image)
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
    func anomalies() -> (found: [String], refused: Error?) {
        guard !self.isUnmapped else {
            return ([], nil)
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
            return (found, error)
        }
        return (found, nil)
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
        let sections: [Section]

        var protection: String {
            Self.protection(self.initprot)
        }

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

        /// Whether the section has bytes in the file: not a zero-fill section, and not empty.
        var hasContent: Bool {
            ![UInt32(S_ZEROFILL), UInt32(S_GB_ZEROFILL), UInt32(S_THREAD_LOCAL_ZEROFILL)].contains(self.flags & UInt32(SECTION_TYPE)) && self.size > 0
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

    /// The image's segments, each with the sections its command holds.
    private static func segments(of image: MachO) -> [Segment] {
        image.loadCommands.compactMap { command in
            switch command.cmd {
            case UInt32(LC_SEGMENT):
                command.payload(as: segment_command.self).map {
                    Segment(name: Self.shown(command.data.bytes(in: 8 ..< 24)), field: command.data.bytes(in: 8 ..< 24), vmaddr: UInt64(image.sw($0.vmaddr)), vmsize: UInt64(image.sw($0.vmsize)), fileoff: UInt64(image.sw($0.fileoff)), filesize: UInt64(image.sw($0.filesize)), maxprot: image.sw($0.maxprot), initprot: image.sw($0.initprot), nsects: image.sw($0.nsects), flags: image.sw($0.flags), cmdsize: command.data.count, sections: self.sections(of: command, in: image, header: MemoryLayout<segment_command>.size, count: Int(image.sw($0.nsects)), wide: false))
                }
            case UInt32(LC_SEGMENT_64):
                command.payload(as: segment_command_64.self).map {
                    Segment(name: Self.shown(command.data.bytes(in: 8 ..< 24)), field: command.data.bytes(in: 8 ..< 24), vmaddr: image.sw($0.vmaddr), vmsize: image.sw($0.vmsize), fileoff: image.sw($0.fileoff), filesize: image.sw($0.filesize), maxprot: image.sw($0.maxprot), initprot: image.sw($0.initprot), nsects: image.sw($0.nsects), flags: image.sw($0.flags), cmdsize: command.data.count, sections: self.sections(of: command, in: image, header: MemoryLayout<segment_command_64>.size, count: Int(image.sw($0.nsects)), wide: true))
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
        return name.allSatisfy { 0x20 ... 0x7e ~= $0 } ? decoded : decoded.debugDescription
    }

    /**
     A string the image carries, a dylib's name, a certificate's, an entitlement's key, as a line shows it: as it is
     when printable ASCII, quoted and escaped otherwise, so that a newline in it cannot make a line of its own.
     */
    private static func shown(_ string: String) -> String {
        string.utf8.allSatisfy { 0x20 ... 0x7e ~= $0 } ? string : string.debugDescription
    }

    /// The filetypes dyld loads and the kernel runs, whose layout its rules are about.
    private static let loadableFiletypes = [MH_EXECUTE, MH_DYLIB, MH_BUNDLE, MH_DYLINKER].map(UInt32.init)

    private var isLoadable: Bool {
        Self.loadableFiletypes.contains(self.image.filetype)
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

    /**
     The table as the loaders walk it: `ncmds` commands, where Security and this parser walk `sizeofcmds` (the
     kernel's `parse_machfile`, dyld's `forEachLoadCommand`), so `ncmds` short of the table hides commands from the
     loaders alone; a command size that is not pointer sized, which dyld's `Header::validLoadCommands` refuses (the
     published `forEachLoadCommand` asks a multiple of 4 alone); a segment command of the other ABI, which the kernel
     refuses; a
     command the loaders take once, twice; `LC_DYSYMTAB` without `LC_SYMTAB`, two fixup encodings, two entry points,
     two version commands in an executable; a filetype no loader knows; the header field no loader reads.
     */
    private func tableAnomalies() -> [String] {
        let image = self.image
        var found: [String] = []
        let held = image.loadCommands.count
        if image.ncmds < held {
            let unread = image.loadCommands[image.ncmds...].map(\.name).joined(separator: ", ")
            found.append("ncmds \(image.ncmds) hides the last \(String(held - image.ncmds, pluralizing: "command")) of \(held) from the loaders: \(unread)")
        } else if image.ncmds > held {
            found.append("ncmds \(image.ncmds) exceeds the \(String(held, pluralizing: "command")) the table holds")
        }
        let pointer = image.is64 ? 8 : 4
        for (index, command) in image.loadCommands.enumerated() where command.data.count % pointer != 0 {
            found.append("load command #\(index), \(command.name), has a size \(command.data.count.hex) that is not a multiple of \(pointer)")
        }
        let counts = Dictionary(image.loadCommands.map { ($0.cmd, 1) }, uniquingKeysWith: +)
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
        if counts[UInt32(LC_DYSYMTAB)] != nil, counts[UInt32(LC_SYMTAB)] == nil {
            found.append("LC_DYSYMTAB without LC_SYMTAB")
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
     than r-x, r-- and rw- on the three, any other segment writable and executable or executable at all, `__TEXT`
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
            if segment.sections.count != Int(segment.nsects) || (segment.cmdsize - (image.is64 ? MemoryLayout<segment_command_64>.size : MemoryLayout<segment_command>.size)) % (image.is64 ? MemoryLayout<section_64>.size : MemoryLayout<section>.size) != 0 {
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

        let headerSize = image.is64 ? MemoryLayout<mach_header_64>.size : MemoryLayout<mach_header>.size
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
        // __IMPORT, the i386 linker's segment of self-modifying symbol stubs, is rwx by design, and __TEXT_EXEC is a
        // kext's code. The kernel maps nothing writable and executable on arm64 ("curprot cannot be write+execute").
        let wx = [CPU_TYPE_ARM64, CPU_TYPE_ARM64_32].contains(image.cpuType) ? ", which the kernel refuses as arm64" : ""
        let own = ["__TEXT", "__DATA", "__LINKEDIT", "__IMPORT"] + (image.filetype == UInt32(MH_KEXT_BUNDLE) ? ["__TEXT_EXEC"] : [])
        for segment in segments where !own.contains(segment.name) && segment.isExecutable {
            found.append(segment.isWritable ? "segment \(segment.name) is writable and executable\(wx)" : "segment \(segment.name) is executable")
        }

        // The kernel's load_segment hands a segment flagged SG_PROTECTED_VERSION_1 to unprotect_dsmos_segment, which
        // decrypts its pages past the first three as it maps them: Apple's own protection of a few 10.4 to 10.6
        // binaries, which a third party's image can claim too, so that its code reads encrypted on disk.
        for segment in segments where segment.flags & UInt32(SG_PROTECTED_VERSION_1) != 0 {
            found.append("segment \(segment.name) is Apple-protected (SG_PROTECTED_VERSION_1): the kernel decrypts it past its first 0x3000 bytes as it maps it")
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
     vmsize, and dyld maps none of it); no file offset though it is not zero-fill; two sections sharing addresses or
     bytes; the segment name it carries not its segment's. And as a disassembler reads it: its file offset not where
     its address lays it, so the tool reads other bytes than the loader maps; its bytes past the image; its name.
     */
    private func sectionAnomalies() -> [String] {
        var found: [String] = []
        for segment in self.segments {
            for section in segment.sections {
                let what = "section \(segment.name),\(section.name)"
                let end = section.addr.addingReportingOverflow(section.size)
                if segment.vmsize == 0 {
                    // Not mapped: its addresses are the linker's own business.
                } else if end.overflow || section.addr < segment.vmaddr || end.partialValue > segment.vmend {
                    found.append("\(what)'s address range \(section.addr.hex)...\(end.partialValue.hex) lies outside its segment's \(segment.vmaddr.hex)...\(segment.vmend.hex)")
                } else if section.hasContent, segment.filesize > 0 {
                    // Where the address lays it may lie past 2^64, in a segment that maps most of the address space.
                    let expected = segment.fileoff.addingReportingOverflow(section.addr - segment.vmaddr)
                    if expected.overflow || UInt64(section.offset) != expected.partialValue {
                        found.append("\(what)'s file offset \(section.offset.hex) is not where its address lays it, \(expected.overflow ? "past 2^64" : expected.partialValue.hex)")
                    }
                }
                if section.hasContent, section.fileend < UInt64(section.offset) || section.fileend > UInt64(self.image.length) {
                    found.append("\(what) at \(section.offset.hex) with size \(section.size.hex) lies outside the image")
                }
                if segment.vmsize > 0, section.addr % (1 << UInt64(min(section.align, 63))) != 0 {
                    found.append("\(what)'s address \(section.addr.hex) is not aligned to the 2^\(section.align) its align field declares")
                }
                if section.offset == 0, section.hasContent {
                    found.append("\(what) has no file offset though it is not zero-fill")
                }
                if section.segname != segment.name {
                    found.append("\(what) carries the segment name \(section.segname)")
                }
                found += Self.nameAnomalies(section.field.prefix(16), of: what)
            }
            let placed = segment.sections.filter(\.hasContent).sorted { $0.offset < $1.offset }
            for (before, after) in zip(placed, placed.dropFirst()) where UInt64(after.offset) < before.fileend {
                found.append("sections \(segment.name),\(before.name) and \(segment.name),\(after.name) overlap in the file")
            }
            let mapped = segment.sections.filter { $0.size > 0 }.sorted { $0.addr < $1.addr }
            for (before, after) in zip(mapped, mapped.dropFirst()) where after.addr < before.addr &+ before.size {
                found.append("sections \(segment.name),\(before.name) and \(segment.name),\(after.name) overlap in memory")
            }
        }
        return found
    }

    // MARK: - Entry point

    /**
     An executable's entry point as dyld's `validMain` finds it: `LC_MAIN`'s `entryoff` from `__TEXT`'s address,
     `LC_UNIXTHREAD`'s pc register, in a segment that is executable, which should be `__TEXT`, and in its `__text`
     section, a stub section, which an app extension enters through, or GCC's `__text_startup`, rather than in no
     section or in another, as a protector or a crafted entry lands; a thread state that is not the architecture's,
     which the kernel refuses; or neither command.
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
            case let .address(address):
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
        case address(UInt64)
        case flavor(UInt32, UInt32)
        case short
    }

    /**
     The entry `LC_UNIXTHREAD` sets, as dyld's `entryAddrFromThreadCmd` reads it: the pc register of the first thread
     state, 16 bytes into the command, by its index in the architecture's state (`entryAddrRegisterIndexForThreadCmd`),
     64 bits wide in a 64-bit image or an `arm64_32` one. The kernel's `thread_entrypoint` takes the architecture's own
     flavor and count alone. Nil for an architecture neither knows.
     */
    private func threadEntry(_ command: MachO.LoadCommand) -> ThreadEntry? {
        let image = self.image
        let state: (index: Int, flavor: UInt32, count: UInt32)? = switch image.cpuType {
        case CPU_TYPE_I386: (10, 1, 16) // x86_THREAD_STATE32, eip
        case CPU_TYPE_X86_64: (16, 4, 42) // x86_THREAD_STATE64, rip
        case CPU_TYPE_ARM: (15, 1, 17) // ARM_THREAD_STATE, pc
        case CPU_TYPE_ARM64, CPU_TYPE_ARM64_32: (32, 6, 68) // ARM_THREAD_STATE64, pc
        default: nil
        }
        guard let state else {
            return nil
        }
        guard command.data.count >= 16 else {
            return .short
        }
        let (flavor, count) = command.data.withUnsafeBytes { raw in
            (image.sw(raw.loadUnaligned(fromByteOffset: 8, as: UInt32.self)), image.sw(raw.loadUnaligned(fromByteOffset: 12, as: UInt32.self)))
        }
        guard flavor == state.flavor, count == state.count else {
            return .flavor(flavor, count)
        }
        let wide = image.is64 || image.cpuType == CPU_TYPE_ARM64_32
        let at = 16 + state.index * (wide ? 8 : 4)
        guard command.data.count >= at + (wide ? 8 : 4) else {
            return .short
        }
        return .address(command.data.withUnsafeBytes { raw in
            wide ? image.sw(raw.loadUnaligned(fromByteOffset: at, as: UInt64.self)) : UInt64(image.sw(raw.loadUnaligned(fromByteOffset: at, as: UInt32.self)))
        })
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
     encryption; and a version command.
     */
    private func linkAnomalies() -> [String] {
        let image = self.image
        var found: [String] = []
        var installName: String?
        var dylibs = 0
        for command in image.loadCommands where Self.stringCommands.contains(command.cmd) {
            guard let string = command.string(swap: image.swap) else {
                found.append("\(command.name)'s name is not terminated inside the command")
                continue
            }
            switch command.cmd {
            case UInt32(LC_LOAD_DYLINKER) where string != "/usr/lib/dyld":
                found.append("LC_LOAD_DYLINKER names \(Self.shown(string)), not /usr/lib/dyld")
            case UInt32(LC_DYLD_ENVIRONMENT):
                // Apple's own set DYLD_DLSYM_RESULT to thousands of bytes; a library's path fits.
                found.append("LC_DYLD_ENVIRONMENT sets \(string.utf8.count > 128 ? "\(Self.shown(String(string.prefix(80))))… (\(String(string.utf8.count, pluralizing: "byte")))" : Self.shown(string))")
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

        for command in image.loadCommands {
            let wide = command.cmd == UInt32(LC_ENCRYPTION_INFO_64)
            guard wide || command.cmd == UInt32(LC_ENCRYPTION_INFO), let info = command.payload(as: encryption_info_command.self) else {
                continue
            }
            if wide != image.is64 {
                found.append("\(command.name) in a \(image.is64 ? 64 : 32)-bit image")
            }
            if image.sw(info.cryptid) != 0 {
                found.append("encrypted: cryptid \(image.sw(info.cryptid)) over \(image.sw(info.cryptsize).hex) bytes at \(image.sw(info.cryptoff).hex)")
            }
        }
        if (try? image.version()) ?? nil == nil {
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

        // codesign rounds __LINKEDIT's vmsize up to 16 KiB when it signs, and leaves it so when it removes the
        // signature, where ld64 and strip round it as `linkeditSizeRounding` says: more than that, on an image without a
        // signature, is a signature's residue.
        if image.findCommand(UInt32(LC_CODE_SIGNATURE)) == nil, let linkedit = self.segments.last(where: { $0.name == "__LINKEDIT" }), linkedit.filesize > 0 {
            let rounding = UInt64(image.linkeditSizeRounding)
            let expected = (linkedit.filesize + rounding - 1) & ~(rounding - 1)
            if linkedit.vmsize % 0x4000 == 0, linkedit.vmsize > expected {
                found.append("__LINKEDIT's vmsize \(linkedit.vmsize.hex) is a signature's 16 KiB rounding on an image without one: a signature came out")
            }
        }

        // UPX: as it is, or behind a signature added after packing, which hides the 16-byte __LINKEDIT UPX left; a
        // pack header found that does not hold is named, as unpack refuses it.
        switch Result(catching: { try PackMach(image) }) {
        case let .success(packed?):
            found.append(packed.packer)
        case .success(nil):
            if image.findCommand(UInt32(LC_CODE_SIGNATURE)) != nil, let pieces = (try? MachOEditor.unsigned(image, end: image.length)) ?? nil, let unsigned = (try? MachO(File(editing: self.file, pieces: pieces))) ?? nil, let packed = try? PackMach(unsigned) {
                found.append("\(packed.packer), signed after packing")
            }
        case let .failure(error):
            found.append("\(File.message(for: error)): a pack header that does not hold, which unpack refuses")
        }
        return found
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
        LC_DYLD_CHAINED_FIXUPS]

    /**
     The tables as dyld's `isValidLinkeditLayout` lays them: each inside `__LINKEDIT`, the first of that name as dyld
     takes it, none overlapping another; and the bytes of `__LINKEDIT` no table references, which the linker and
     codesign leave as zeros: a payload otherwise, signed over when the image was signed after.
     */
    private func linkeditAnomalies() -> [String] {
        let image = self.image
        guard let linkedit = self.segments.first(where: { $0.name == "__LINKEDIT" }), linkedit.filesize > 0 else {
            return []
        }
        var found: [String] = []
        let tables = image.loadCommands.filter { Self.linkeditCommands.contains($0.cmd) }.flatMap { image.fileRanges(of: $0) ?? [] }.filter { $0.size > 0 }
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
        if let (count, first) = self.nonZero(in: gaps) {
            found.append("\(count.hex) bytes of __LINKEDIT that no table references are not zero, the first at \(first.hex)")
        }
        return found
    }

    /// How many bytes of `ranges` of the image are not zero, and where the first is: `File.nonZero(in:)` of the image.
    private func nonZero(in ranges: [Range<Int>]) -> (count: Int, first: Int)? {
        let offset = self.image.offset
        return self.file.nonZero(in: ranges.map { $0.lowerBound + offset ..< $0.upperBound + offset }).map { ($0.count, $0.first - offset) }
    }

    // MARK: - Padding

    /**
     The bytes of a segment no section covers, past the header and load commands, and the bytes between one segment's
     content and the next's: page padding the linker writes as zeros, which no loader reads and codesign signs over. A
     gap shorter than the alignment of the section that follows is that section's alignment padding, which an older
     ld64 fills with no-ops on x86_64, so it is not looked at.
     */
    private func paddingAnomalies() -> [String] {
        let image = self.image
        var found: [String] = []
        let headerEnd = UInt64((image.is64 ? MemoryLayout<mach_header_64>.size : MemoryLayout<mach_header>.size) + image.sizeofcmds)
        for segment in self.segments where segment.filesize > 0 && segment.name != "__LINKEDIT" && !segment.sections.isEmpty {
            var gaps: [Range<Int>] = []
            var cursor = segment.fileoff == 0 ? min(headerEnd, segment.fileend) : segment.fileoff
            for section in segment.sections.filter(\.hasContent).sorted(by: { $0.offset < $1.offset }) {
                let start = min(max(UInt64(section.offset), segment.fileoff), segment.fileend)
                if start > cursor, start - cursor >= 1 << min(section.align, 63) {
                    gaps.append(Int(cursor) ..< Int(start))
                }
                cursor = max(cursor, min(section.fileend, segment.fileend))
            }
            if segment.fileend > cursor {
                gaps.append(Int(cursor) ..< Int(segment.fileend))
            }
            if let (count, first) = self.nonZero(in: gaps) {
                found.append("\(count.hex) bytes of \(segment.name) that no section covers are not zero, the first at \(first.hex)")
            }
        }
        let placed = self.segments.filter { $0.filesize > 0 }.sorted { $0.fileoff < $1.fileoff }
        for (before, after) in zip(placed, placed.dropFirst()) where after.fileoff > before.fileend {
            if let (count, first) = self.nonZero(in: [Int(before.fileend) ..< Int(after.fileoff)]) {
                found.append("\(count.hex) bytes between \(before.name) and \(after.name) are not zero, the first at \(first.hex)")
            }
        }
        return found
    }

    // MARK: - Signature

    // The special slots a code directory seals (`cs_blobs.h`), the CMS blob's slot, and the ad-hoc flag.
    private static let csslotRequirements: UInt32 = 2
    private static let csslotEntitlements: UInt32 = 5
    private static let csslotDEREntitlements: UInt32 = 7
    private static let csslotSignature: UInt32 = 0x10000
    private static let csAdhoc: UInt32 = 0x2

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
     The signature as Security verifies it and the kernel takes it: an arm64 image without one, which the kernel does
     not run; a signature Security loads no code directory from; for each directory, the first page of code that does
     not hash to it (`validateExecutable`), a code limit short of the signature's offset, which leaves the pages before
     it unsigned (the kernel's `csb_end_offset`), or past it, a scatter vector, which is not checked here, a page size
     the kernel refuses; no CMS blob behind a directory not flagged ad hoc; a special slot that does not seal the blob
     it should, `__TEXT,__info_plist`, the requirements, the entitlements and their DER form, which the kernel checks
     for the last two and Security for all; entitlements that opt out of hardening; and who signed, as `Signer` has
     it: a CMS blob that does not verify over the directory, a chain that ends outside Apple's roots, which codesign
     and the kernel take and Gatekeeper refuses, a development or submission certificate, a Developer ID signature old
     enough to run without a ticket, a team identifier the developer's certificate does not bear, a CMS blob Security
     ignores behind an ad-hoc directory, and entitlements AMFI reserves to Apple's own signature. The Info.plist slot is not checked: for a
     bundle's executable it seals the bundle's Info.plist, not the section's.

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
        let directories = MachO.loadCodeDirectories(superblob)
        guard let primary = directories.first else {
            return found + ["a signature Security loads no code directory from"]
        }
        // Security verifies the CMS blob over the first directory, slot 0, and reads the flags and the team from the
        // best of them, the kernel's choice too (`SecStaticCode::codeDirectory`, `bestHashOf`).
        let best = directories.max { $0.hashType.rank < $1.hashType.rank } ?? primary

        for (directory, checked) in try zip(directories, image.validateExecutables(directories)) {
            let type = "the \(directory.hashType.name) code directory"
            if let slot = checked.failedSlot {
                found.append("page \(slot) of the code does not hash to \(type)")
            } else if !checked.valid {
                found.append("\(type) covers \(directory.codeLimit.hex) bytes, past the image's \(image.length.hex)")
            }
            if directory.codeLimit < UInt64(signature.offset) {
                found.append("\(type) covers \(directory.codeLimit.hex) bytes, \((UInt64(signature.offset) - directory.codeLimit).hex) short of the signature at \(signature.offset.hex): the rest is unsigned")
            } else if checked.valid, directory.codeLimit > UInt64(signature.offset) {
                found.append("\(type) covers \(directory.codeLimit.hex) bytes, past the signature at \(signature.offset.hex)")
            }
            if directory.scattered {
                found.append("\(type) is scattered, which is not checked here")
            }
            if ![12, 14].contains(directory.pageSizeLog) {
                found.append("\(type)'s page size, 2^\(directory.pageSizeLog), is neither the 4 KiB nor the 16 KiB the kernel takes")
            }
        }

        let sealed: [(slot: UInt32, what: String, blob: Data?)] = [
            (Self.csslotRequirements, "the requirements blob", MachO.component(Self.csslotRequirements, of: superblob)),
            (Self.csslotEntitlements, "the entitlements blob", MachO.component(Self.csslotEntitlements, of: superblob)),
            (Self.csslotDEREntitlements, "the DER entitlements blob", MachO.component(Self.csslotDEREntitlements, of: superblob)),
        ]
        for directory in directories {
            let type = "the \(directory.hashType.name) code directory"
            for (slot, what, blob) in sealed {
                let hash = directory.specialSlot(Int(slot))
                let zero = hash?.allSatisfy { $0 == 0 } ?? true
                if let blob {
                    // A slot the signer left empty seals nothing, which the kernel refuses of entitlements.
                    if zero {
                        found.append("\(what) is not sealed by \(type)")
                    } else if directory.hashType.digest(blob).prefix(directory.hashType.slotSize) != hash {
                        found.append("\(what) does not hash to its slot in \(type)")
                    }
                } else if !zero {
                    found.append("\(type) seals \(what), which the signature does not hold")
                }
            }
        }

        // The entitlements: the XML plist, and its DER form, which codesign writes beside it since macOS 12 and
        // which AMFI and the kernel read where it is. The verdicts below are read from the DER form when there is one.
        var entitled: [String: Any]?
        if let entitlements = MachO.component(Self.csslotEntitlements, of: superblob) {
            if let plist = try? PropertyListSerialization.propertyList(from: Data(entitlements.dropFirst(8)), format: nil) as? [String: Any] {
                entitled = plist
            } else {
                found.append("entitlements that do not parse as a plist")
            }
        }
        if let der = MachO.component(Self.csslotDEREntitlements, of: superblob) {
            if let decoded = DEREntitlements.decode(Data(der.dropFirst(8))) {
                if let plist = entitled {
                    let differing = Set(plist.keys).union(decoded.keys).filter { !Self.equal(plist[$0], decoded[$0]) }
                    if !differing.isEmpty {
                        found.append("the entitlements and their DER form, which AMFI reads, disagree on \(differing.sorted().map(Self.shown).joined(separator: ", "))")
                    }
                }
                entitled = decoded
            } else {
                found.append("DER entitlements that do not decode")
            }
        }
        if let entitled {
            let weakening = Self.weakeningEntitlements.filter { (entitled[$0] as? Bool) == true }
            if !weakening.isEmpty {
                found.append("entitled to opt out of hardening: \(weakening.joined(separator: ", "))")
            }
        }

        // The CMS blob, past its 8-byte header; Security reads it only behind a directory not flagged ad hoc.
        let cms = MachO.component(Self.csslotSignature, of: superblob).map { Data($0.dropFirst(8)) } ?? Data()
        if best.flags & Self.csAdhoc != 0 {
            if !cms.isEmpty {
                found.append("a CMS signature behind a code directory flagged ad hoc, which Security ignores")
            }
            found += self.restrictedEntitlements(entitled, signedBy: nil)
        } else if cms.isEmpty {
            found.append("no CMS signature behind a code directory not flagged ad hoc")
            found += self.restrictedEntitlements(entitled, signedBy: nil)
        } else {
            found += self.signerAnomalies(cms, over: primary, team: best, entitled: entitled)
        }
        return found
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
     Who signed, as `Signer` verifies and classes the CMS blob over `primary`: what fails to verify, in one line, else
     the chain Gatekeeper refuses or runs without a ticket, and a team identifier in `best`, the directory Security
     reads it from, that the certificate does not bear, which Security refuses (`errSecCSBadTeamIdentifier`); then the
     entitlements AMFI reserves, given who signed.
     */
    private func signerAnomalies(_ cms: Data, over primary: EmbeddedCodeDirectory, team best: EmbeddedCodeDirectory, entitled: [String: Any]?) -> [String] {
        let type = "the \(primary.hashType.name) code directory"
        let signer: Signer
        do {
            signer = try Signer(cms: cms, over: primary.data)
        } catch {
            let line = switch error {
            case .undecodable: "a CMS signature Security cannot decode"
            case .unsigned: "a CMS signature with no signer"
            case .invalidSignature: "the CMS signature does not verify over \(type)"
            case let .chain(reason): "the signer's certificate chain does not build: \(Self.shown(reason))"
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
     the table's count, which dyld and codesign find and the kernel does not; two slices of one architecture, which the
     kernel refuses (`fatfile_validate_fatarches`); slices that overlap; a slice not aligned as its entry declares;
     padding before a slice that is not zero, which Security calls suspicious (`Universal::Universal`); and bytes past
     the last slice.
     */
    static func anomalies(universal file: File, _ archs: [Universal.Architecture]) -> [String] {
        var found: [String] = []
        let magic = (try? file.read(at: 0, count: 4))?.withUnsafeBytes { UInt32(bigEndian: $0.loadUnaligned(as: UInt32.self)) }
        let is64 = magic == FAT_MAGIC_64
        if is64 {
            found.append("a 64-bit universal file, which the kernel does not run and codesign signs as a generic file")
        }
        let counted = archs.filter { !$0.hidden }.count
        for arch in archs where arch.hidden {
            found.append("slice \(arch.name) is hidden past the table's \(String(counted, pluralizing: "entry", plural: "entries")): dyld and codesign find it, the kernel does not")
        }
        // The kernel compares the entries' cputype and cpusubtype as they are, capability bits included.
        var slices: [String: (name: String, count: Int)] = [:]
        for arch in archs {
            slices["\(arch.cpuType),\(arch.cpuSubtype)", default: (arch.name, 0)].count += 1
        }
        for (name, count) in slices.values.sorted(by: { $0.name < $1.name }) where count > 1 {
            found.append("\(count) slices of \(name), which the kernel refuses")
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
            if arch.offset > cursor, let (count, first) = file.nonZero(in: [cursor ..< arch.offset]) {
                found.append("\(count.hex) bytes of padding before slice \(arch.name) are not zero, the first at \(first.hex)")
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
     for the arm64 family and 4 KiB otherwise. An image no loader maps says nothing of its page, as a Metal library
     packs its GPU slices as it likes.
     */
    func anomalies(slice arch: Universal.Architecture) -> [String] {
        let image = self.image
        var found: [String] = []
        let mask = ~cpu_subtype_t(bitPattern: CPU_SUBTYPE_MASK)
        if image.cpuType != arch.cpuType || image.cpuSubtype & mask != arch.cpuSubtype & mask {
            found.append("slice \(arch.name) by the table is \(Universal.archName(cpuType: image.cpuType, cpuSubtype: image.cpuSubtype)) by its header")
        }
        let page = [CPU_TYPE_ARM64, CPU_TYPE_ARM64_32].contains(image.cpuType) ? 0x4000 : 0x1000
        if !self.isUnmapped, arch.offset % page != 0 {
            found.append("slice \(arch.name) at \(arch.offset.hex) is not page aligned")
        }
        return found
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
    func nonZero(in ranges: [Range<Int>]) -> (count: Int, first: Int)? {
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
        return first.map { (count, $0) }
    }
}
