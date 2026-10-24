import Foundation
import MachO

enum EditError: Error, Equatable {
    /// The code signature does not end the image, so removing it would cut off what follows.
    case signatureNotAtEnd
}

extension EditError: LocalizedError {
    var errorDescription: String? {
        switch self {
        case .signatureNotAtEnd:
            // Security's own words, which codesign logs before it fails with an internal error.
            "LC_CODE_SIGNATURE does not point to end of file"
        }
    }
}

/**
 A Mach-O file as `--unsign` and `--unpack` edit it, named after Security's `MachOEditor`, which `codesign
 --remove-signature` drives: the file is edited in memory (`File(editing:pieces:)`), as Security edits its copy before
 it writes it, so hash mode digests the edit and `thin` writes it out.

 Where Security stops at what it can tell from the signed file, the file is restored as it was before it was signed,
 as far as it can be: the linker's `__LINKEDIT` vmsize, and the layout `lipo` gave a universal file. An image UPX packed
 is unpacked as `upx -d` unpacks it (`PackMach`), the one edit whose bytes all live in memory.
 */
enum MachOEditor {
    /// What the edits did to an image, which `thin` names its artifact by.
    struct Edits: OptionSet {
        let rawValue: Int

        /// The `exact` cut took the bytes appended to it off.
        static let exact = Edits(rawValue: 1 << 0)
        /// UPX packed it, and it was unpacked.
        static let unpacked = Edits(rawValue: 1 << 1)
        /// It was signed, and its signature came out.
        static let unsigned = Edits(rawValue: 1 << 2)
    }

    /**
     The file as the edits leave it, and what they did to each image, in the order of a universal file's
     architectures; nil when they change nothing. With `unpack`, each image UPX packed is unpacked, then with `unsign`,
     each comes out without its code signature, as `MachO.removingSignature(end:)` leaves it; a universal file with its
     architectures so is laid out again as `lipo` lays out the architectures it is given. With `exact`, an image is cut
     where it ends before its signature comes out, so appended bytes do not keep it in. Throws for a Mach-O that does
     not parse, a signature that does not end its image, or packed data that does not hold.
     */
    static func edit(_ file: File, exact: Bool, unsign: Bool, unpack: Bool) throws -> (file: File, edits: [Edits])? {
        switch try Universal.open(file) {
        case let .thin(image):
            return try self.edit(image, of: file, exact: exact, unsign: unsign, unpack: unpack).map { (File(editing: file, pieces: $0.pieces), [$0.edits]) }
        case let .fat(archs):
            let slices = try archs.map { arch -> (arch: Universal.Architecture, pieces: [File.Piece], align: Int, edits: Edits) in
                let whole: [File.Piece] = [.range(arch.offset ..< arch.offset + arch.length)]
                guard let image = try MachO(file, offset: arch.offset, length: arch.length) else {
                    // An archive, aligned by lipo for its members' symbols.
                    return (arch, whole, arch.cpuType & CPU_ARCH_ABI64 != 0 ? 3 : 2, [])
                }
                guard let edit = try self.edit(image, of: file, exact: exact, unsign: unsign, unpack: unpack) else {
                    return (arch, whole, image.universalAlignment, [])
                }
                return (arch, edit.pieces, edit.align, edit.edits)
            }
            guard slices.contains(where: { !$0.edits.isEmpty }) else {
                return nil
            }
            let magic = try file.read(at: 0, count: MemoryLayout<UInt32>.size).withUnsafeBytes { UInt32(bigEndian: $0.loadUnaligned(as: UInt32.self)) }
            return (File(editing: file, pieces: self.universal(slices.map { ($0.arch, $0.pieces, $0.align) }, is64: magic == FAT_MAGIC_64)), slices.map(\.edits))
        case .notMachO:
            return nil
        }
    }

    // MARK: - Private

    /**
     The pieces of `image` of `file` as the edits leave it, the alignment `lipo` gives the image they make, and what they
     did to it; nil when they change nothing. An unpacked image lives in memory, without its signature too with
     `unsign`.
     */
    private static func edit(_ image: MachO, of file: File, exact: Bool, unsign: Bool, unpack: Bool) throws -> (pieces: [File.Piece], align: Int, edits: Edits)? {
        if unpack, var data = try self.unpacked(image, of: file, exact: exact) {
            // The unpacked image is parsed in a scope of its own, so that nothing holds its bytes, up to 768 MiB, when
            // they are edited in place below.
            let align: Int
            let unsigned: (head: Data, end: Int, cut: Bool)?
            do {
                guard let unpacked = try MachO(File(editing: file, pieces: [.bytes(data)])) else {
                    throw UnpackError.cantUnpack("file header corrupted")
                }
                align = unpacked.universalAlignment
                let end = exact ? unpacked.logicalEnd() : unpacked.length
                unsigned = try unsign ? unpacked.removingSignature(end: end).map { ($0.head, $0.end, end < unpacked.length) } : nil
            }
            var edits: Edits = .unpacked
            if let unsigned {
                data.replaceSubrange(0 ..< unsigned.head.count, with: unsigned.head)
                data.removeSubrange(unsigned.end...)
                edits.formUnion(unsigned.cut ? [.exact, .unsigned] : .unsigned)
            }
            return ([.bytes(data)], align, edits)
        }
        guard
            unsign,
            let pieces = try self.unsigned(image, exact: exact)
        else {
            return nil
        }
        return (pieces, image.universalAlignment, exact && image.logicalEnd() < image.length ? [.exact, .unsigned] : .unsigned)
    }

    /**
     What UPX packed in `image` of `file`, unpacked; nil when UPX did not pack it. A signature added after packing hides
     the 16-byte `__LINKEDIT` UPX leaves, so `upx -d` gives up on it: the image is looked at without it.
     */
    private static func unpacked(_ image: MachO, of file: File, exact: Bool) throws -> Data? {
        // A signature that cannot come out, or leaves no image behind, is no sign of UPX: the image is looked at as it is.
        let unsigned = (try? self.unsigned(image, exact: exact)) ?? nil
        let packed = unsigned.flatMap { (try? MachO(File(editing: file, pieces: $0))) ?? nil } ?? image
        return try PackMach(packed)?.unpack()
    }

    /**
     The pieces of `image` without its signature, after the `exact` cut: its header and load commands in memory, then
     the rest of it; nil when it is not signed.
     */
    private static func unsigned(_ image: MachO, exact: Bool) throws -> [File.Piece]? {
        guard let unsigned = try image.removingSignature(end: exact ? image.logicalEnd() : image.length) else {
            return nil
        }
        return [.bytes(unsigned.head), .range(image.offset + unsigned.head.count ..< image.offset + unsigned.end)]
    }

    /**
     A universal file of `slices`, in order, laid out as `lipo` lays them out (`create_fat`): each slice at the first
     offset after the fat table, or after the slice before it, that its alignment allows, the gaps zeroed; the table
     records each slice where it lies, and its alignment.
     */
    private static func universal(_ slices: [(arch: Universal.Architecture, pieces: [File.Piece], align: Int)], is64: Bool) -> [File.Piece] {
        func append(_ value: some FixedWidthInteger, to data: inout Data) {
            withUnsafeBytes(of: value.bigEndian) { data.append(contentsOf: $0) }
        }

        var table = Data()
        append(is64 ? FAT_MAGIC_64 : FAT_MAGIC, to: &table)
        append(UInt32(slices.count), to: &table)
        var offset = table.count + slices.count * (is64 ? MemoryLayout<fat_arch_64>.size : MemoryLayout<fat_arch>.size)
        var body: [File.Piece] = []
        for slice in slices {
            let start = (offset + (1 << slice.align) - 1) & ~((1 << slice.align) - 1)
            let size = slice.pieces.reduce(0) { $0 + $1.count }
            body.append(.bytes(Data(count: start - offset)))
            body += slice.pieces
            offset = start + size

            append(slice.arch.cpuType, to: &table)
            append(slice.arch.cpuSubtype, to: &table)
            if is64 {
                append(UInt64(start), to: &table)
                append(UInt64(size), to: &table)
                append(UInt32(slice.align), to: &table)
                append(UInt32(0), to: &table) // reserved
            } else {
                append(UInt32(truncatingIfNeeded: start), to: &table)
                append(UInt32(truncatingIfNeeded: size), to: &table)
                append(UInt32(slice.align), to: &table)
            }
        }
        return [.bytes(table)] + body
    }
}

// MARK: -

extension MachO {
    /**
     The image as `codesign --remove-signature` leaves it, the image ending at `end`, but restored as the linker left
     it: its header and load commands rewritten, and where it now ends. Nil when it is not signed.

     Security removes the signature in process (`remove_signature_space`, which `MachOEditor::allocate` calls for each
     architecture) where it once ran `codesign_allocate -r`: `LC_CODE_SIGNATURE` comes out of the load commands, which
     close up behind it, and the image ends where the signature started, or where the string table ends when no more
     than 12 bytes, the padding that aligns the signature, lie between. `__LINKEDIT` ends there too. Throws
     `EditError.signatureNotAtEnd` when the signature does not end the image, give or take the 7 bytes Security lets
     go with it: removing it would cut off what follows.

     Security leaves the vmsize of `__LINKEDIT` as the signature needed it, which `assure_signature_space` rounded up to
     16 KiB, so copies signed by different identities would still differ there: it is rounded up to the page the
     linker aligns the image's segments to instead (`segmentAlignment`), as the linker left it before any signature.

     Where Security goes astray, the intent is followed instead. It keeps pointers to the commands across the move, so
     when `LC_CODE_SIGNATURE` is not the last command it writes the size of `__LINKEDIT` 16 bytes past a command that
     moved, and reads `LC_SYMTAB` there; it moves the commands by 16 bytes whatever `cmdsize` says, and reads the
     string table's range without swapping it. Security also refuses an image without `__LINKEDIT`, or of a filetype it
     never signs, though what to write is as clear there.
     */
    func removingSignature(end: Int) throws -> (head: Data, end: Int)? {
        guard
            let command = self.findCommand(UInt32(LC_CODE_SIGNATURE)),
            let signature = try self.findCodeSignature()
        else {
            return nil
        }
        guard end - 7 ... end ~= signature.offset + signature.size else {
            throw EditError.signatureNotAtEnd
        }

        var newEnd = signature.offset
        if let symtab = self.findCommand(UInt32(LC_SYMTAB))?.payload(as: symtab_command.self) {
            let strings = Int(self.sw(symtab.stroff)) + Int(self.sw(symtab.strsize))
            if strings < newEnd, newEnd <= strings + 12 {
                newEnd = strings
            }
        }

        // The header and load commands, where a command's data keeps the table's indices, its offsets in the image.
        let headerSize = self.is64 ? MemoryLayout<mach_header_64>.size : MemoryLayout<mach_header>.size
        var head = try self.dataAt(0, count: headerSize + self.sizeofcmds)
        func store<T: FixedWidthInteger>(_ value: T, at offset: Int) {
            head.withUnsafeMutableBytes { $0.storeBytes(of: self.sw(value), toByteOffset: offset, as: T.self) }
        }

        // Its size as Security writes it, wrapping when the segment starts past the new end.
        if let linkedit = try self.findSegment("__LINKEDIT") {
            let page = self.segmentAlignment
            if linkedit.cmd == UInt32(LC_SEGMENT_64) {
                let segment = try linkedit.load(segment_command_64.self)
                let filesize = UInt64(newEnd) &- self.sw(segment.fileoff)
                store(filesize, at: linkedit.data.startIndex + MemoryLayout<segment_command_64>.offset(of: \.filesize)!)
                store((filesize &+ UInt64(page - 1)) & ~UInt64(page - 1), at: linkedit.data.startIndex + MemoryLayout<segment_command_64>.offset(of: \.vmsize)!)
            } else {
                let segment = try linkedit.load(segment_command.self)
                let filesize = UInt32(truncatingIfNeeded: newEnd) &- self.sw(segment.fileoff)
                store(filesize, at: linkedit.data.startIndex + MemoryLayout<segment_command>.offset(of: \.filesize)!)
                store((filesize &+ UInt32(page - 1)) & ~UInt32(page - 1), at: linkedit.data.startIndex + MemoryLayout<segment_command>.offset(of: \.vmsize)!)
            }
        }
        let ncmdsOffset = MemoryLayout<mach_header>.offset(of: \.ncmds)!
        let ncmds = head.withUnsafeBytes { self.sw($0.loadUnaligned(fromByteOffset: ncmdsOffset, as: UInt32.self)) }
        store(ncmds &- 1, at: ncmdsOffset)
        store(UInt32(self.sizeofcmds - command.data.count), at: MemoryLayout<mach_header>.offset(of: \.sizeofcmds)!)
        head.removeSubrange(command.data.indices)
        head.append(Data(count: command.data.count))

        // An image that now ends inside its load commands keeps that much of them.
        return (head.prefix(newEnd), newEnd)
    }

    /**
     The page the linker aligns the image's segments to, and rounds their vmsize up to, unless told otherwise: ld64
     uses 16 KiB for arm64 and arm64_32, and for 32-bit ARM but in a kext, 4 KiB for anything else
     (`Options::reconfigureDefaults`).
     */
    var segmentAlignment: Int {
        switch self.cpuType {
        case CPU_TYPE_ARM64, CPU_TYPE_ARM64_32:
            0x4000
        case CPU_TYPE_ARM:
            self.filetype == MH_KEXT_BUNDLE ? 0x1000 : 0x4000
        default:
            0x1000
        }
    }

    /**
     The alignment `lipo` gives the image in a universal file, as a power of two (`get_seg_align`): the largest that
     every segment's address allows, from 2^3, 2^2 in a 32-bit image, up to 2^15, which an address of zero allows.
     */
    var universalAlignment: Int {
        var align = 15
        for command in self.loadCommands {
            let vmaddr: UInt64? = switch command.cmd {
            case UInt32(LC_SEGMENT):
                command.payload(as: segment_command.self).map { UInt64(self.sw($0.vmaddr)) }
            case UInt32(LC_SEGMENT_64):
                command.payload(as: segment_command_64.self).map { self.sw($0.vmaddr) }
            default:
                nil
            }
            if let vmaddr, vmaddr != 0 {
                align = min(align, max(self.is64 ? 3 : 2, vmaddr.trailingZeroBitCount))
            }
        }
        return align
    }
}
