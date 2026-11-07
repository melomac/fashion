import Foundation
import MachO
import os

private let logger = Logger(subsystem: "fashion", category: "edit")

enum EditError: Error, Equatable {
    /// The code signature does not end the image, so removing it would cut off what follows.
    case signatureNotAtEnd
    /// The code signature starts inside the header or the load commands, which the edit rewrites.
    case signatureInsideHeaders
}

extension EditError: LocalizedError {
    var errorDescription: String? {
        switch self {
        case .signatureNotAtEnd:
            // Security's own words, which codesign logs before it fails with an internal error.
            "LC_CODE_SIGNATURE does not point to end of file"
        case .signatureInsideHeaders:
            "LC_CODE_SIGNATURE points inside the load commands"
        }
    }
}

/**
 A Mach-O file as `unsign` and `unpack` edit it, named after Security's `MachOEditor`, which `codesign
 --remove-signature` drives: the file is edited in memory (`File(editing:pieces:)`), as Security edits its copy before
 it writes it, so hash mode digests the edit and `thin` writes it out.

 Where Security stops at what it can tell from the signed file, the file is restored as it was before it was signed,
 as far as it can be: the linker's `__LINKEDIT` vmsize, and the layout `lipo` gave a universal file. An image UPX packed
 is unpacked as `upx -d` unpacks it (`PackMach`), the one edit whose bytes all live in memory.
 */
enum MachOEditor {
    /**
     What the edits did to an image, in the order they are done, which `thin` names its artifacts by: the `exact` cut,
     then its signature out, then what UPX packed unpacked, then the unpacked image's own `exact` cut and its own
     signature out.
     */
    struct Edits: OptionSet {
        let rawValue: Int

        /// The `exact` cut took the bytes appended to it off.
        static let exact = Edits(rawValue: 1 << 0)
        /// It was signed, and its signature came out.
        static let unsigned = Edits(rawValue: 1 << 1)
        /// UPX packed it, and it was unpacked.
        static let unpacked = Edits(rawValue: 1 << 2)
        /// The `exact` cut took the bytes appended to the unpacked image off.
        static let exactUnpacked = Edits(rawValue: 1 << 3)
        /// The unpacked image was signed, and its signature came out.
        static let unsignedUnpacked = Edits(rawValue: 1 << 4)
        /// UPX packed it, and what decompressed fails a check: kept as it is, under --keep, in place of `unpacked`.
        static let decompressed = Edits(rawValue: 1 << 5)

        /// The edits in the order they are done, each with the word an artifact is named by for it: `_unsigned` in a
        /// file's name, `unsigned` in hash mode's label (`Artifact`).
        static let names: [(Edits, String)] = [(.exact, "exact"), (.unsigned, "unsigned"), (.decompressed, "decompressed"), (.unpacked, "unpacked"), (.exactUnpacked, "exact"), (.unsignedUnpacked, "unsigned")]

        /// The words for these edits, in the order they were done: `["exact", "unsigned"]`.
        var words: [String] {
            Self.names.filter { self.contains($0.0) }.map(\.1)
        }
    }

    /// An image as one edit leaves it: what was done to it so far, and its bytes, in memory or ranges of the file.
    struct State {
        let edits: Edits
        let pieces: [File.Piece]
    }

    /**
     One slice of a universal file as the edits leave it, for `universal(_:is64:)` to lay out: its architecture, as
     the table read it, its bytes, pieces of the file or in memory, and the alignment `lipo` gives it, as a power of
     two; with the states it went through and its `exact` cut alone, for the `Edit`.
     */
    struct Slice {
        let arch: Universal.Architecture
        let pieces: [File.Piece]
        let align: Int
        var states: [State] = []
        var cut: State?
    }

    /**
     How far the `exact` cut goes: nowhere (`never`), or everywhere, each image cut where its load commands end it
     (`always`), as hash mode has it without and with --exact; or where a stage needs it alone (`asNeeded`), as `thinr`,
     `unsign` and `unpack` have it without --exact: a file cut short of its last page padded to be read at all, an
     image cut where bytes appended past its end keep its signature from coming out, and the unpacked image likewise,
     each named `_exact` for it as the flag would name it.
     */
    enum Exact {
        case never, asNeeded, always

        /// The cut as the flag alone has it, for a stage that needs none.
        var flagged: Exact {
            self == .always ? .always : .never
        }
    }

    /**
     What the edits made of a file: `file`, the file as they leave it, which hash mode digests whole and `unsign` and
     `unpack` write; `states`, the way each image went, one chain per image in the order of a universal file's
     architectures, a thin file's alone, empty for an image the edits leave alone, each piece a range of `source` or
     bytes in memory; `cuts`, the `exact` cut alone of each image the edits leave alone, in the same order, which is
     no edit and so no state of its own: the artifact `thinr --exact` lists and hash mode digests for the image, nil
     where the image ends where it is, or something was done to it, its chain then cut as it went; `source`, the file
     the states are pieces of, the file as read or padded to be read (`padded`); and `opened`, `source` as `Universal`
     opened it for the edit, which the states follow, so that what is named, digested or written after them follows
     the same read and reads the headers no second time.
     */
    struct Edit {
        let file: File
        let states: [[State]]
        let cuts: [State?]
        let source: File
        let opened: Universal

        /// A universal file's architectures as its table was read for the edit, `opened`'s; nil for a thin file.
        var archs: [Universal.Architecture]? {
            if case let .fat(table) = self.opened {
                return table.archs
            }
            return nil
        }

        /// Whether the edits left every image as it is: `file` is `source`, and the `exact` cut alone, which is no
        /// edit, is in `cuts` where it is asked.
        var isUnchanged: Bool {
            self.states.allSatisfy(\.isEmpty)
        }
    }

    /**
     What the edits make of `file` (`Edit`): the file as they leave it, the states each image went through, one per
     edit, in the order of a universal file's architectures, an image the edits leave alone with none and its `exact`
     cut alone beside, and the file the states are pieces of, `file` or its padding (`padded`), as it was opened;
     every image with none when they change nothing, the headers read all the same, so that what comes after the
     edit reads them no second time; nil for a file that is not Mach-O. With
     `unsign`, each image comes out without its code signature, as `MachO.removingSignature(end:)` leaves it; with
     `unpack`, each image UPX packed is unpacked, its signature out first where one was added after packing, since it
     hides what UPX left, then with `unsign` the unpacked image's own signature comes out; a universal file with its
     architectures so is laid out again as `lipo` lays out the architectures it is given. With `exact` `always`, an
     image is cut where it ends before its signature comes out, so appended bytes do not keep it in, the unpacked image
     too; one the edits leave alone is left as it is, appended bytes included, since the cut alone is no edit. As
     needed, the cut and the padding come where a stage needs them alone, the padding held back until an edit comes of
     it. Throws for a Mach-O that does not parse, with `unsign` for a signature that does not end its image and that no
     cut frees, which `unpack` alone leaves in, the image looked at as it is, and for packed data, or the image
     unpacked from it, that does not hold: a `SliceError` naming the architecture, in a universal file. `caveat` hears
     what an edit has to say about an image, named after its architecture in a universal file: that a modified UPX
     packed it, and how. Each edit done is noted in the unified log, under the edit category, after the image's path
     and architecture: the bytes a cut dropped, the signature removed, and how UPX packed what is unpacked, with where
     its pack header, `l_info`, `p_info` and each block lie, to read the packed file by hand. `keep`, when given,
     gets what decompressed of an image that fails a check after, a sum or its headers, with the edits done before it
     and `decompressed` for it, and the architecture: the refusal is thrown all the same.
     */
    static func edit(_ file: File, exact: Exact, unsign: Bool, unpack: Bool, caveat: (_ arch: String?, _ message: String) -> Void = { _, _ in }, keep: ((_ arch: String?, _ edits: Edits, _ data: Data) -> Void)? = nil) throws -> Edit? {
        let read = file
        var held: [String] = []
        let (file, opened): (File, Universal)
        do {
            if exact == .never {
                (file, opened) = (read, try Universal.open(read))
            } else {
                (file, opened) = try self.padded(read, caveat: { exact == .always ? caveat(nil, $0) : held.append($0) })
            }
        } catch {
            // The padding is said before the error the padded file ends in, which names the padded size.
            held.forEach { caveat(nil, $0) }
            throw error
        }
        switch opened {
        case let .thin(image):
            var said: [String] = []
            // The padding is said before what the edit says, or the error it ends in, unless nothing comes of it.
            var padding = held
            defer {
                (padding + said).forEach { caveat(nil, $0) }
            }
            let edit = try self.edit(image, of: file, subject: file.path, exact: exact, unsign: unsign, unpack: unpack, padded: file !== read, caveat: { said.append($0) }, keep: keep.map { held in { held(nil, $0, $1) } })
            guard let last = edit.states.last else {
                // Padded as needed for nothing: the file as it is, which the parser refuses, says why.
                padding = []
                if file !== read {
                    _ = try Universal.open(read)
                }
                return Edit(file: file, states: [[]], cuts: [edit.cut], source: file, opened: opened)
            }
            return Edit(file: File(editing: file, pieces: last.pieces), states: [edit.states], cuts: [nil], source: file, opened: opened)
        case let .fat(table):
            // Each slice is named as Universal.named names it, the second of one architecture apart, as the artifacts
            // of them are.
            let slices = try Universal.named(table.archs).map { arch, name -> Slice in
                let whole: [File.Piece] = [.range(arch.offset ..< arch.offset + arch.length)]
                do {
                    guard let image = try MachO(file, offset: arch.offset, length: arch.length) else {
                        // An archive, which lipo aligns to 2^3 whatever its architecture.
                        return Slice(arch: arch, pieces: whole, align: 3)
                    }
                    let edit = try self.edit(image, of: file, subject: "\(file.path) (\(name))", exact: exact, unsign: unsign, unpack: unpack, padded: false, caveat: { caveat(name, $0) }, keep: keep.map { held in { held(name, $0, $1) } })
                    guard let last = edit.states.last else {
                        return Slice(arch: arch, pieces: whole, align: image.universalAlignment, cut: edit.cut)
                    }
                    return Slice(arch: arch, pieces: last.pieces, align: edit.align, states: edit.states)
                } catch {
                    throw SliceError(arch: name, error: error)
                }
            }
            guard slices.contains(where: { !$0.states.isEmpty }) else {
                return Edit(file: file, states: slices.map(\.states), cuts: slices.map(\.cut), source: file, opened: opened)
            }
            return Edit(file: File(editing: file, pieces: self.universal(slices, is64: table.is64)), states: slices.map(\.states), cuts: slices.map(\.cut), source: file, opened: opened)
        case .notMachO:
            return nil
        }
    }

    // MARK: - Private

    /**
     `file` as its headers lay it out, for `exact`, and as `Universal` opened it: a thin Mach-O cut short of an empty
     segment that lies past its end, as a file UPX 3.91 packed, padded with a page of zeros, and lost that page, is
     padded with zeros up to the segment, a page at most, since nothing the image references is missing, and `caveat`
     hears of it, the padded file then opened in its place. Any other file as it is, opened the once: a segment with
     bytes past the end is a malformed Mach-O, which the parser refuses.
     */
    static func padded(_ file: File, caveat: (String) -> Void) throws -> (file: File, opened: Universal) {
        do {
            return (file, try Universal.open(file))
        } catch let ParserError.invalidSegmentRange(name, offset, size, fileSize) where size == 0 && fileSize == file.size && offset > UInt64(fileSize) && offset - UInt64(fileSize) <= 0x4000 {
            let missing = Int(offset) - fileSize
            caveat("cut short of its last page, \(missing.hex) bytes before \(name) at \(offset.hex): padded with zeros")
            let padded = File(editing: file, pieces: [.range(0 ..< fileSize), .bytes(Data(count: missing))])
            return (padded, try Universal.open(padded))
        }
    }

    /**
     The states `image` of `file` goes through as the edits are done, the last as they leave it, the first the image
     `padded` where `file` was cut short of its last page, cut where it ends as the padding is the cut's doing, and the
     alignment `lipo` gives the image they make; none when they change nothing, an image the `exact` cut alone would
     shorten included, which is left as it is, its cut kept beside as `cut` where the flag asks for it, and the padded
     image as needed. `caveat` hears `PackMach`'s word on the
     image: that a modified UPX packed it, and how. Each edit is noted in the unified log after `subject`, the image's
     path and architecture. An unpacked image lives in memory, the states after it sharing its bytes. `keep` gets
     what decompressed of an image that fails a check after, with the edits before it and `decompressed`, before the
     refusal is thrown.
     */
    private static func edit(_ image: MachO, of file: File, subject: String, exact: Exact, unsign: Bool, unpack: Bool, padded: Bool, caveat: (String) -> Void, keep: ((Edits, Data) -> Void)?) throws -> (states: [State], align: Int, cut: State?) {
        var states: [State] = []
        var edits: Edits = padded ? [.exact] : []
        let end = padded ? image.logicalEnd() : self.cut(image, exact: exact)
        if end < image.length {
            edits.insert(.exact)
            states.append(State(edits: edits, pieces: [.range(image.offset ..< image.offset + end)]))
            logger.info("\(subject, privacy: .public): cut, \(String(image.length - end, pluralizing: "byte"), privacy: .public) appended past the image dropped, \(end, privacy: .public) left")
        } else if padded {
            // The padding is the cut's doing, the image as its headers lay it out: a state of its own, written as such.
            states.append(State(edits: edits, pieces: [.range(image.offset ..< image.offset + image.length)]))
        }

        // With unpack alone, a signature that cannot come out, or leaves no image behind, is no sign of UPX: the image
        // is looked at as it is.
        let unsigned = try unsign ? self.unsigned(image, end: end) : (try? self.unsigned(image, end: end)) ?? nil
        if unsign, let unsigned {
            edits.insert(.unsigned)
            states.append(State(edits: edits, pieces: unsigned))
            logger.info("\(subject, privacy: .public): unsigned, \(Self.removal(of: unsigned, from: end), privacy: .public)")
        }
        var align = image.universalAlignment
        if unpack {
            // A signature added after packing hides the 16-byte __LINKEDIT UPX leaves, so upx -d gives up on it: the
            // image is looked at without it.
            let probed = unsigned.flatMap { (try? MachO(File(editing: file, pieces: $0))) ?? nil } ?? image
            if let packMach = try PackMach(probed) {
                // What decompressed of an image that fails a check, or decoded under no key where a key was applied,
                // kept as it is for --keep: named for the edits before it, the signature that came out for UPX to be
                // found behind it included.
                let hold = { (data: Data, why: String) in
                    guard let keep else {
                        return
                    }
                    var kept = edits.subtracting(.unpacked)
                    if unsigned != nil {
                        kept.insert(.unsigned)
                    }
                    kept.insert(.decompressed)
                    keep(kept, data)
                    logger.info("\(subject, privacy: .public): decompressed, kept as it is: \(why, privacy: .public)")
                }
                let output = try packMach.unpack()
                let data = output.data
                if let message = output.caveat {
                    caveat(message)
                }
                if let decompressed = output.decompressed {
                    hold(decompressed, "the blocks under no XOR key, as decoded")
                }
                if let unsigned, !edits.contains(.unsigned) {
                    // Its signature had to come out to unpack it: a state of its own.
                    edits.insert(.unsigned)
                    states.append(State(edits: edits, pieces: unsigned))
                    logger.info("\(subject, privacy: .public): unsigned, \(Self.removal(of: unsigned, from: end), privacy: .public), for UPX to be found behind it")
                }
                edits.insert(.unpacked)
                states.append(State(edits: edits, pieces: [.bytes(data)]))
                for note in output.notes {
                    logger.info("\(subject, privacy: .public): unpacked, \(note, privacy: .public)")
                }

                // The unpacked image must parse: one that does not is refused as the sums are, with what decompressed
                // kept as it is for --keep.
                let unpacked: MachO
                do {
                    guard let parsed = try MachO(File(editing: file, pieces: [.bytes(data)])) else {
                        throw UnpackError.cantUnpack("file header corrupted")
                    }
                    unpacked = parsed
                } catch {
                    let reason = error is UnpackError ? "file header corrupted" : "the unpacked image does not parse, \(File.message(for: error))"
                    hold(data, reason)
                    throw UnpackError.unverified(reason)
                }
                align = unpacked.universalAlignment
                // Its own cut, as needed for its own signature to come out.
                let end = self.cut(unpacked, exact: unsign ? exact : exact.flagged)
                if end < unpacked.length {
                    edits.insert(.exactUnpacked)
                    states.append(State(edits: edits, pieces: [.bytes(data[..<end])]))
                    logger.info("\(subject, privacy: .public): unpacked image cut, \(String(unpacked.length - end, pluralizing: "byte"), privacy: .public) appended past it dropped, \(end, privacy: .public) left")
                }
                if unsign, let inner = try unpacked.removingSignature(end: end) {
                    edits.insert(.unsignedUnpacked)
                    states.append(State(edits: edits, pieces: [.bytes(inner.head), .bytes(data[inner.head.count ..< inner.end])]))
                    logger.info("\(subject, privacy: .public): unpacked image unsigned, a code signature of \(String(end - inner.end, pluralizing: "byte"), privacy: .public) removed, \(inner.end, privacy: .public) left")
                }
            }
        }
        guard !edits.isDisjoint(with: [.unsigned, .unpacked]) || (padded && exact == .always) else {
            // The cut alone is no edit, nor the padding as needed: no state, the cut kept beside where the flag asks
            // for it, for what lists the image as --exact cuts it.
            return ([], align, exact == .always ? states.first : nil)
        }
        return (states, align, nil)
    }

    /**
     Where `image` is cut before its signature comes out, as `exact` has it: where its load commands end it, or as it
     is; and as needed, where they end it when its signature does not end the image as it is, bytes appended past them
     keeping it in, which the cut takes off, tried as it is first. A signature inside the image, which no cut frees, is
     left for the removal itself to refuse, as is whatever else it has to say.
     */
    private static func cut(_ image: MachO, exact: Exact) -> Int {
        switch exact {
        case .always:
            return image.logicalEnd()
        case .never:
            return image.length
        case .asNeeded:
            do {
                _ = try image.removingSignature(end: image.length)
            } catch EditError.signatureNotAtEnd where image.logicalEnd() < image.length {
                return image.logicalEnd()
            } catch {
                // Said when the removal is done for good.
            }
            return image.length
        }
    }

    /// What the log says of a signature removed from an image `end` bytes long, `unsigned` its pieces without it.
    private static func removal(of unsigned: [File.Piece], from end: Int) -> String {
        let left = unsigned.reduce(0) { $0 + $1.count }
        return "a code signature of \(String(end - left, pluralizing: "byte")) removed, \(left) left"
    }

    /**
     The pieces of `image` without its signature, cut at `end`: its header and load commands in memory, then the rest
     of it; nil when it is not signed.
     */
    static func unsigned(_ image: MachO, end: Int) throws -> [File.Piece]? {
        guard let unsigned = try image.removingSignature(end: end) else {
            return nil
        }
        return [.bytes(unsigned.head), .range(image.offset + unsigned.head.count ..< image.offset + unsigned.end)]
    }

    /**
     A universal file of `slices`, in order, laid out as `lipo` lays them out (`UniversalWriter`): each slice at the
     first offset after the fat table, or after the slice before it, that its alignment allows, the gaps zeroed; the
     table records each slice where it lies, and its alignment, and counts the slices as `lipo -hideARM64` counts
     them, a hidden one lying past the count of a 32-bit table; a 64-bit table counts it, as no reader looks past the
     count of one. The table is 32-bit unless the file was, or a slice lies or sizes past 4 GiB, which `lipo` writes a
     64-bit table for too.
     */
    static func universal(_ slices: [Slice], is64: Bool) -> [File.Piece] {
        self.universal(slices, wide: is64) ?? self.universal(slices, wide: true)!
    }

    /// `universal(_:is64:)` with a table of 32-bit or `wide` entries; nil for a 32-bit table that cannot place a slice.
    private static func universal(_ slices: [Slice], wide: Bool) -> [File.Piece]? {
        func append(_ value: some FixedWidthInteger, to data: inout Data) {
            withUnsafeBytes(of: value.bigEndian) { data.append(contentsOf: $0) }
        }

        var table = Data()
        append(wide ? FAT_MAGIC_64 : FAT_MAGIC, to: &table)
        append(UInt32(wide ? slices.count : slices.count { !$0.arch.hidden }), to: &table)
        var offset = table.count + slices.count * (wide ? MemoryLayout<fat_arch_64>.size : MemoryLayout<fat_arch>.size)
        var body: [File.Piece] = []
        for slice in slices {
            let start = (offset + (1 << slice.align) - 1) & ~((1 << slice.align) - 1)
            let size = slice.pieces.reduce(0) { $0 + $1.count }
            body.append(.bytes(Data(count: start - offset)))
            body += slice.pieces
            offset = start + size

            append(slice.arch.cpuType, to: &table)
            append(slice.arch.cpuSubtype, to: &table)
            if wide {
                append(UInt64(start), to: &table)
                append(UInt64(size), to: &table)
                append(UInt32(slice.align), to: &table)
                append(UInt32(0), to: &table) // reserved
            } else {
                guard let start = UInt32(exactly: start), let size = UInt32(exactly: size) else {
                    return nil
                }
                append(start, to: &table)
                append(size, to: &table)
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
     architecture) where it once ran `codesign_allocate -r`: it walks the `ncmds` commands the loaders read, the last
     `LC_CODE_SIGNATURE`, `__LINKEDIT` and `LC_SYMTAB` of them its, so a signature command hidden past `ncmds` is none
     to it; `LC_CODE_SIGNATURE` comes out of the load commands, which close up behind it, and the image ends where the
     signature started, or where the string table ends when no more than 12 bytes, the padding that aligns the
     signature, lie between. `__LINKEDIT` ends there too. Throws
     `EditError.signatureNotAtEnd` when the signature does not end the image, give or take the 7 bytes Security lets
     go with it: removing it would cut off what follows.

     Security leaves the vmsize of `__LINKEDIT` as the signature needed it, which `assure_signature_space` rounded up to
     16 KiB, so copies signed by different identities would still differ there: it is rounded as the tool that last
     wrote the segment rounded it, before any signature (`linkeditSizeRounding`).

     Where Security goes astray, the intent is followed instead. It keeps pointers to the commands across the move, so
     when `LC_CODE_SIGNATURE` is not the last command it writes the size of `__LINKEDIT` 16 bytes past a command that
     moved, and reads `LC_SYMTAB` there; it moves the commands by 16 bytes whatever `cmdsize` says, and reads the
     string table's range without swapping it. Security also refuses an image without `__LINKEDIT`, or of a filetype it
     never signs, though what to write is as clear there.
     */
    func removingSignature(end: Int) throws -> (head: Data, end: Int)? {
        let read = self.loadCommands.prefix(self.ncmds)
        guard let command = read.last(where: { $0.cmd == UInt32(LC_CODE_SIGNATURE) }) else {
            return nil
        }
        let data = try command.load(linkedit_data_command.self)
        let signature = (offset: Int(self.sw(data.dataoff)), size: Int(self.sw(data.datasize)))
        guard end - 7 ... end ~= signature.offset + signature.size else {
            throw EditError.signatureNotAtEnd
        }
        // A signature laid over the header and the load commands, which are rewritten below, is no image to give back.
        guard signature.offset >= self.headerSize + self.sizeofcmds else {
            throw EditError.signatureInsideHeaders
        }

        var newEnd = signature.offset
        if let symtab = read.last(where: { $0.cmd == UInt32(LC_SYMTAB) })?.payload(as: symtab_command.self) {
            let strings = Int(self.sw(symtab.stroff)) + Int(self.sw(symtab.strsize))
            if strings < newEnd, newEnd <= strings + 12 {
                newEnd = strings
            }
        }

        // The header and load commands, where a command's data keeps the table's indices, its offsets in the image.
        var head = try self.dataAt(0, count: headerSize + self.sizeofcmds)
        func store<T: FixedWidthInteger>(_ value: T, at offset: Int) {
            head.withUnsafeMutableBytes { $0.storeBytes(of: self.sw(value), toByteOffset: offset, as: T.self) }
        }

        // Its size as Security writes it, wrapping when the segment starts past the new end.
        if let linkedit = read.last(where: { $0.isSegment(named: "__LINKEDIT") }) {
            // Rounding to 1 leaves the size as it is, which is the choice where the rounding cannot be told.
            let page = self.linkeditSizeRounding ?? 1
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
     What `__LINKEDIT`'s vmsize was rounded up to by the tool that last wrote the segment, before a signature, which
     Security's `assure_signature_space` then rounds up to 16 KiB whatever it was, and `remove_signature_space` leaves
     so, as Apple's sources have it:

     - ld64 rounds it up to the page it aligns segments to (`segmentAlignment`): `(address - base + 4095) & -4096` in
       `adjustLinkEditSections` of `MachOWriterExecutable.hpp`, ld64 77.1 to 97.17 (Mac OS X 10.5 to 10.6), then the
       segment alignment of every segment in `HeaderAndLoadCommands.hpp` since ld64 123 (Xcode 4), 16 KiB on arm64;
       cctools' classic `ld` rounded it to the segment alignment as well (`ld/layout.c`);
     - `strip`, which rewrites the segment when it strips an image, sets it to the segment's file size (`misc/strip.c`),
       32-bit and 64-bit alike, from cctools 698 (10.5) through 1009 (Xcode 15.2), and rounds 64-bit up to 16 KiB from
       cctools 1010, which Xcode 15.3 shipped with ld64 1115: the linker's version, which `LC_BUILD_VERSION` records
       (`linkerVersion`), tells the toolchain, where the SDK alone would not, since one builds against older SDKs.

     An image is stripped when its symbol table is as `strip` leaves it (`isStripped`). 1 for the file size as it is.
     An image that records no linker, as one built for macOS 10.13 or earlier does, with `LC_VERSION_MIN_MACOSX` in
     place of `LC_BUILD_VERSION`, or one whose `LC_BUILD_VERSION` names no `TOOL_LD`, is dated by the SDK it was built
     against, Xcode 15.3's being the first to ship cctools 1010. Nil for a stripped 64-bit image that records neither.
     */
    var linkeditSizeRounding: Int? {
        guard self.isStripped else {
            return self.segmentAlignment
        }
        guard self.is64 else {
            return 1
        }
        if let linker = self.linkerVersion {
            return linker >= 0x045b_0000 ? 0x4000 : 1
        }
        guard let version = try? self.version(), let first = Self.firstRoundingSDK[version.platform] else {
            return nil
        }
        return version.sdk >= first ? 0x4000 : 1
    }

    /// The SDKs Xcode 15.3 shipped, by platform: macOS 14.4, iOS and tvOS 17.4, watchOS 10.4, visionOS 1.1, and the
    /// simulators' and Mac Catalyst's the same.
    private static let firstRoundingSDK: [Int32: UInt32] = [
        PLATFORM_MACOS: 0x000e_0400,
        PLATFORM_IOS: 0x0011_0400, PLATFORM_IOSSIMULATOR: 0x0011_0400, PLATFORM_MACCATALYST: 0x0011_0400,
        PLATFORM_TVOS: 0x0011_0400, PLATFORM_TVOSSIMULATOR: 0x0011_0400,
        PLATFORM_WATCHOS: 0x000a_0400, PLATFORM_WATCHOSSIMULATOR: 0x000a_0400,
        11: 0x0001_0100, 12: 0x0001_0100, // visionOS and its simulator
    ]

    /**
     The version of the linker that wrote the image, as `LC_BUILD_VERSION` records it among its tools (`TOOL_LD`),
     X.Y.Z as `0xXXXXYYZZ` like the load commands encode versions; nil without the command, or a linker among its tools.
     */
    var linkerVersion: UInt32? {
        guard
            let command = self.findCommand(UInt32(LC_BUILD_VERSION)),
            let build = command.payload(as: build_version_command.self)
        else {
            return nil
        }
        let header = MemoryLayout<build_version_command>.size
        let entry = MemoryLayout<build_tool_version>.size
        // As many tools as the command holds, whatever ntools claims: a count past them would be walked for nothing.
        let count = min(Int(self.sw(build.ntools)), max(command.data.count - header, 0) / entry)
        for index in 0 ..< count {
            let tool = command.data.dropFirst(header + index * entry).withUnsafeBytes { $0.loadUnaligned(as: build_tool_version.self) }
            if self.sw(tool.tool) == UInt32(TOOL_LD) {
                return self.sw(tool.version)
            }
        }
        return nil
    }

    /**
     Whether the image's symbol table is as `strip` leaves it (`strip_symtab` in cctools' `misc/strip.c`): no local
     symbol but the one `radr://5614542` placeholder `strip` writes when none is left and the image has an indirect
     symbol table, so that no indirect symbol gets the index 0, which dyld reads as the classic linker's bug, so that
     no local symbol beside an indirect symbol table is the linker's doing, not `strip`'s; and in an
     executable, no defined global symbol but those `strip` keeps, the ones referenced dynamically
     (`REFERENCED_DYNAMICALLY`, `__mh_execute_header` as the linker marks it) and the weak definitions, where the
     linker leaves `_main` at least, while a library keeps every global symbol. An executable `strip -x` kept the global
     symbols of passes for the linker's. An image without `LC_DYSYMTAB`, or whose tables do not lie in the image, or
     whose symbol ranges do not lie in the tables, is taken for unstripped: in a universal file, a range past the slice
     would read another slice's bytes.
     */
    var isStripped: Bool {
        guard
            let dysymtab = self.findCommand(UInt32(LC_DYSYMTAB))?.payload(as: dysymtab_command.self),
            let symtab = self.findCommand(UInt32(LC_SYMTAB))?.payload(as: symtab_command.self)
        else {
            return false
        }
        let entry = self.is64 ? MemoryLayout<nlist_64>.size : MemoryLayout<nlist>.size
        let (symoff, nsyms) = (Int(self.sw(symtab.symoff)), Int(self.sw(symtab.nsyms)))
        let (stroff, strsize) = (Int(self.sw(symtab.stroff)), Int(self.sw(symtab.strsize)))
        guard
            symoff <= self.length, nsyms <= (self.length - symoff) / entry,
            stroff <= self.length, strsize <= self.length - stroff
        else {
            return false
        }
        /// The `count` symbols from `first`, when the table holds them.
        func symbols(_ first: UInt32, _ count: Int) -> Data? {
            guard Int(first) <= nsyms, count <= nsyms - Int(first) else {
                return nil
            }
            return try? self.dataAt(symoff + Int(first) * entry, count: count * entry)
        }
        switch self.sw(dysymtab.nlocalsym) {
        case 0:
            guard self.sw(dysymtab.nindirectsyms) == 0 else {
                return false
            }
        case 1:
            let placeholder = Array("radr://5614542".utf8) + [0]
            guard
                let local = symbols(self.sw(dysymtab.ilocalsym), 1),
                let strx = Int(exactly: self.sw(local.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) })),
                strx <= strsize - placeholder.count,
                let name = try? self.dataAt(stroff + strx, count: placeholder.count),
                name.elementsEqual(placeholder)
            else {
                return false
            }
        default:
            return false
        }
        guard self.filetype == UInt32(MH_EXECUTE) else {
            return true
        }
        // What strip keeps a defined global symbol for; n_desc lies where it does in nlist_64 in nlist too. The
        // symbols are read a chunk at a time: a crafted count is the table's at most.
        let kept = UInt16(REFERENCED_DYNAMICALLY | N_WEAK_DEF)
        let desc = MemoryLayout<nlist_64>.offset(of: \.n_desc)!
        let (first, count) = (self.sw(dysymtab.iextdefsym), Int(self.sw(dysymtab.nextdefsym)))
        let batch = File.chunkSize / entry
        for start in stride(from: 0, to: count, by: batch) {
            let read = min(batch, count - start)
            guard let globals = symbols(first &+ UInt32(start), read) else {
                return false
            }
            let stripped = globals.withUnsafeBytes { raw in
                (0 ..< read).allSatisfy { self.sw(raw.loadUnaligned(fromByteOffset: $0 * entry + desc, as: UInt16.self)) & kept != 0 }
            }
            if !stripped {
                return false
            }
        }
        return true
    }

    /**
     The page the linker aligns the image's segments to, and rounds their vmsize up to, unless told otherwise: ld64
     uses 16 KiB for arm64 and `arm64_32`, and for 32-bit ARM but in a kext, 4 KiB for anything else
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
     The alignment `lipo` gives the image in a universal file it creates, as a power of two
     (`Universal::defaultAlignment`): 2^14 for an image mapped on 16 KiB pages, the arm64 family and armv7k, and for
     an arm image dyld manages, a dylib, a bundle or a dynamically linked executable; 2^12 for `x86_64`, `i386` and any
     other; 2^3 for an object and 2^5 for a dSYM. The segments' addresses do not enter into it.
     */
    var universalAlignment: Int {
        switch self.filetype {
        case UInt32(MH_OBJECT):
            return 3
        case UInt32(MH_DSYM):
            return 5
        default:
            break
        }
        if self.uses16KPages {
            return 14
        }
        return self.cpuType == CPU_TYPE_ARM && self.isDyldManaged ? 14 : 12
    }
}
