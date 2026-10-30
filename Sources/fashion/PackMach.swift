import Foundation
import MachO
import zlib

enum UnpackError: Error, Equatable {
    /// UPX's `CantUnpackException`: a Mach-O UPX packed whose packed data, or the image unpacked from it, does not hold,
    /// in UPX's words.
    case cantUnpack(String)
    /// Packed data that decompressed to its end and fails a check after, a sum or the image's headers, in UPX's words
    /// as much; with what decompressed, which `thinr` and `unpack` write as it is under --keep.
    case unverified(String, decompressed: Data)
}

extension UnpackError: LocalizedError {
    var errorDescription: String? {
        switch self {
        case let .cantUnpack(reason), let .unverified(reason, _):
            "Invalid UPX data: \(reason)"
        }
    }
}

/**
 A Mach-O image UPX packed, after UPX's `PackMachBase` (`p_mach.cpp`, UPX 5.2.1, and its development branch for the
 arm64 filter 0x53). `init` mirrors `canUnpack`: it finds the pack header UPX leaves before `__LINKEDIT`, and reads the
 offset of the packed data from it. `unpack()` mirrors `unpack`: it decompresses the image block by block, to the bytes
 `upx -d` writes.

 `init` takes any Mach-O and returns nil for one UPX did not pack. That includes a file UPX would throw on before it
 finds a pack header, for headers or load commands its packer never writes. It also includes a file whose pack header
 pirates overwrote: UPX recovers one by emulating the stub's entry code and scanning for the packed data, which is not
 ported.

 Two tricks of a modified UPX make `upx -d` call the file not packed. Both are seen through, and named in a warning:

 - The "UPX!" marker replaced everywhere it appears. The pack header is found by its structure and checksum where UPX
   looks for it, and the `l_info` before the packed data must confirm it.
 - The segments `canUnpack` goes by renamed: `__XHDR`, `UPX_DATA`, `__TEXT` or `__LINKEDIT`. The kernel loads the
   packed file without dyld, by offsets, and neither it nor the stub reads a segment name, so the file runs as it is.
   The pack header is looked for around the segment lying last in the file, and must confirm itself the same way.

 Packed data that fails its checks, or an unpacked image that does, is refused in red by `thinr` and `unpack`, which
 write what decompressed under --keep. Hash mode hashes every file, so it hashes the file as packed and reports the
 refusal as a warning.

 The packed file, with the offsets of an `x86_64` file UPX 3.91 packed:

 ```text
  0x0000 +-----------------------------------------------+
         | mach_header_64 and the packed file's load     |  __PAGEZERO, __XHDR (3.91), __TEXT, __LINKEDIT,
         | commands; its __TEXT spans everything below   |  LC_UNIXTHREAD or LC_MAIN
  0x02c0 +-----------------------------------------------+
         | l_info (12): l_checksum | l_magic "UPX!" |    |  the marker the stub looks for, whose word init
         |              l_lsize | l_version | l_format   |  takes for a header found without "UPX!"
  0x02cc +-----------------------------------------------+
         | p_info (12): p_progid | p_filesize |          |  <- overlay_offset points here
         |              p_blocksize                      |
  0x02d8 +-----------------------------------------------+
         | b_info (12): sz_unc | sz_cpr | b_method |     |  block 0: the original's Mach-O headers,
         |              b_ftid | b_cto8 | b_unused       |  compressed apart, never filtered
         | sz_cpr bytes of compressed data               |
         +-----------------------------------------------+
         | b_info | block 1: the rest of __TEXT          |  filtered (0x49 on x86_64): what a modified
         +-----------------------------------------------+  stub XORs before it unfilters
         | b_info | block 2: __DATA                      |
         +-----------------------------------------------+
         | b_info | block 3: __LINKEDIT, then the gaps   |  u_adler sums the blocks in this order
  0x663c +-----------------------------------------------+
         | the stub, l_lsize bytes: UPX's decompressor,  |  the entry point lands here
         | unfilter, and the jump to the original's      |
  0x6d05 +-----------------------------------------------+
         | PackHeader (32): "UPX!" | version | format |  |  found by scanning back from the end of __TEXT
         | method | level | u_adler | c_adler | u_len |  |  (3.91) or from before the 16-byte __LINKEDIT
         | c_len | u_file_size | filter | filter_cto |   |  (UPX 5); its checksum skips the four magic
         | n_mru | checksum                              |  bytes
  0x6d25 +-----------------------------------------------+
         | overlay_offset (4) = 0x2cc                    |
  0x6d29 +-----------------------------------------------+
         | zeros to the page                             |  3.91: an empty __LINKEDIT at 0x7000;
  0x7000 +-----------------------------------------------+  UPX 5: 16 bytes of __LINKEDIT instead
 ```

 How `init` tells a packed file, and `unpack` gives the original back:

 ```text
                      thin Mach-O: the file, or a slice of a universal one
                                           |
                                           v
         +---------------------------------------------------------+
         | 1. class: cputype and filetype among UPX's Mach-O       |--- no ---> not packed
         |    packers (x86_64 executable: format 34, 4 KiB page)   |
         +---------------------------------------------------------+
                                           |
                                           v
         +----------------------------------------------------------+
         | 2. layout, the segments walked as canUnpack walks them:  |
         |    __XHDR or __TEXT    -> style 391 (3.91)               |  a segment past the file,
         |    UPX_DATA            -> style 392 (3.92)               |  no style, no offLINK
         |    __LINKEDIT of 16    -> style 395 (3.95 on)            |--------------> not packed
         |    three segments      -> style 392                      |
         |    offLINK: __LINKEDIT's fileoff, or what ends before it |
         |    names that tell nothing, or a window with no header:  |  a modified UPX renamed them;
         |    the segment lying last in the file stands in for      |  the header found is named
         |    __LINKEDIT, the window before it, after it, the end   |  in a warning
         +----------------------------------------------------------+
                                           |
                                           v
    ... blocks | stub | PackHeader | overlay_offset | 0 0 0 0 | __LINKEDIT
                 <---- window: page + 208 + 4 bytes ---->|
                       scanned back from its last non-zero byte, over 32 + 4
                                           |
                                           v
         +---------------------------------------------------------+
         | 3. "UPX!" in the window?                                |
         +----------------------------+----------------------------+
                | yes                                   | no
                v                                       v
    +----------------------------------+   +------------------------------------------+
    | 4. getPackHeader: version 8..13, |   | 5. each offset tried as a header:        |
    |    this format, a known method,  |   |    version 10..13, this format, checksum |
    |    sizes that hold, checksum of  |   |    holding, one chance in 251 * 4 * 10,  |
    |    bytes 4..30 mod 251 at 31     |   |    and l_info, 12 bytes before the       |
    |                                  |   |    overlay, bearing the same marker,     |
    |    fails -> red, in UPX's words  |   |    version and format: the marker named  |
    +----------------------------------+   |    nothing holds -> not packed           |
                |                          +------------------------------------------+
                +-------------------+-------------------+
                                    v
         +---------------------------------------------------------+
         | 6. overlay_offset, after the header, between the load   |--- no ---> "file corrupted"
         |    commands' end and the file's end                     |
         +---------------------------------------------------------+
                                    | packed
                                    v
         +----------------------------------------------------------+
         | unpack: p_info, then each b_info as it is read; a block  |  bad -> "Invalid UPX data: ..."
         | decompressed, XORed with the key if any, then unfiltered |
         | u_adler of the image must be the PackHeader's:           |
         |   as it is         -> the original                       |
         |   under key 1..255 -> the original, key and marker named |  no key -> "Invalid UPX data: checksum error..."
         +----------------------------------------------------------+
 ```

 */
struct PackMach {
    private let image: MachO
    private let format: Class
    /// Where the packed data starts: UPX's `p_info`, then a `b_info` before each block.
    private let overlayOffset: Int
    /// The pack header, as UPX wrote it, and where it lies in the image: for the log, so that the file can be read
    /// by hand.
    private let header: PackHeader
    private let headerOffset: Int
    /// The Adler-32 of the original, block by block as the packer summed it: the pack header's `u_adler`.
    private let uAdler: UInt32
    /// The Adler-32 of the packed bytes, block by block as the packer summed them: the pack header's `c_adler`.
    private let cAdler: UInt32
    /// What packed the image: UPX, or a modified UPX, the marker it bears in place of "UPX!" and the segment it
    /// renamed named.
    let packer: String
    /// Whether a modified UPX packed the image, by its marker or its segments' names.
    private let modified: Bool

    /// A packer class UPX unpacks Mach-O with: its CPU, filetype, format id and page.
    private struct Class {
        let cpuType: cpu_type_t
        let filetype: UInt32
        let format: UInt8
        let pageShift: Int
    }

    /// The classes UPX visits to unpack Mach-O (`packmast.cpp`), with those `PackMachFat` uses for slices.
    private static let classes = [
        Class(cpuType: CPU_TYPE_I386, filetype: UInt32(MH_EXECUTE), format: 29, pageShift: 12),
        Class(cpuType: CPU_TYPE_I386, filetype: UInt32(MH_DYLIB), format: 33, pageShift: 12),
        Class(cpuType: CPU_TYPE_ARM, filetype: UInt32(MH_EXECUTE), format: 32, pageShift: 12),
        Class(cpuType: CPU_TYPE_X86_64, filetype: UInt32(MH_EXECUTE), format: 34, pageShift: 12),
        Class(cpuType: CPU_TYPE_X86_64, filetype: UInt32(MH_DYLIB), format: 35, pageShift: 12),
        Class(cpuType: CPU_TYPE_ARM64, filetype: UInt32(MH_EXECUTE), format: 37, pageShift: 14),
        Class(cpuType: CPU_TYPE_POWERPC, filetype: UInt32(MH_EXECUTE), format: 131, pageShift: 12),
        Class(cpuType: CPU_TYPE_POWERPC, filetype: UInt32(MH_DYLIB), format: 138, pageShift: 12),
        Class(cpuType: CPU_TYPE_POWERPC64, filetype: UInt32(MH_EXECUTE), format: 139, pageShift: 16),
        Class(cpuType: CPU_TYPE_POWERPC64, filetype: UInt32(MH_DYLIB), format: 142, pageShift: 16),
    ]

    /// The most load commands UPX takes (`MAX_N_CMDS`).
    private static let maxCommands = 256
    /// The largest file UPX packs, and so the largest it unpacks to (`UPX_RSIZE_MAX`): the image is made in memory.
    private static let maxSize = 768 << 20

    // MARK: - canUnpack

    /**
     The image UPX packed, as `canUnpack` finds it: its segments tell where UPX put its pack header (UPX 3.91 before
     `__LINKEDIT`, 3.92 after the loader in it, 3.95 on before a 16-byte `__LINKEDIT`), whose checksum must hold and
     whose format must be the image's. Where the segments' names tell nothing, a modified UPX having renamed them,
     the pack header is looked for around the segment lying last in the file, and must vouch for itself. Nil when
     UPX did not pack it; throws for a pack header that does not hold.
     */
    init?(_ image: MachO) throws {
        guard
            let format = Self.classes.first(where: { $0.cpuType == image.cpuType && $0.filetype == image.filetype }),
            image.is64 == (image.cpuType & CPU_ARCH_ABI64 != 0)
        else {
            return nil
        }
        let headerSize = image.is64 ? MemoryLayout<mach_header_64>.size : MemoryLayout<mach_header>.size
        let header = try image.dataAt(0, count: headerSize)
        let ncmds = Int(image.word(header, at: 16))
        let headway = image.sizeofcmds
        let segmentSize = image.is64 ? MemoryLayout<segment_command_64>.size : MemoryLayout<segment_command>.size
        guard
            1 ... Self.maxCommands ~= ncmds,
            16 ... image.length ~= headway,
            ncmds != 2 || headway >= segmentSize + 16,
            ncmds < 3 || headway >= 3 * segmentSize + MemoryLayout<entry_point_command>.size,
            image.loadCommands.count >= ncmds
        else {
            return nil
        }

        var style = 0
        var offLINK = 0
        var posNext = 0
        var segments = 0
        var text: Segment?
        // The segment lying last in the file, and where the one before it ends: UPX's __LINKEDIT, whatever a modified
        // UPX named it.
        var last: (segment: Segment, before: Int)?
        for command in image.loadCommands.prefix(ncmds) {
            guard let segment = Segment(command, in: image) else {
                continue
            }
            guard
                segment.fileoff <= image.length,
                segment.filesize <= image.length - segment.fileoff
            else {
                return nil
            }
            segments += 1
            switch segment.name {
            case "__XHDR":
                style = 391
            case "__TEXT":
                text = segment
                style = 391
            case "UPX_DATA":
                style = 392
            case "__LINKEDIT":
                offLINK = max(segment.fileoff, posNext)
                if segment.filesize == 16 {
                    style = 395
                }
            default:
                break
            }
            if last.map({ segment.fileoff >= $0.segment.fileoff }) ?? true {
                last = (segment, posNext)
            }
            posNext = segment.fileoff + segment.filesize
        }
        if segments == 3, style != 395 {
            style = 392
        }
        if style == 391, offLINK == 0, ncmds == 2, let text {
            offLINK = text.fileoff + text.filesize
        }

        // A page and the pack header after it, then the overlay offset, read back from where UPX left them, in the
        // window UPX reads: the page, `sizeof(PackHeader)`, the 208 bytes of the object it decodes the header into
        // rather than the 32 it wrote, and the offset's 4. The scan below steps back from the last byte that is not
        // zero, the offset's, over the header's 32 bytes and the offset's 4, and gives up at the window's first byte,
        // as UPX does at its own, 176 bytes earlier: a window a page and 36 bytes long gave up on a header that a page
        // less 3 bytes of zeros followed, which `upx -d` unpacks. UPX reads before the file's start for a __TEXT
        // shorter than that, and gives up, where the window starts there instead.
        let small = 32 + 4
        let count = (1 << format.pageShift) + 208 + 4

        // A window to read the pack header back from, and where it lies for the warning when no segment name said.
        typealias Window = (start: Int, count: Int, found: String?)
        var windows: [Window] = []

        func before(_ offLINK: Int, found: String?) -> Window {
            let start = offLINK - count
            return start < 0 ? (0, count + start, found) : (start, count, found)
        }

        func after(_ offLINK: Int, found: String?) -> Window? {
            // UPX gives up here ("bad offLINK"); a __LINKEDIT this short is a linker's, in an image it never packed.
            let count = min(count, image.length - offLINK)
            return count >= 12 ? (offLINK, count, found) : nil
        }

        // The window the segment names lead to, as canUnpack reads it.
        if style != 0, offLINK != 0 {
            if style != 392 {
                windows.append(before(offLINK, found: nil))
            } else if image.filetype == MH_DYLIB {
                windows.append(before(image.length, found: nil))
            } else if let window = after(offLINK, found: nil) {
                windows.append(window)
            }
        }

        // Where the names lead nowhere, or to a window without a pack header, as a modified UPX's do once it names
        // its segments otherwise, whose files load and run as they are: the segment lying last in the file stands in
        // for __LINKEDIT, and the pack header is looked for where each layout UPX has used puts it, before the
        // segment, after it, and for a dylib at the file's end. The header's structure and checksum, then the l_info
        // before the packed data, vouch for what is found, as they do for a header without its marker. Not in an
        // image signed after packing, whose signature grew the 16-byte __LINKEDIT and so moved the named window off
        // the header: the callers look at such an image without its signature, where the names tell again.
        if let last, image.findCommand(UInt32(LC_CODE_SIGNATURE)) == nil {
            let name = Self.quoted(Array(last.segment.name.utf8))
            let offLINK = max(last.segment.fileoff, last.before)
            var candidates = [before(offLINK, found: "before its last segment \(name)")]
            if let window = after(offLINK, found: "after its last segment \(name)") {
                candidates.append(window)
            }
            if image.filetype == MH_DYLIB {
                candidates.append(before(image.length, found: "at the file's end"))
            }
            windows += candidates.filter { candidate in !windows.contains { $0.start == candidate.start && $0.count == candidate.count } }
        }

        var found: (header: PackHeader, offset: Int, overlayOffset: Int, where: String?)?
        for window in windows where found == nil && window.count > small {
            let data = try image.dataAt(window.start, count: window.count)
            // The pack header ends where the zeros that pad __TEXT to its page begin.
            var i = data.count
            while i > small {
                i -= 1
                if data[data.startIndex + i] != 0 {
                    break
                }
            }
            i -= small
            guard i >= 1 else {
                continue
            }
            let packHeader: PackHeader?
            do {
                packHeader = try PackHeader(data.dropFirst(i), fileSize: image.length, format: format.format)
            } catch where window.found != nil {
                // A marker that holds nothing, in a window the segments' names did not lead to, which UPX never
                // reads: no pack header there, as an image of its own may carry the four bytes.
                continue
            }
            guard let packHeader, packHeader.format == format.format else {
                continue
            }

            let at = i + packHeader.offset + packHeader.size
            let overlayOffset = at + 4 <= data.count ? Int(image.word(data, at: at)) : 0
            if packHeader.magic != PackHeader.magic {
                // Found without its marker, the pack header needs the word of UPX's `l_info`, the 12 bytes before the
                // packed data, inside the image: its marker, version and format must be the header's, as the packer
                // wrote them.
                guard
                    overlayOffset >= headerSize + headway + 12,
                    overlayOffset <= image.length,
                    let lInfo = try? image.dataAt(overlayOffset - 12, count: 12),
                    lInfo.dropFirst(4).prefix(4).elementsEqual(packHeader.magic),
                    lInfo[lInfo.startIndex + 10] == packHeader.version,
                    lInfo[lInfo.startIndex + 11] == packHeader.format
                else {
                    continue
                }
            }
            found = (packHeader, window.start + i + packHeader.offset, overlayOffset, window.found)
        }
        guard let found else {
            return nil
        }

        let (packHeader, overlayOffset) = (found.header, found.overlayOffset)
        guard (headerSize + headway) ..< image.length ~= overlayOffset else {
            throw UnpackError.cantUnpack("file corrupted")
        }

        var signs: [String] = []
        if packHeader.magic != PackHeader.magic {
            signs.append("its marker \(Self.quoted(packHeader.magic)) in place of \"UPX!\"")
        }
        if let renamed = found.where {
            signs.append("a segment renamed, its pack header found \(renamed)")
        }
        let modified = !signs.isEmpty
        let packer = modified ? "packed by a modified UPX, " + signs.joined(separator: " and ") : "packed by UPX"

        self.image = image
        self.format = format
        self.overlayOffset = overlayOffset
        self.header = packHeader
        self.headerOffset = found.offset
        self.uAdler = packHeader.uAdler
        self.cAdler = packHeader.cAdler
        self.packer = packer
        self.modified = modified
    }

    /// `bytes` quoted, a quote or backslash among them escaped, when they all print; hexadecimal otherwise.
    private static func quoted(_ bytes: [UInt8]) -> String {
        bytes.allSatisfy { 0x20 ... 0x7e ~= $0 } ? String(decoding: bytes, as: UTF8.self).debugDescription : "0x" + bytes.map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - unpack

    /**
     The image UPX packed, as `unpack` writes it: its Mach-O headers come first, then each segment from its offset, in
     the order of their offsets, then what lies between them and after the last up to the original size; a dylib's
     segments but the first are copied as they are. With it, a word on the image when a modified UPX packed it: the
     marker it bears in place of "UPX!", the byte its filtered blocks are XORed with before they are unfiltered, or
     both; and words for the log, `notes`, on how it was packed and where its parts lie. Throws for packed data that
     does not hold.

     The packed bytes must bear the Adler-32 the pack header holds of them, `c_adler`, and the image the one it holds
     of the original, `u_adler`, neither of which `upx -d` checks for a Mach-O, where it checks both for an ELF. Packed
     bytes that fail theirs are damaged, which no key undoes: refused, in UPX's words, both sums named. A modified UPX may XOR the
     blocks it filtered with a byte before they are unfiltered, as the UPX 3.91 behind OSX/Keydnap did, which unfilter
     to a wrong image without it: the key is the byte, tried in turn over the filtered blocks as decoded, decoded
     once, under which the image bears its checksum. An image that bears it under no key is refused as much, in red,
     its sum and the header's named with the packer. Either refusal carries what decompressed, as it is, for --keep to
     write.
     */
    func unpack() throws -> (data: Data, caveat: String?, notes: [String]) {
        var plain = try self.unpack(keeping: false)
        guard plain.cAdler == self.cAdler else {
            throw UnpackError.unverified("checksum error: the packed bytes sum to \(plain.cAdler.hex), the pack header says \(self.cAdler.hex)", decompressed: plain.data)
        }
        if plain.adler == self.uAdler {
            return (plain.data, self.caveat(xor: 0), self.notes(plain))
        }
        let refusal = "checksum error on the unpacked image, \(self.packer): it sums to \(plain.adler.hex), the pack header says \(self.uAdler.hex)"
        guard plain.filtered else {
            throw UnpackError.unverified(refusal, decompressed: plain.data)
        }
        // Decoded once more, the filtered blocks kept as decoded, so each key is tried over them alone; the
        // first image goes first, so no more than the second and the kept blocks are held at once.
        plain.data = Data()
        var keyed = try self.unpack(keeping: true)
        for key in UInt8(1) ... 255 {
            if try keyed.keyed(key) == self.uAdler {
                return (keyed.data, self.caveat(xor: key), self.notes(keyed))
            }
        }
        // What decompressed as it is, the blocks under no key again, for --keep to write.
        _ = try keyed.keyed(0)
        throw UnpackError.unverified(refusal + ", under no XOR key", decompressed: keyed.data)
    }

    /**
     How the image was packed, for the log, a line each: its size from the packed image's, the pack header's version
     and format, the methods of its blocks and their filters, "68640 bytes from 30688, pack header version 13 for
     format 34, NRV2E, filter 0x49"; then where the parts lie, to read the file by hand: the pack header, field by
     field, `l_info` and `p_info`, and each block, where its `b_info` lies, what it holds and where it is written in
     the image. Offsets count from the image's start, and from the file's when the image is a slice of a universal
     file.
     */
    private func notes(_ unpacked: Unpacked) -> [String] {
        let methods = unpacked.methods.sorted().map(Self.methodName).joined(separator: ", ")
        let filters = unpacked.filters.isEmpty ? "no filter" : "filter \(unpacked.filters.sorted().map { String(format: "0x%02x", $0) }.joined(separator: ", "))"
        let header = self.header
        let at = { (offset: Int) in self.image.offset == 0 ? offset.hex : "\(offset.hex) (\((self.image.offset + offset).hex) in the file)" }
        var notes = [
            "\(String(unpacked.data.count, pluralizing: "byte")) from \(self.image.length), pack header version \(header.version) for format \(header.format), \(methods), \(filters)",
            "pack header at \(at(self.headerOffset)), \(header.size) bytes: marker \(Self.quoted(header.magic)), version \(header.version), format \(header.format), method \(header.method) (\(Self.methodName(header.method))), level \(header.level), u_adler \(header.uAdler.hex), c_adler \(header.cAdler.hex), u_len \(header.uncompressed), c_len \(header.compressed), u_file_size \(header.uFileSize), filter \(String(format: "0x%02x", header.filter)), cto \(String(format: "0x%02x", header.cto)), n_mru \(header.nMru), checksum \(String(format: "0x%02x", header.checksum)), then overlay_offset \(self.overlayOffset.hex)",
            "l_info at \(at(self.overlayOffset - 12)), p_info at \(at(self.overlayOffset)): p_progid \(unpacked.pInfo.progid.hex), p_filesize \(unpacked.pInfo.fileSize), p_blocksize \(unpacked.pInfo.blocksize.hex); the blocks follow, each after its 12-byte b_info",
        ]
        for (index, block) in unpacked.blocks.enumerated() {
            let how = block.info.compressed < block.info.uncompressed ? "\(Self.methodName(block.info.method)) (method \(block.info.method)), \(block.info.filter == 0 ? "no filter" : "filter \(String(format: "0x%02x", block.info.filter)), cto \(String(format: "0x%02x", block.info.cto))")" : "stored as is"
            notes.append("block \(index + 1), b_info at \(at(block.offset)): \(String(block.info.compressed, pluralizing: "packed byte")) at \(at(block.offset + 12)) to \(block.info.uncompressed) at \(block.at.hex) of the image, \(how)")
        }
        return notes
    }

    /// UPX's name for a compression method, `M_NRV2B_LE32` and the rest by family, `M_LZMA`.
    private static func methodName(_ method: UInt8) -> String {
        switch method {
        case 2 ... 4: "NRV2B"
        case 5 ... 7: "NRV2D"
        case 8 ... 10: "NRV2E"
        case 14: "LZMA"
        default: "method \(method)"
        }
    }

    /// The word on the image for a modified UPX: its marker, the `key` its filtered blocks are XORed with, or both;
    /// nil for UPX's own.
    private func caveat(xor key: UInt8) -> String? {
        let xor = key == 0 ? nil : "its filtered blocks XORed with 0x\(String(format: "%02x", key)) before they are unfiltered"
        return switch (self.modified, xor) {
        case (false, nil): nil
        case (true, nil): self.packer
        case (false, let xor?): "packed by a modified UPX, \(xor)"
        case (true, let xor?): "\(self.packer) and \(xor)"
        }
    }

    /// An image unpacked, with what the pass over its blocks summed and saw, and the `p_info` before the blocks.
    private struct Unpacked {
        var data: Data
        var pass: Pass
        let pInfo: (progid: UInt32, fileSize: Int, blocksize: Int)

        var blocks: [Block] {
            self.pass.blocks
        }

        /// The Adler-32 of the image as the packer summed it, block by block in the order they were unpacked.
        var adler: UInt32 {
            UInt32(self.pass.sums.reduce(1 as uLong) { adler32_combine($0, uLong($1.adler), $1.count) })
        }

        var cAdler: UInt32 {
            self.pass.cAdler
        }

        var filtered: Bool {
            self.pass.filtered
        }

        var methods: Set<UInt8> {
            self.pass.methods
        }

        var filters: Set<UInt8> {
            self.pass.filters
        }

        /**
         The image with its filtered blocks, kept as decoded, XORed with `key` and unfiltered again in place of
         what the last key made of them, and its Adler-32 so: no block is decoded again for a key.
         */
        mutating func keyed(_ key: UInt8) throws -> UInt32 {
            for kept in self.pass.kept {
                let sum = try self.data.withUnsafeMutableBytes { buffer in
                    let destination = UnsafeMutableRawBufferPointer(rebasing: buffer[kept.at ..< kept.at + kept.decoded.count])
                    kept.decoded.withUnsafeBytes { destination.copyMemory(from: $0) }
                    for index in destination.indices {
                        destination[index] ^= key
                    }
                    try PackMach.unfilter(destination, id: kept.filter, cto: kept.cto)
                    return UInt32(adler32(1, destination.baseAddress!.assumingMemoryBound(to: Bytef.self), uInt(destination.count)))
                }
                self.pass.sums[kept.index].adler = sum
            }
            return self.adler
        }
    }

    /**
     The image unpacked, the Adler-32 of its packed bytes and of each block as unpacked, block by block as the packer
     summed them, whether a block was unfiltered, the methods and filters the blocks were packed with and, when
     `keeping`, the filtered blocks as decoded, for `Unpacked.keyed` to try the keys a modified UPX may have XORed
     them with.
     */
    private func unpack(keeping: Bool) throws -> Unpacked {
        let pInfo = try self.read(at: self.overlayOffset, count: 12)
        let progid = self.image.word(pInfo, at: 0)
        let fileSize = Int(self.image.word(pInfo, at: 4))
        let blocksize = Int(self.image.word(pInfo, at: 8))
        guard
            blocksize <= fileSize,
            fileSize <= Self.maxSize
        else {
            throw UnpackError.cantUnpack("file header corrupted")
        }

        // The first block, the image's Mach-O headers, read ahead for its load commands: a block of the first segment,
        // so no larger than a block, which UPX does not check before it allocates it.
        let headerSize = self.image.is64 ? MemoryLayout<mach_header_64>.size : MemoryLayout<mach_header>.size
        let blocks = self.overlayOffset + 12
        let first = try self.blockInfo(at: blocks)
        guard
            first.compressed > 0,
            first.compressed <= self.image.length,
            first.uncompressed >= headerSize,
            first.uncompressed <= blocksize,
            2 ... 17 ~= first.method
        else {
            throw UnpackError.cantUnpack("file header corrupted")
        }
        guard first.compressed <= first.uncompressed else {
            throw UnpackError.cantUnpack("header corrupted")
        }

        // The block is decoded into a buffer of its own, up to the block size, which the commands copy their bytes out
        // of, so that it goes before the image is made rather than stay beside it.
        let commands: [Command]
        do {
            var headers = Data(count: first.uncompressed)
            try headers.withUnsafeMutableBytes { try Self.decompress(self.block(at: blocks + 12, count: first.compressed), count: first.compressed, method: first.method, into: $0) }
            let packedHeader = try self.image.dataAt(0, count: 16)
            guard headers.prefix(16).elementsEqual(packedHeader.prefix(16)) else {
                throw UnpackError.cantUnpack("file header corrupted")
            }
            let ncmds = Int(self.image.word(headers, at: 16))
            guard 1 ... Self.maxCommands ~= ncmds else {
                throw UnpackError.cantUnpack("bad Mach_header.ncmds = \(ncmds)")
            }
            commands = try self.commands(in: headers, from: headerSize, count: ncmds)
        }
        let segments = commands.compactMap(\.segment).sorted(by: Segment.precedes)

        // UPX writes a segment wherever its headers place it; it must lie in the image made here.
        guard segments.allSatisfy({ $0.filesize == 0 || ($0.fileoff <= fileSize && $0.filesize <= fileSize - $0.fileoff) }) else {
            throw UnpackError.cantUnpack("file header corrupted")
        }

        var output = Data(count: fileSize)
        var cursor = blocks
        var pass = Pass(keeping: keeping)
        pass.methods.insert(first.method)
        for segment in segments where segment.filesize != 0 {
            try self.unpackExtent(segment.filesize, into: &output, at: segment.fileoff, cursor: &cursor, blocksize: blocksize, pass: &pass)
            if self.image.filetype == MH_DYLIB {
                break
            }
        }

        if self.image.filetype == MH_DYLIB {
            try self.copyDylibSegments(commands, into: &output)
        } else {
            for (index, segment) in segments.enumerated() where segment.filesize != 0 {
                let gap = Self.gap(after: index, in: segments, end: fileSize)
                if gap > 0 {
                    try self.unpackExtent(gap, into: &output, at: segment.fileoff + segment.filesize, cursor: &cursor, blocksize: blocksize, pass: &pass)
                }
            }
        }

        return Unpacked(data: output, pass: pass, pInfo: (progid, fileSize, blocksize))
    }

    // MARK: - Private

    /// A segment command's fields, as UPX sorts and writes segments by them.
    private struct Segment {
        let name: String
        let vmaddr: UInt64
        let vmsize: UInt64
        let fileoff: Int
        let filesize: Int
        let cmdsize: Int
        let maxprot: Int32
        let initprot: Int32
        let nsects: UInt32
        let flags: UInt32
        /// The load command, for a dylib's segments.
        let data: Data

        /// The segment `command` holds, in the image's layout; nil for any other command, or one too short.
        init?(_ command: MachO.LoadCommand, in image: MachO) {
            let name = String(decoding: command.data.dropFirst(8).prefix(16).prefix { $0 != 0 }, as: UTF8.self)
            if image.is64, command.cmd == UInt32(LC_SEGMENT_64), let segment = command.payload(as: segment_command_64.self) {
                (self.vmaddr, self.vmsize) = (image.sw(segment.vmaddr), image.sw(segment.vmsize))
                (self.fileoff, self.filesize) = (Int(clamping: image.sw(segment.fileoff)), Int(clamping: image.sw(segment.filesize)))
                (self.maxprot, self.initprot) = (image.sw(segment.maxprot), image.sw(segment.initprot))
                (self.nsects, self.flags) = (image.sw(segment.nsects), image.sw(segment.flags))
            } else if !image.is64, command.cmd == UInt32(LC_SEGMENT), let segment = command.payload(as: segment_command.self) {
                (self.vmaddr, self.vmsize) = (UInt64(image.sw(segment.vmaddr)), UInt64(image.sw(segment.vmsize)))
                (self.fileoff, self.filesize) = (Int(image.sw(segment.fileoff)), Int(image.sw(segment.filesize)))
                (self.maxprot, self.initprot) = (image.sw(segment.maxprot), image.sw(segment.initprot))
                (self.nsects, self.flags) = (image.sw(segment.nsects), image.sw(segment.flags))
            } else {
                return nil
            }
            self.name = name
            self.cmdsize = command.data.count
            self.data = command.data
        }

        /// UPX's order (`compare_segment_command`): by offset, then address, a segment with a size first, then the
        /// remaining fields, so the order is the same everywhere.
        static func precedes(_ a: Segment, _ b: Segment) -> Bool {
            if a.fileoff != b.fileoff {
                return a.fileoff < b.fileoff
            }
            if a.vmaddr != b.vmaddr {
                return a.vmaddr < b.vmaddr
            }
            if (a.vmsize != 0) != (b.vmsize != 0) {
                return a.vmsize != 0
            }
            let lhs = (a.vmsize, a.cmdsize, a.filesize, a.maxprot, a.initprot, a.nsects)
            let rhs = (b.vmsize, b.cmdsize, b.filesize, b.maxprot, b.initprot, b.nsects)
            return lhs != rhs ? lhs < rhs : a.flags < b.flags
        }
    }

    /// A load command of the packed image's own headers: its segment, if it is one.
    private struct Command {
        let segment: Segment?
    }

    /// A pass over the blocks: the Adler-32 of their packed bytes as the packer summed them, of each block as unpacked,
    /// in order, how many bytes they made so far, and whether one was unfiltered.
    private struct Pass {
        /// Whether a filtered block is kept as it decoded, before it is unfiltered, for the keys to be tried over it.
        let keeping: Bool
        var cAdler: UInt32 = 1
        var filtered = false
        var produced = 0
        /// Each block's Adler-32 and length, in order, which the image's sum combines.
        var sums: [(adler: UInt32, count: Int)] = []
        /// The filtered blocks as decoded, when `keeping`: which block, where it lies in the image, and its filter.
        var kept: [(index: Int, at: Int, filter: UInt8, cto: UInt8, decoded: Data)] = []
        /// The compression methods and filters of the blocks seen, for the log, and the blocks themselves.
        var methods: Set<UInt8> = []
        var filters: Set<UInt8> = []
        var blocks: [Block] = []
    }

    /// A block as the pass met it: where its `b_info` lies in the packed image, what it says, and where the block is
    /// written in the unpacked image.
    private struct Block {
        let offset: Int
        let info: BlockInfo
        let at: Int
    }

    /// A `b_info`, the header before each block: its sizes, compression method and filter.
    private struct BlockInfo {
        let uncompressed: Int
        let compressed: Int
        let method: UInt8
        let filter: UInt8
        let cto: UInt8
    }

    /**
     A block of `count` bytes of packed data at `offset`, with `UCLBridge.slack` bytes after it, the image's where it
     holds them and zeros where the block ends it: what UCL's decoders may read past the block, as UPX's buffer lets
     them.
     */
    private func block(at offset: Int, count: Int) throws -> Data {
        let slack = UCLBridge.slack
        if count <= self.image.length - offset - slack {
            return try self.read(at: offset, count: count + slack)
        }
        return try self.read(at: offset, count: count) + Data(count: slack)
    }

    /// `count` bytes of the packed image at `offset`, which must hold them.
    private func read(at offset: Int, count: Int) throws -> Data {
        guard
            offset >= 0,
            count >= 0,
            count <= self.image.length - offset
        else {
            throw UnpackError.cantUnpack("file header corrupted")
        }
        return try self.image.dataAt(offset, count: count)
    }

    private func blockInfo(at offset: Int) throws -> BlockInfo {
        let data = try self.read(at: offset, count: 12)
        // UPX reads the sizes as int: one past 2 GiB is negative, which no block is.
        let uncompressed = Int(Int32(bitPattern: self.image.word(data, at: 0)))
        let compressed = Int(Int32(bitPattern: self.image.word(data, at: 4)))
        let bytes = data.dropFirst(8)
        return BlockInfo(uncompressed: uncompressed, compressed: compressed, method: bytes[bytes.startIndex], filter: bytes[bytes.startIndex + 1], cto: bytes[bytes.startIndex + 2])
    }

    /**
     The load commands of the decompressed headers, as `unpack` walks them, each a copy of its bytes: each must fit what
     is left of them.
     */
    private func commands(in headers: Data, from start: Int, count: Int) throws -> [Command] {
        var commands: [Command] = []
        var offset = start
        for _ in 0 ..< count {
            guard offset + 8 <= headers.count else {
                throw UnpackError.cantUnpack("bad packed Mach load_command")
            }
            let cmd = self.image.word(headers, at: offset)
            let cmdsize = Int(self.image.word(headers, at: offset + 4))
            guard
                cmdsize >= 8,
                cmdsize <= headers.count - offset
            else {
                throw UnpackError.cantUnpack("bad packed Mach load_command @\(offset.hex)")
            }
            let command = MachO.LoadCommand(cmd: cmd, data: headers.subdata(in: offset ..< offset + cmdsize))
            commands.append(Command(segment: Segment(command, in: self.image)))
            offset += cmdsize
        }
        return commands
    }

    /**
     Decompress blocks into `output` at `offset` until they make `wanted` bytes, as `unpackExtent` does: a block whose
     compressed size is its size is stored as it is, any other is decompressed by its method where it goes, then
     unfiltered there; each is summed into `pass`, its packed bytes and its own. The blocks of every extent together
     make no more than the image, `p_filesize`: extents laid over one another by crafted headers would decode the
     image's worth of blocks each, up to 255 times, where UPX writes each byte of the original once.
     */
    private func unpackExtent(_ wanted: Int, into output: inout Data, at offset: Int, cursor: inout Int, blocksize: Int, pass: inout Pass) throws {
        var wanted = wanted
        var offset = offset
        while wanted > 0 {
            let info = try self.blockInfo(at: cursor)
            guard
                info.uncompressed > 0,
                info.compressed > 0,
                info.method <= 14,
                info.compressed <= info.uncompressed,
                info.uncompressed <= blocksize,
                info.uncompressed <= wanted,
                info.uncompressed <= output.count - offset
            else {
                throw UnpackError.cantUnpack("corrupt b_info")
            }
            guard info.uncompressed <= output.count - pass.produced else {
                throw UnpackError.cantUnpack("the blocks make more than p_filesize bytes")
            }
            let block = try self.block(at: cursor + 12, count: info.compressed)
            pass.blocks.append(Block(offset: cursor, info: info, at: offset))
            cursor += 12 + info.compressed
            pass.cAdler = block.prefix(info.compressed).withUnsafeBytes { UInt32(adler32(uLong(pass.cAdler), $0.baseAddress!.assumingMemoryBound(to: Bytef.self), uInt(info.compressed))) }
            if info.compressed < info.uncompressed {
                pass.methods.insert(info.method)
                try output.withUnsafeMutableBytes { buffer in
                    let destination = UnsafeMutableRawBufferPointer(rebasing: buffer[offset ..< offset + info.uncompressed])
                    try Self.decompress(block, count: info.compressed, method: info.method, into: destination)
                    if info.filter != 0 {
                        pass.filtered = true
                        pass.filters.insert(info.filter)
                        if pass.keeping {
                            pass.kept.append((pass.sums.count, offset, info.filter, info.cto, Data(destination)))
                        }
                        try Self.unfilter(destination, id: info.filter, cto: info.cto)
                    }
                }
            } else {
                output.replaceSubrange(offset ..< offset + info.uncompressed, with: block.prefix(info.compressed))
            }
            let sum = output.withUnsafeBytes { UInt32(adler32(1, $0.baseAddress!.advanced(by: offset).assumingMemoryBound(to: Bytef.self), uInt(info.uncompressed))) }
            pass.sums.append((sum, info.uncompressed))
            pass.produced += info.uncompressed
            offset += info.uncompressed
            wanted -= info.uncompressed
        }
    }

    /**
     The bytes between segment `index` and the segment that follows it in the file, or `end` (`find_SEGMENT_gap`).
     */
    private static func gap(after index: Int, in segments: [Segment], end: Int) -> Int {
        let high = segments[index].fileoff + segments[index].filesize
        let low = segments.filter { $0.filesize != 0 && $0.fileoff >= high }.map(\.fileoff).min() ?? end
        return max(0, min(low, end) - high)
    }

    /**
     A dylib's segments after the first, which UPX leaves uncompressed where they lie in the packed image: copied to
     where the original headers place them, the pointer in `__mod_init_func`, which UPX points at its loader, restored.
     */
    private func copyDylibSegments(_ commands: [Command], into output: inout Data) throws {
        let packed = self.image.loadCommands
        guard packed.count == commands.count else {
            throw UnpackError.cantUnpack("file header corrupted")
        }
        for (raw, original) in zip(packed, commands).dropFirst() {
            guard
                let rc = Segment(raw, in: self.image),
                let sc = original.segment,
                rc.filesize != 0
            else {
                continue
            }
            var data = try self.read(at: rc.fileoff, count: rc.filesize)
            if rc.name == "__DATA", let (offset, pointer) = try self.modInitFunc(in: rc) {
                let original = try self.read(at: Int(clamping: pointer) - 16, count: 4)
                let at = offset - rc.fileoff
                guard
                    at >= 0,
                    at + 4 <= data.count
                else {
                    throw UnpackError.cantUnpack("bad __mod_init_func")
                }
                data.replaceSubrange(data.startIndex + at ..< data.startIndex + at + 4, with: original)
            }
            guard
                sc.fileoff >= 0,
                rc.filesize <= output.count - sc.fileoff
            else {
                throw UnpackError.cantUnpack("file header corrupted")
            }
            output.replaceSubrange(sc.fileoff ..< sc.fileoff + rc.filesize, with: data)
        }
    }

    /// The offset of a pointer-sized `__mod_init_func` section in `segment`, and the pointer there (`get_mod_init_func`).
    private func modInitFunc(in segment: Segment) throws -> (offset: Int, pointer: UInt64)? {
        let sectionSize = self.image.is64 ? MemoryLayout<section_64>.size : MemoryLayout<section>.size
        let pointerSize = self.image.is64 ? 8 : 4
        var at = (self.image.is64 ? MemoryLayout<segment_command_64>.size : MemoryLayout<segment_command>.size)
        while at + sectionSize <= segment.cmdsize {
            let section = segment.data.bytes(in: at ..< at + sectionSize)
            let size = self.image.is64 ? Int(clamping: self.image.sw(section.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 40, as: UInt64.self) })) : Int(self.image.word(section, at: 36))
            if size == pointerSize, MachO.field(section.prefix(16), is: "__mod_init_func") {
                let offset = Int(self.image.word(section, at: self.image.is64 ? 48 : 40))
                let pointer = try self.read(at: offset, count: pointerSize)
                return (offset, self.image.is64 ? self.image.sw(pointer.withUnsafeBytes { $0.loadUnaligned(as: UInt64.self) }) : UInt64(self.image.word(pointer, at: 0)))
            }
            at += sectionSize
        }
        return nil
    }

    // MARK: - Decompression (compress.cpp)

    /**
     The first `count` bytes of `data`, a block with its slack after it, decompressed by UPX method `method` into
     `destination`, which it must fill: NRV2B, NRV2D and NRV2E by UCL (`UCLBridge`), LZMA by the LZMA SDK
     (`LZMABridge`).
     */
    private static func decompress(_ data: Data, count: Int, method: UInt8, into destination: UnsafeMutableRawBufferPointer) throws {
        let decompressed = data.withUnsafeBytes { source in
            method == 14 ? LZMABridge.decompress(UnsafeRawBufferPointer(rebasing: source.prefix(count)), into: destination) : UCLBridge.decompress(source, count: count, method: method, into: destination) ?? false
        }
        guard decompressed else {
            throw UnpackError.cantUnpack("compressed data violation")
        }
    }

    // MARK: - Filters (filter_impl.cpp)

    /**
     Undo the filter UPX applied to a block before compressing it, to make branch targets repeat: the x86 call and
     jump trick (0x46, and 0x49 with conditional jumps), the ARM and arm64 branch tricks (0x50, 0x52, and 0x53 with
     conditional branches, which UPX added after 5.2.1), and the PowerPC one (0xd0), the filters its Mach-O packers
     use, each with `cto`, the byte that marks a filtered target.
     */
    static func unfilter(_ b: UnsafeMutableRawBufferPointer, id: UInt8, cto: UInt8) throws {
        let length = b.count
        // A block shorter than the filter's `min_buf_len`, or longer than its `max_buf_len`, UPX's `Filter` leaves as it
        // is (`filter.cpp`); its packer writes no filter for such a block, so only a crafted one meets this.
        let (shortest, longest): (Int, Int) = switch id {
        case 0x46, 0x49: (6, 0x00ff_ffff)
        case 0x50: (8, 0x01ff_ffff)
        case 0x52, 0x53: (8, 0x03ff_ffff)
        case 0xd0: (8, 0)
        default: (0, 0)
        }
        guard
            length >= shortest,
            longest == 0 || length <= longest
        else {
            return
        }
        func le32(_ at: Int) -> UInt32 {
            b.loadUnaligned(fromByteOffset: at, as: UInt32.self).littleEndian
        }
        func be32(_ at: Int) -> UInt32 {
            b.loadUnaligned(fromByteOffset: at, as: UInt32.self).bigEndian
        }
        switch id {
        case 0x46, 0x49:
            // ctoj, and ctok, which also takes the conditional jumps 0x0f 0x80...0x8f.
            var lastcall = 0
            var ic = 0
            while ic + 5 < length {
                let isCall = b[ic] == 0xe8 || b[ic] == 0xe9
                let isJump = id == 0x49 && lastcall != ic && ic >= 1 && b[ic - 1] == 0x0f && 0x80 ... 0x8f ~= b[ic]
                if isCall || isJump, b[ic + 1] == cto {
                    let jc = be32(ic + 1)
                    b.storeBytes(of: (jc &- UInt32(ic) &- 1 &- (UInt32(cto) << 24)).littleEndian, toByteOffset: ic + 1, as: UInt32.self)
                    ic += 4
                    lastcall = ic + 1
                }
                ic += 1
            }
        case 0x50, 0x52:
            // ct24arm (BL) and ct26arm (arm64 B and BL), word by word, every word but the last.
            var a = 0
            repeat {
                if a + 4 <= length {
                    let word = le32(a)
                    let mask: UInt32 = id == 0x50 ? 0x00ff_ffff : 0x03ff_ffff
                    let isBranch = id == 0x50 ? (word >> 24) & 0x0f == 0x0b : (word >> 24) & 0x7c == 0x14
                    if isBranch {
                        let target = ((word & mask) &- UInt32(a / 4)) & mask
                        b.storeBytes(of: ((word & ~mask) | target).littleEndian, toByteOffset: a, as: UInt32.self)
                    }
                }
                a += 4
            } while a < length - 4
        case 0x53:
            // CTarm64: B and BL as ct26arm, and the conditional branches, whose offset starts at bit 5: B.cond, CBZ and
            // CBNZ in 19 bits, TBZ and TBNZ in 14; word by word, the last word too.
            var a = 0
            while a + 4 <= length {
                let word = le32(a)
                let mask: UInt32 = if (word >> 26) & 0x1f == 0x05 {
                    0x03ff_ffff
                } else if word >> 24 == 0x54 || (word >> 25) & 0x3f == 0x1a {
                    0x00ff_ffe0
                } else if (word >> 25) & 0x3f == 0x1b {
                    0x0007_ffe0
                } else {
                    0
                }
                if mask != 0 {
                    let shift = mask.trailingZeroBitCount
                    let target = (((word >> shift) &- UInt32(a / 4)) << shift) & mask
                    b.storeBytes(of: ((word & ~mask) | target).littleEndian, toByteOffset: a, as: UInt32.self)
                }
                a += 4
            }
        case 0xd0:
            // ppcbxx: B and BL whose displacement's top 4 bits are cto.
            guard length >= 4 else {
                return
            }
            var ic = 0
            while ic <= min(length - 4, 0x0040_0000) {
                let word = be32(ic)
                if word >> 26 == 18, (word >> 22) & 0xf == UInt32(cto) {
                    let jc = word & 0x003f_fffc
                    b.storeBytes(of: ((word & 0xfc00_0003) | ((jc &- UInt32(ic)) & 0x03ff_fffc)).bigEndian, toByteOffset: ic, as: UInt32.self)
                }
                ic += 4
            }
        default:
            throw UnpackError.cantUnpack("unknown filter \(id.hex)")
        }
    }
}

// MARK: -

extension PackMach {
    /**
     UPX's pack header, as `decodePackHeaderFromBuf` reads it: the "UPX!" magic, then version, format, method and level,
     then sizes and checksums, little-endian for a little-endian format, big-endian past 128, and a checksum of its own.
     */
    private struct PackHeader {
        /// UPX's marker, "UPX!", as its packer writes it.
        static let magic = Array("UPX!".utf8)

        /// Where the marker lies in the buffer it was found in.
        let offset: Int
        /// Its size, by version and format (`getPackHeaderSize`).
        let size: Int
        let version: UInt8
        let format: UInt8
        /// Its marker: "UPX!", or what a packer modified to defeat `upx -d` writes instead.
        let magic: [UInt8]
        /// The Adler-32 of the original, block by block as the packer summed it: `u_adler`.
        let uAdler: UInt32
        /// The Adler-32 of the packed bytes, block by block as the packer summed them: `c_adler`.
        let cAdler: UInt32
        /// The rest of its fields, as the packer wrote them, for the log: `method`, `level`, `u_len`, `c_len`,
        /// `u_file_size`, `filter`, `filter_cto`, `n_mru` and its own `checksum`, zero where a version lacks them.
        let method: UInt8
        let level: UInt8
        let uncompressed: UInt32
        let compressed: UInt32
        let uFileSize: UInt32
        let filter: UInt8
        let cto: UInt8
        let nMru: UInt8
        let checksum: UInt8

        /**
         The pack header in `buffer`: the first "UPX!" in it, checked as `getPackHeader` checks it in a `fileSize`-byte
         image, which throws for a header that does not hold; without one, the first header for `format` that holds,
         by its own checksum, whose marker is whatever a packer modified to defeat `upx -d` wrote. Nil without either.
         */
        init?(_ buffer: Data, fileSize: Int, format: UInt8) throws {
            let offset: Int
            if let range = buffer.firstRange(of: Data(Self.magic)) {
                offset = range.lowerBound
            } else {
                // A header with a checksum, version 10 on, for the image's format, with the overlay offset after it.
                guard let start = buffer.indices.first(where: { start in
                    start + 36 <= buffer.endIndex && 10 ... 13 ~= buffer[start + 4] && buffer[start + 5] == format && (try? Self.decode(buffer[start...], fileSize: fileSize)) != nil
                }) else {
                    return nil
                }
                offset = start
            }
            let fields = try Self.decode(buffer[offset...], fileSize: fileSize)
            self.offset = offset - buffer.startIndex
            self.size = fields.size
            self.version = fields.version
            self.format = fields.format
            self.magic = Array(buffer[offset ..< offset + 4])
            self.uAdler = fields.uAdler
            self.cAdler = fields.cAdler
            self.method = fields.method
            self.level = fields.level
            self.uncompressed = fields.uncompressed
            self.compressed = fields.compressed
            self.uFileSize = fields.uFileSize
            self.filter = fields.filter
            self.cto = fields.cto
            self.nMru = fields.nMru
            self.checksum = fields.checksum
        }

        /// The header at the start of `p`, checked as `getPackHeader` checks it; throws, in UPX's words, for one that
        /// does not hold.
        private static func decode(_ p: Data, fileSize: Int) throws -> (size: Int, version: UInt8, format: UInt8, uAdler: UInt32, cAdler: UInt32, method: UInt8, level: UInt8, uncompressed: UInt32, compressed: UInt32, uFileSize: UInt32, filter: UInt8, cto: UInt8, nMru: UInt8, checksum: UInt8) {
            let at = { (index: Int) in p[p.startIndex + index] }
            guard p.count >= 20 else {
                throw UnpackError.cantUnpack("header corrupted 1")
            }
            func word(_ index: Int, bigEndian: Bool) -> UInt32 {
                let value = p.dropFirst(index).withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }
                return bigEndian ? value.bigEndian : value.littleEndian
            }
            let (version, format) = (at(4), at(5))
            let method = at(6)
            // Mach-O formats only: neither DOS's 16-bit sizes nor its 24-bit ones.
            guard p.count >= 31 else {
                throw UnpackError.cantUnpack("header corrupted 7")
            }
            let bigEndian = format >= 128
            let (uncompressed, compressed) = bigEndian ? (word(8, bigEndian: true), word(12, bigEndian: true)) : (word(16, bigEndian: false), word(20, bigEndian: false))
            let (uAdler, cAdler) = bigEndian ? (word(16, bigEndian: true), word(20, bigEndian: true)) : (word(8, bigEndian: false), word(12, bigEndian: false))
            guard version != 0xff else {
                throw UnpackError.cantUnpack("cannot unpack UPX ;-)")
            }
            let size = version <= 3 ? 24 : version <= 9 ? 28 : 32
            if version >= 10 {
                // The checksum: every byte after the magic and before it, modulo 251.
                guard size <= p.count, at(size - 1) == UInt8(p.dropFirst(4).prefix(size - 5).reduce(0) { $0 + Int($1) } % 251) else {
                    throw UnpackError.cantUnpack("header corrupted 3")
                }
            }
            guard
                compressed >= 2,
                uncompressed >= 2,
                compressed <= PackMach.maxSize,
                uncompressed <= PackMach.maxSize
            else {
                throw UnpackError.cantUnpack("header corrupted 4")
            }
            guard version <= 13 else {
                throw UnpackError.cantUnpack("need a newer version of UPX")
            }
            guard version >= 8 else {
                throw UnpackError.cantUnpack("I am not compatible with older versions of UPX")
            }
            guard
                compressed <= uncompressed,
                compressed < fileSize
            else {
                throw UnpackError.cantUnpack("header corrupted")
            }
            guard 2 ... 10 ~= method || method == 14 else {
                throw UnpackError.cantUnpack("unknown compression method (try a newer version of UPX)")
            }
            // The fields after the sizes, for the log: a shorter header, of a version before 10, lacks some.
            let byte = { (index: Int) in index < size && index < p.count ? at(index) : 0 }
            let uFileSize = size >= 28 && p.count >= 28 ? word(24, bigEndian: bigEndian) : 0
            return (size, version, format, uAdler, cAdler, method, at(7), uncompressed, compressed, uFileSize, byte(28), byte(29), byte(30), byte(size - 1))
        }
    }
}

extension MachO {
    /// The 32-bit word at `offset` in `data`, in the image's byte order: UPX's `get_te32`.
    func word(_ data: Data, at offset: Int) -> UInt32 {
        self.sw(data.dropFirst(offset).withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) })
    }
}
