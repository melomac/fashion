import Foundation
import MachO
import zlib

enum UnpackError: MalformedInput, Equatable {
    /// UPX's `CantUnpackException`: a Mach-O UPX packed whose packed data, or the image unpacked from it, does not hold,
    /// in UPX's words.
    case cantUnpack(String)
    /// Packed data that decompressed to its end and whose image's headers do not parse, in UPX's words as much; what
    /// decompressed, `thinr` and `unpack` write as it is under --keep, which the editor's `keep` gets.
    case unverified(String)
    /// An image too large to unpack in memory. UPX would unpack it: it bounds each block, not the image. `limit`
    /// is what is left of `PackMach.maxSize`, which the images of one file share.
    case imageTooLarge(size: Int, limit: Int)
}

extension UnpackError: LocalizedError {
    var errorDescription: String? {
        switch self {
        case let .cantUnpack(reason), let .unverified(reason):
            "Invalid UPX data: \(reason)"
        case let .imageTooLarge(size, limit):
            limit < PackMach.maxSize
                ? "Mach-O too large: the image UPX packed would be \(size) bytes, more than the \(limit) left of the \(PackMach.maxSize) this tool unpacks of one file in memory"
                : "Mach-O too large: the image UPX packed would be \(size) bytes, more than the \(limit) this tool unpacks in memory"
        }
    }
}

/**
 A Mach-O image UPX packed, after UPX's `PackMachBase` (`p_mach.cpp`, UPX 5.3.0). `init` mirrors `canUnpack`: it finds
 the pack header UPX leaves before `__LINKEDIT`, and reads the offset of the packed data from it. `unpack()` mirrors
 `unpack`: it decompresses the image block by block, to the bytes `upx -d` writes.

 `init` takes any Mach-O and returns nil for one UPX did not pack. That includes a file UPX would throw on before it
 finds a pack header, for headers or load commands its packer never writes. It also includes a file whose pack header
 pirates overwrote: UPX recovers one by emulating the stub's entry code and scanning for the packed data, which is not
 ported.

 Two tricks of a modified UPX make `upx -d` call the file not packed. Both are seen through, and named in a warning:

 - The "UPX!" marker replaced in the pack header, or everywhere it appears. The pack header is found by its structure
   and checksum where UPX looks for it, and the `l_info` before the packed data must confirm it, under the header's
   marker or UPX's own, which a packer that rewrote the header alone leaves.
 - The segments `canUnpack` goes by renamed: `__XHDR`, `UPX_DATA`, `__TEXT` or `__LINKEDIT`. The kernel loads the
   packed file without dyld, by offsets, and neither it nor the stub reads a segment name, so the file runs as it is.
   The pack header is looked for around the segment lying last in the file, and must confirm itself the same way.

 Packed data that fails its checks, or an unpacked image whose headers do not parse, is refused in red by `thinr`
 and `unpack`, which write what decompressed under --keep. Hash mode hashes every file, so it hashes the file as
 packed and reports the refusal as a warning. The pack header's two Adler-32 sums, which neither the stub nor
 `upx -d` reads for a Mach-O, refuse nothing: a packer may write what it likes there, so an image that bears neither
 is unpacked as UPX unpacks it, the mismatch said, once the XOR key a modified UPX may have applied has been looked
 for under the packer's sum.

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
         | u_adler of the image against the PackHeader's:           |
         |   as it is         -> the original                       |
         |   under an XOR key -> the original, key and marker named |
         |   under no key     -> as UPX unpacks it, the sums named  |
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

    /**
     The original's size as the `p_info` before the blocks claims it and as the pack header says it: UPX writes the
     one value in both, the pack header's under its checksum, the `p_info`'s under nothing, where its stub never
     reads it. Nil when the image ends before the `p_info`; throws for a read that fails.
     */
    func claimedSizes() throws -> ClaimedSizes? {
        guard self.overlayOffset + 12 <= self.image.length else {
            return nil
        }
        return try ClaimedSizes(pInfo: Int(self.image.word(self.read(at: self.overlayOffset, count: 12), at: 4)), header: Int(self.header.uFileSize))
    }

    /// The original's size as the `p_info` claims it, and as the pack header says it.
    struct ClaimedSizes {
        let pInfo: Int
        let header: Int
    }

    /// The segment lying last in the file, UPX's `__LINKEDIT` whatever a modified UPX named it, and where the one
    /// before it ends.
    private struct LastSegment {
        let segment: Segment
        let before: Int
    }

    /// The pack header as the scan found it: the header, where it lies in the image, the overlay offset after it,
    /// and where the scan looked when the segments' names did not lead it, nil where they did.
    private struct FoundHeader {
        let header: PackHeader
        let offset: Int
        let overlayOffset: Int
        let location: String?
    }

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
    /// The largest file UPX packs (`UPX_RSIZE_MAX`). UPX bounds each block it unpacks by it, not the image. Here the
    /// image is made in memory, so it bounds the image too, and the images of one universal file together, which
    /// are held in memory at once (`MachOEditor.edit`).
    static let maxSize = 768 << 20
    /// How many blocks the notes name one by one, where a crafted stream holds millions: the rest are counted.
    private static let notedBlocks = 16

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
        let headerSize = image.headerSize
        let ncmds = image.ncmds
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
        var last: LastSegment?
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
                last = LastSegment(segment: segment, before: posNext)
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

        /// Where the pack header may lie: `count` bytes of the image from `start`, and where that is in the segments'
        /// terms, `found`, for a header found without its marker to be said so, nil where the names led there.
        struct Window {
            let start: Int
            let count: Int
            let found: String?
        }
        var windows: [Window] = []

        /// The window of `count` bytes before `offLINK`, cut at the image's start.
        func before(_ offLINK: Int, found: String?) -> Window {
            let start = offLINK - count
            return start < 0 ? Window(start: 0, count: count + start, found: found) : Window(start: start, count: count, found: found)
        }

        /// The window of `count` bytes from `offLINK`, cut at the image's end; nil for fewer than 12.
        func after(_ offLINK: Int, found: String?) -> Window? {
            // UPX gives up here ("bad offLINK"); a __LINKEDIT this short is a linker's, in an image it never packed.
            let count = min(count, image.length - offLINK)
            return count >= 12 ? Window(start: offLINK, count: count, found: found) : nil
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

        var found: FoundHeader?
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
                // packed data, inside the image: its version and format must be the header's, as the packer wrote
                // them, under the header's marker or UPX's own, which a packer that rewrote the header alone leaves.
                guard
                    overlayOffset >= headerSize + headway + 12,
                    overlayOffset <= image.length,
                    let lInfo = try? image.dataAt(overlayOffset - 12, count: 12),
                    lInfo.dropFirst(4).prefix(4).elementsEqual(packHeader.magic) || lInfo.dropFirst(4).prefix(4).elementsEqual(PackHeader.magic),
                    lInfo[lInfo.startIndex + 10] == packHeader.version,
                    lInfo[lInfo.startIndex + 11] == packHeader.format
                else {
                    continue
                }
            }
            found = FoundHeader(header: packHeader, offset: window.start + i + packHeader.offset, overlayOffset: overlayOffset, location: window.found)
        }

        guard let found else {
            // No pack header where the scan looks, before the 16-byte __LINKEDIT only UPX writes: a packed image
            // whose zero padding after the header was written into, which moves the last non-zero byte the scan
            // steps back from. Its stub runs it as packed (the entry code carries its own offsets); canUnpack calls
            // it "file corrupted" (its style 395 branch) and gives up, and so does this tool, rather than taking the
            // image for one UPX never packed, as it does an image of any other layout.
            if style == 395 {
                throw UnpackError.cantUnpack("file corrupted: no pack header before the 16-byte __LINKEDIT UPX writes")
            }
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
        if let renamed = found.location {
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
     segments but the first are copied as they are. Throws for packed data that does not hold, and for an image
     larger than `limit`: what is left of `maxSize` for the file this image is part of.

     With it come a caveat when a modified UPX packed the image (the marker it bears in place of "UPX!", its XOR
     key, or both) and `notes` for the log, on how it was packed and where its parts lie (`Unpacked`).

     The sums. The pack header holds two Adler-32 sums: `c_adler` of the packed bytes, `u_adler` of the original.
     For a Mach-O neither the stub nor `upx -d` reads them, where `upx -d` checks both for an ELF. A packer may
     write anything there, so a sum that does not match refuses nothing: it is named in the caveat.

     The XOR. A modified UPX may XOR each block it filtered with a key: one byte, 0x01, for the UPX 3.91 behind
     OSX/Keydnap. The key must be undone before the block is unfiltered, or the block unfilters to wrong bytes.
     So when the image does not match `u_adler` and has filtered blocks, a key is looked for.

     The key is read off the filtered blocks as they decompress (`KeySample`):

     ```
     the original      | mach_header, load commands | 00 00 00 00 00 00 .. | __text ..
                                                    ^ the first extent starts here (`x.offset += delta` in `pack2`)
     first block,                                   | 00 00 00 00 00 00 .. | calls rewritten ..
       filtered
     XORed with kk                                  | kk kk kk kk kk kk .. | every byte ^ kk ..
     XORed with "Hello"                             | H  e  l  l  o  H  .. | each byte ^ the key's next ..
     ```

     1. The lead. UPX packs the Mach-O headers apart and starts the first extent where they end, in the padding
        a linker leaves after the load commands. That padding is zeros, which a filter leaves alone, so the first
        filtered block starts with the key, repeated. The key is the shortest stretch of it that repeats: one
        byte, or several.
     2. The commonest byte. Zero is the commonest byte of code, so a key of one byte is the commonest byte of the
        blocks.

     A key of several bytes is taken to start again with each filtered block. No packer is known to use one, so
     none tells otherwise.

     Each candidate costs one more decoding of the image, and is the key when the image then matches `u_adler`.
     Nothing else is tried: a search of every byte would decode the image 255 times, for nothing when a crafted
     header claims a sum no key gives, and a search of longer keys has no end.

     `decompressed` is set only when a key was found: the image as it unpacks without the key, for --keep to write.
     */
    func unpack(limit: Int = PackMach.maxSize) throws -> Unpacked {
        let plain = try self.unpack(key: [], limit: limit)
        var sums: [String] = []
        if plain.cAdler != self.cAdler {
            sums.append("the packed bytes sum to \(plain.cAdler.hex), the pack header says \(self.cAdler.hex)")
        }

        /// `image` with its caveat and its notes. The caveat is nil when there is nothing to say: the packer's marker
        /// and key (`caveat(xor:)`), a load command UPX refuses, and the sums that do not match, `unverified` among
        /// them.
        func finished(_ image: Unpacked, xor: [UInt8] = [], unverified: String? = nil) -> Unpacked {
            var image = image
            let all = sums + (unverified.map { [$0] } ?? [])
            let refused = plain.refusedCommand.map { "its headers hold a load command UPX refuses to unpack, at \($0.hex)" }
            let text = [self.caveat(xor: xor), refused, all.isEmpty ? nil : "checksums neither UPX nor its stub reads: " + all.joined(separator: ", ")].compactMap(\.self).joined(separator: "; ")
            image.caveat = text.isEmpty ? nil : text
            image.notes = self.notes(image)
            return image
        }

        if plain.adler == self.uAdler {
            return finished(plain)
        }

        let unverified = "the image sums to \(plain.adler.hex), the pack header says \(self.uAdler.hex)"
        guard plain.filtered else {
            return finished(plain, unverified: unverified)
        }

        // Each candidate is tried: the image decoded again under it. It is the key when the image then matches
        // `u_adler`. The image as it unpacks without the key goes with it, for --keep.
        for key in plain.pass.sample.keys {
            var keyed = try self.unpack(key: key, limit: limit)
            if keyed.adler == self.uAdler {
                keyed.decompressed = plain.data
                return finished(keyed, xor: key)
            }
        }

        // No candidate is the key: the image as UPX unpacks it, the mismatch named.
        return finished(plain, unverified: unverified + ", under no filtered XOR key")
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
        if unpacked.blockCount > unpacked.blocks.count {
            notes.append("and \(String(unpacked.blockCount - unpacked.blocks.count, pluralizing: "more block"))")
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
    /// nil for UPX's own. A key of one byte is said in hexadecimal, a longer one as `quoted` has it.
    private func caveat(xor key: [UInt8]) -> String? {
        let said = key.count == 1 ? "0x\(String(format: "%02x", key[0]))" : Self.quoted(key)
        let xor = key.isEmpty ? nil : "its filtered blocks XORed with \(said) before they are unfiltered"
        return switch (self.modified, xor) {
        case (false, nil): nil
        case (true, nil): self.packer
        case (false, let xor?): "packed by a modified UPX, \(xor)"
        case (true, let xor?): "\(self.packer) and \(xor)"
        }
    }

    /**
     An image unpacked, as `upx -d` writes it: its bytes, `data`; a word on it when a modified UPX packed it, `caveat`,
     nil for UPX's own; words for the log on how it was packed and where its parts lie, `notes`; and under a XOR key,
     `decompressed`, the image with its blocks as they decoded under none, for --keep to write, nil otherwise. With
     what the pass over its blocks summed and saw, and the `p_info` before the blocks, for the unpacker alone.
     */
    struct Unpacked {
        var data: Data
        var caveat: String?
        var notes: [String] = []
        var decompressed: Data?
        /// The offset in the image's headers of the first load command UPX refuses, "bad packed Mach
        /// load_command". The image is unpacked all the same: its bytes are the original's.
        fileprivate var refusedCommand: Int?
        fileprivate var pass: Pass
        fileprivate let pInfo: PInfo

        fileprivate var blocks: [Block] {
            self.pass.blocks
        }

        fileprivate var blockCount: Int {
            self.pass.blockCount
        }

        /// The Adler-32 of the image as the packer summed it, block by block in the order they were unpacked.
        fileprivate var adler: UInt32 {
            UInt32(self.pass.adler)
        }

        fileprivate var cAdler: UInt32 {
            self.pass.cAdler
        }

        fileprivate var filtered: Bool {
            self.pass.filtered
        }

        fileprivate var methods: Set<UInt8> {
            self.pass.methods
        }

        fileprivate var filters: Set<UInt8> {
            self.pass.filters
        }
    }

    /**
     One pass over the blocks: the image unpacked, each filtered block XORed with `key` before it is unfiltered,
     the key repeated from the block's start. No `key` changes nothing, as for UPX's own files.

     The result carries what the pass saw (`Pass`): the Adler-32 of the packed bytes and of the image, summed block
     by block as the packer sums them; whether a block was unfiltered; the methods and filters of the blocks; and,
     without a `key`, the candidates for one (`KeySample`).
     */
    private func unpack(key: [UInt8], limit: Int) throws -> Unpacked {
        let pInfo = try self.read(at: self.overlayOffset, count: 12)
        let progid = self.image.word(pInfo, at: 0)
        let fileSize = Int(self.image.word(pInfo, at: 4))
        let blocksize = Int(self.image.word(pInfo, at: 8))
        guard blocksize <= fileSize else {
            throw UnpackError.cantUnpack("file header corrupted")
        }
        guard fileSize <= limit else {
            throw UnpackError.imageTooLarge(size: fileSize, limit: limit)
        }

        // The first block, the image's Mach-O headers, read ahead for its load commands: a block of the first segment,
        // so no larger than a block, which UPX does not check before it allocates it.
        let headerSize = self.image.headerSize
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
        var refusedCommand: Int?
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
            commands = try self.commands(in: headers, from: headerSize, count: ncmds, refused: &refusedCommand)
        }
        let segments = commands.compactMap(\.segment).sorted(by: Segment.precedes)

        // UPX writes a segment wherever its headers place it; one decoded from the blocks must lie in the image made
        // here, p_filesize bytes, as the blocks are bounded by it. A dylib's segments after the first are copied, not
        // decoded, and UPX seeks to where the headers place them and writes, past p_filesize included: those grow
        // the image, under this tool's limit, as they do UPX's file.
        let decoded = self.image.filetype == MH_DYLIB ? Array(segments.first { $0.filesize != 0 }.map { [$0] } ?? []) : segments
        guard decoded.allSatisfy({ $0.filesize == 0 || ($0.fileoff <= fileSize && $0.filesize <= fileSize - $0.fileoff) }) else {
            throw UnpackError.cantUnpack("file header corrupted")
        }

        var output = Data(count: fileSize)
        var cursor = blocks
        var pass = Pass(key: key)
        pass.methods.insert(first.method)
        for segment in segments where segment.filesize != 0 {
            try self.unpackExtent(segment.filesize, into: &output, at: segment.fileoff, cursor: &cursor, blocksize: blocksize, pass: &pass)
            if self.image.filetype == MH_DYLIB {
                break
            }
        }

        if self.image.filetype == MH_DYLIB {
            try self.copyDylibSegments(commands, into: &output, limit: limit, pass: &pass)
        } else {
            for (index, segment) in segments.enumerated() where segment.filesize != 0 {
                let gap = Self.gap(after: index, in: segments, end: fileSize)
                if gap > 0 {
                    try self.unpackExtent(gap, into: &output, at: segment.fileoff + segment.filesize, cursor: &cursor, blocksize: blocksize, pass: &pass)
                }
            }
        }

        // The image ends at the last byte written, by a block or a copied segment, as UPX's output file ends where it
        // last wrote: p_filesize bounds what the blocks fill and where the segments lie, it is not a length. A dylib
        // whose p_filesize claims more than its segments reach would otherwise come out that long, zeros after the
        // last one, and cost that much to hash.
        output.count = pass.extent
        return Unpacked(data: output, refusedCommand: refusedCommand, pass: pass, pInfo: PInfo(progid: progid, fileSize: fileSize, blocksize: blocksize))
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
            let name = command.segmentName
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

    /// What one pass over the blocks saw: the Adler-32 of their packed bytes and of the image they make, summed as
    /// the packer sums them, how many bytes they made so far, and whether one was unfiltered.
    fileprivate struct Pass {
        /// The key each filtered block is XORed with once decompressed, before it is unfiltered, repeated from the
        /// block's start: none for UPX's own.
        let key: [UInt8]
        var cAdler: UInt32 = 1
        /// The image's Adler-32 so far, the blocks' combined as they came.
        var adler: uLong = 1
        var filtered = false
        var produced = 0
        /// The end of the furthest byte written, by a block or a copied segment: where the image ends.
        var extent = 0
        /// The candidates for an XOR key, sampled when there is no `key`.
        var sample = KeySample()
        /// The compression methods and filters of the blocks seen, for the log, the first blocks themselves, and how
        /// many there were.
        var methods: Set<UInt8> = []
        var filters: Set<UInt8> = []
        var blocks: [Block] = []
        var blockCount = 0
    }

    /// UPX's `p_info`, the 12 bytes before the blocks: the program id, the original's size and the block size.
    fileprivate struct PInfo {
        let progid: UInt32
        let fileSize: Int
        let blocksize: Int
    }

    /**
     The candidates for the key a modified UPX XORed the filtered blocks with, sampled from the blocks as they
     decompress (see `unpack(limit:)`):

     - the lead: the shortest stretch of the first filtered block's start that repeats. What repeats there is the
       zero padding after the load commands, XORed, so the stretch is the key: one byte, or several.
     - the commonest byte among the first `limit` filtered bytes: zero, the commonest byte of code, XORed.

     A candidate is a guess. It is the key when the image decoded under it matches `u_adler`.
     */
    fileprivate struct KeySample {
        /// How many bytes of the first filtered block's start a key must repeat over, and twice over at least:
        ///
        /// ```
        /// kk kk kk kk kk kk kk kk kk kk kk kk kk kk kk kk     one byte, over 16
        /// H e l l o H e l l o H e l l o H                     5 bytes, over 16
        /// H e l l o , _ W o r l d ! H e l l o , _ W o r l d ! 13 bytes, twice
        /// ```
        ///
        /// A linker pads by more.
        static let run = 16
        /// The longest key read off the lead, which then takes twice as many bytes of padding.
        static let longest = 64
        /// How many filtered bytes are counted: enough to tell the commonest byte of an image of any size.
        static let limit = 1 << 20

        /// The start of the first filtered block: as much as shows a key of `longest` bytes twice.
        private var head: [UInt8]?
        private var counts = [Int](repeating: 0, count: 256)
        private var counted = 0

        /// Sample a filtered block, decompressed and not yet unfiltered.
        mutating func add(_ block: UnsafeMutableRawBufferPointer) {
            if self.head == nil {
                self.head = Array(block.prefix(2 * Self.longest))
            }
            let taken = min(block.count, Self.limit - self.counted)
            for byte in block.prefix(taken) {
                self.counts[Int(byte)] += 1
            }
            self.counted += taken
        }

        /// The shortest stretch the first filtered block's start repeats with, over `run` bytes and twice over.
        private var lead: [UInt8]? {
            guard let head = self.head else {
                return nil
            }
            for length in 1 ... Self.longest {
                var repeated = 0
                while repeated + length < head.count, head[repeated] == head[repeated + length] {
                    repeated += 1
                }
                if repeated >= max(length, Self.run - length) {
                    return Array(head.prefix(length))
                }
            }
            return nil
        }

        /// The candidates to try, the lead first. Zeros are left out: they are no key.
        var keys: [[UInt8]] {
            let common = self.counted > 0 ? self.counts.indices.max { self.counts[$0] < self.counts[$1] }.map { [UInt8($0)] } : nil
            var keys: [[UInt8]] = []
            for key in [self.lead, common] {
                if let key, key.contains(where: { $0 != 0 }), !keys.contains(key) {
                    keys.append(key)
                }
            }
            return keys
        }
    }

    /// A block as the pass met it: where its `b_info` lies in the packed image, what it says, and where the block is
    /// written in the unpacked image.
    fileprivate struct Block {
        let offset: Int
        let info: BlockInfo
        let at: Int
    }

    /// A `b_info`, the header before each block: its sizes, compression method and filter.
    fileprivate struct BlockInfo {
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
    private func commands(in headers: Data, from start: Int, count: Int, refused: inout Int?) throws -> [Command] {
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
            // UPX refuses more than that: a command it does not know, or one of a size it does not expect. Such a
            // command is noted for the caveat, and the image is unpacked anyway: its bytes are the original's,
            // whichever packer kept them.
            if refused == nil, self.isBadLinkerCommand(cmd, size: cmdsize) {
                refused = offset
            }
            let command = MachO.LoadCommand(cmd: cmd, data: headers.subdata(in: offset ..< offset + cmdsize))
            commands.append(Command(segment: Segment(command, in: self.image)))
            offset += cmdsize
        }
        return commands
    }

    /// The size UPX expects of each load command, by command number (`lc_cmd_size`): a positive entry is the exact
    /// size, a negative one a minimum, 0 a command UPX does not take. The table ends at `LC_FILESET_ENTRY`.
    private static let commandSizes: [Int] = [
        0, -56, 24, 0, -16, -16, 0, 0, 0, 0, 0, 80, -24, -24, -12, -12, // 0x00
        0, 0, 0, 0, 0, 0, -16, 0, -24, -72, 0, 24, -12, 16, 16, -24, // 0x10
        8, 20, 48, 0, 16, 16, 16, -12, 24, 16, 16, 16, 24, 0, 0, 16, // 0x20
        16, -40, -24, 16, 16, -32, // 0x30
    ]

    /**
     Whether UPX refuses the load command `command` of `size` bytes, which lies within the headers
     (`is_bad_linker_command`). It refuses:

     - a command it does not take, or one past its table;
     - a size that is not a multiple of the image's word, 4 or 8 bytes;
     - a segment whose size is not its own header plus whole sections;
     - a size other than the exact one in `commandSizes`, or under the minimum there.
     */
    private func isBadLinkerCommand(_ command: UInt32, size: Int) -> Bool {
        let number = Int(command & ~UInt32(LC_REQ_DYLD))
        guard number != 0, number < Self.commandSizes.count, Self.commandSizes[number] != 0 else {
            return true
        }

        let known = Self.commandSizes[number]
        let wide = self.image.is64
        if size & ((wide ? 8 : 4) - 1) != 0 {
            return true
        }

        if number == (wide ? Int(LC_SEGMENT_64) : Int(LC_SEGMENT)) {
            let (segment, section) = wide ? (72, 80) : (56, 68)
            // A segment shorter than its header is under the minimum below. UPX's unsigned subtraction wraps there.
            if size >= segment, (size - segment) % section != 0 {
                return true
            }
        }

        return known > 0 ? known != size : -known > size
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
            if pass.blockCount < Self.notedBlocks {
                pass.blocks.append(Block(offset: cursor, info: info, at: offset))
            }
            pass.blockCount += 1
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
                        if pass.key.isEmpty {
                            pass.sample.add(destination)
                        } else {
                            for index in destination.indices {
                                destination[index] ^= pass.key[index % pass.key.count]
                            }
                        }
                        try Self.unfilter(destination, id: info.filter, cto: info.cto)
                    }
                }
            } else {
                output.replaceSubrange(offset ..< offset + info.uncompressed, with: block.prefix(info.compressed))
            }
            let sum = output.withUnsafeBytes { UInt32(adler32(1, $0.baseAddress!.advanced(by: offset).assumingMemoryBound(to: Bytef.self), uInt(info.uncompressed))) }
            pass.adler = adler32_combine(pass.adler, uLong(sum), info.uncompressed)
            pass.produced += info.uncompressed
            pass.extent = max(pass.extent, offset + info.uncompressed)
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
     where the original headers place them, the image grown to hold one placed past its end, as UPX's output file
     grows, the pointer in `__mod_init_func`, which UPX points at its loader, restored.
     */
    private func copyDylibSegments(_ commands: [Command], into output: inout Data, limit: Int, pass: inout Pass) throws {
        // UPX compares the two headers' ncmds, the packed file's and the original's.
        let packed = self.image.loadCommands.prefix(self.image.ncmds)
        guard self.image.ncmds == commands.count else {
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
            if rc.name == "__DATA", let initFunc = try self.modInitFunc(in: rc) {
                let original = try self.read(at: Int(clamping: initFunc.pointer) - 16, count: 4)
                let at = initFunc.offset - rc.fileoff
                guard
                    at >= 0,
                    at + 4 <= data.count
                else {
                    throw UnpackError.cantUnpack("bad __mod_init_func")
                }
                data.replaceSubrange(data.startIndex + at ..< data.startIndex + at + 4, with: original)
            }
            let end = sc.fileoff.addingReportingOverflow(rc.filesize)
            guard sc.fileoff >= 0, !end.overflow, end.partialValue <= limit else {
                throw UnpackError.imageTooLarge(size: end.overflow ? Int.max : end.partialValue, limit: limit)
            }
            if end.partialValue > output.count {
                output.append(Data(count: end.partialValue - output.count))
            }
            output.replaceSubrange(sc.fileoff ..< end.partialValue, with: data)
            pass.extent = max(pass.extent, end.partialValue)
        }
    }

    /// A pointer-sized `__mod_init_func` section: its offset in the image, and the pointer it holds.
    private struct ModInitFunc {
        let offset: Int
        let pointer: UInt64
    }

    /// The offset of a pointer-sized `__mod_init_func` section in `segment`, and the pointer there (`get_mod_init_func`).
    private func modInitFunc(in segment: Segment) throws -> ModInitFunc? {
        let sectionSize = self.image.is64 ? MemoryLayout<section_64>.size : MemoryLayout<section>.size
        let pointerSize = self.image.is64 ? 8 : 4
        var at = (self.image.is64 ? MemoryLayout<segment_command_64>.size : MemoryLayout<segment_command>.size)
        while at + sectionSize <= segment.cmdsize {
            let section = segment.data.bytes(in: at ..< at + sectionSize)
            let size = self.image.is64 ? Int(clamping: self.image.sw(section.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 40, as: UInt64.self) })) : Int(self.image.word(section, at: 36))
            if size == pointerSize, MachO.field(section.prefix(16), is: "__mod_init_func") {
                let offset = Int(self.image.word(section, at: self.image.is64 ? 48 : 40))
                let pointer = try self.read(at: offset, count: pointerSize)
                return ModInitFunc(offset: offset, pointer: self.image.is64 ? self.image.sw(pointer.withUnsafeBytes { $0.loadUnaligned(as: UInt64.self) }) : UInt64(self.image.word(pointer, at: 0)))
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
     conditional branches, which UPX 5.3.0 added), and the PowerPC one (0xd0), the filters its Mach-O packers
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
        /// The little-endian word at `at`.
        func le32(_ at: Int) -> UInt32 {
            b.loadUnaligned(fromByteOffset: at, as: UInt32.self).littleEndian
        }

        /// The big-endian word at `at`.
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
            if let range = buffer.firstRange(of: Data(Self.magic)) {
                self = try PackHeader(decoding: buffer[range.lowerBound...], at: range.lowerBound - buffer.startIndex, fileSize: fileSize)
                return
            }
            // A header with a checksum, version 10 on, for the image's format, with the overlay offset after it: the
            // first that holds, decoded the once.
            for start in buffer.indices where start + 36 <= buffer.endIndex && 10 ... 13 ~= buffer[start + 4] && buffer[start + 5] == format {
                if let header = try? PackHeader(decoding: buffer[start...], at: start - buffer.startIndex, fileSize: fileSize) {
                    self = header
                    return
                }
            }
            return nil
        }

        /// Whether UPX has a format numbered `format` (`Packer::isValidFormat`): 1 to 46 and 129 to 142, less the holes.
        private static func isValidFormat(_ format: UInt8) -> Bool {
            (1 ... 46 ~= format || 129 ... 142 ~= format) && ![6, 11, 13, 17, 38, 41, 130].contains(format)
        }

        /**
         The header at the start of `p`, which lies at `offset` in the buffer it was found in, checked as
         `getPackHeader` checks it; throws, in UPX's words, for one that does not hold.
         */
        private init(decoding p: Data, at offset: Int, fileSize: Int) throws {
            let at = { (index: Int) in p[p.startIndex + index] }
            guard p.count >= 20 else {
                throw UnpackError.cantUnpack("header corrupted 1")
            }
            /// The 32-bit word `index` bytes in, in the header's byte order.
            func word(_ index: Int, bigEndian: Bool) -> UInt32 {
                let value = p.dropFirst(index).withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }
                return bigEndian ? value.bigEndian : value.littleEndian
            }
            let (version, format) = (at(4), at(5))
            let method = at(6)
            guard Self.isValidFormat(format) else {
                throw UnpackError.cantUnpack("unknown format \(format)")
            }
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
            self.offset = offset
            self.size = size
            self.version = version
            self.format = format
            self.magic = Array(p.prefix(4))
            self.uAdler = uAdler
            self.cAdler = cAdler
            self.method = method
            self.level = at(7)
            self.uncompressed = uncompressed
            self.compressed = compressed
            self.uFileSize = uFileSize
            self.filter = byte(28)
            self.cto = byte(29)
            self.nMru = byte(30)
            self.checksum = byte(size - 1)
        }
    }
}

extension MachO {
    /// The 32-bit word at `offset` in `data`, in the image's byte order: UPX's `get_te32`.
    func word(_ data: Data, at offset: Int) -> UInt32 {
        self.sw(data.dropFirst(offset).withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) })
    }
}
