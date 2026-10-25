import Foundation
import MachO

enum UnpackError: Error, Equatable {
    /// UPX's `CantUnpackException`: a Mach-O UPX packed whose packed data does not hold, in UPX's words.
    case cantUnpack(String)
}

extension UnpackError: LocalizedError {
    var errorDescription: String? {
        switch self {
        case let .cantUnpack(reason):
            "Invalid UPX data: \(reason)"
        }
    }
}

/**
 A Mach-O image UPX packed, named after UPX's `PackMachBase`, whose `canUnpack` and `unpack` it mirrors (`p_mach.cpp`,
 UPX 5.2.1): `init` finds the pack header UPX leaves before `__LINKEDIT`, and the offset of the packed data it records;
 `unpack()` decompresses the image UPX packed, block by block, as `upx -d` writes it.

 Where UPX throws before it has found its pack header, for a header or load commands its packer would never write, the
 image is merely not packed: `--unpack` meets every Mach-O. UPX's recovery of a pack header pirates overwrote, which
 emulates the stub's entry code and scans for the packed data, is not ported: such an image is not packed either.
 A packer modified to write another marker than "UPX!" everywhere it goes, whose files `upx -d` calls not packed, is
 seen through: the pack header is found by its structure and checksum where UPX looks for it, and the `l_info` before
 the packed data must vouch for it.
 */
struct PackMach {
    private let image: MachO
    private let format: Class
    /// Where the packed data starts: UPX's `p_info`, then a `b_info` before each block.
    private let overlayOffset: Int
    /// A word on the image when a modified UPX packed it: the marker it bears in place of "UPX!"; nil for "UPX!".
    let caveat: String?

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
        Class(cpuType: CPU_TYPE_POWERPC64, filetype: UInt32(MH_EXECUTE), format: 139, pageShift: 12),
        Class(cpuType: CPU_TYPE_POWERPC64, filetype: UInt32(MH_DYLIB), format: 142, pageShift: 12),
    ]

    /// The most load commands UPX takes (`MAX_N_CMDS`).
    private static let maxCommands = 256
    /// The largest file UPX packs, and so the largest it unpacks to (`UPX_RSIZE_MAX`): the image is made in memory.
    private static let maxSize = 768 << 20

    // MARK: - canUnpack

    /**
     The image UPX packed, as `canUnpack` finds it: its segments tell where UPX put its pack header (UPX 3.91 before
     `__LINKEDIT`, 3.92 after the loader in it, 3.95 on before a 16-byte `__LINKEDIT`), whose checksum must hold and
     whose format must be the image's. Nil when UPX did not pack it; throws for a pack header that does not hold.
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
            posNext = segment.fileoff + segment.filesize
        }
        if segments == 3, style != 395 {
            style = 392
        }
        if style == 391, offLINK == 0, ncmds == 2, let text {
            offLINK = text.fileoff + text.filesize
        }
        guard style != 0, offLINK != 0 else {
            return nil
        }

        // A page and the pack header after it, then the overlay offset, read back from where UPX left them; UPX reads
        // before the file's start for a __TEXT shorter than that, and gives up, where the window starts there instead.
        let small = 32 + 4
        var count = (1 << format.pageShift) + small
        var start: Int
        if style == 392 {
            if image.filetype == MH_DYLIB {
                start = image.length - count
            } else {
                start = offLINK
                count = min(count, image.length - offLINK)
                // UPX gives up here ("bad offLINK"); a __LINKEDIT this short is a linker's, in an image it never packed.
                guard count >= 12 else {
                    return nil
                }
            }
        } else {
            start = offLINK - count
        }
        if start < 0 {
            count += start
            start = 0
        }
        let window = try image.dataAt(start, count: count)

        // The pack header ends where the zeros that pad __TEXT to its page begin.
        var i = window.count
        while i > small {
            i -= 1
            if window[window.startIndex + i] != 0 {
                break
            }
        }
        i -= small
        guard
            i >= 1,
            let packHeader = try PackHeader(window.dropFirst(i), fileSize: image.length, format: format.format),
            packHeader.format == format.format
        else {
            return nil
        }

        let at = i + packHeader.offset + packHeader.size
        let overlayOffset = at + 4 <= window.count ? Int(image.word(window, at: at)) : 0
        if packHeader.magic != PackHeader.magic {
            // Found without its marker, the pack header needs the word of UPX's `l_info`, the 12 bytes before the
            // packed data: its marker, version and format must be the header's, as the packer wrote them.
            guard
                overlayOffset >= headerSize + headway + 12,
                let lInfo = try? image.dataAt(overlayOffset - 12, count: 12),
                lInfo.dropFirst(4).prefix(4).elementsEqual(packHeader.magic),
                lInfo[lInfo.startIndex + 10] == packHeader.version,
                lInfo[lInfo.startIndex + 11] == packHeader.format
            else {
                return nil
            }
        }
        guard (headerSize + headway) ..< image.length ~= overlayOffset else {
            throw UnpackError.cantUnpack("file corrupted")
        }

        self.image = image
        self.format = format
        self.overlayOffset = overlayOffset
        self.caveat = packHeader.magic == PackHeader.magic ? nil : "packed by a modified UPX, its marker \(Self.quoted(packHeader.magic)) in place of \"UPX!\""
    }

    /// `bytes` quoted, a quote or backslash among them escaped, when they all print; hexadecimal otherwise.
    private static func quoted(_ bytes: [UInt8]) -> String {
        bytes.allSatisfy { 0x20 ... 0x7e ~= $0 } ? String(decoding: bytes, as: UTF8.self).debugDescription : "0x" + bytes.map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - unpack

    /**
     The image UPX packed, as `unpack` writes it: its Mach-O headers come first, then each segment from its offset, in
     the order of their offsets, then what lies between them and after the last up to the original size; a dylib's
     segments but the first are copied as they are. Throws for packed data that does not hold.
     */
    func unpack() throws -> Data {
        let pInfo = try self.read(at: self.overlayOffset, count: 12)
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
        var headers = Data(count: first.uncompressed)
        try headers.withUnsafeMutableBytes { try Self.decompress(self.read(at: blocks + 12, count: first.compressed), method: first.method, into: $0) }
        let packedHeader = try self.image.dataAt(0, count: 16)
        guard headers.prefix(16).elementsEqual(packedHeader.prefix(16)) else {
            throw UnpackError.cantUnpack("file header corrupted")
        }
        let ncmds = Int(self.image.word(headers, at: 16))
        guard 1 ... Self.maxCommands ~= ncmds else {
            throw UnpackError.cantUnpack("bad Mach_header.ncmds = \(ncmds)")
        }
        let commands = try self.commands(in: headers, from: headerSize, count: ncmds)
        let segments = commands.compactMap(\.segment).sorted(by: Segment.precedes)
        // UPX writes a segment wherever its headers place it; it must lie in the image made here.
        guard segments.allSatisfy({ $0.filesize == 0 || ($0.fileoff <= fileSize && $0.filesize <= fileSize - $0.fileoff) }) else {
            throw UnpackError.cantUnpack("file header corrupted")
        }

        var output = Data(count: fileSize)
        var cursor = blocks
        for segment in segments where segment.filesize != 0 {
            try self.unpackExtent(segment.filesize, into: &output, at: segment.fileoff, cursor: &cursor, blocksize: blocksize)
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
                    try self.unpackExtent(gap, into: &output, at: segment.fileoff + segment.filesize, cursor: &cursor, blocksize: blocksize)
                }
            }
        }
        return output
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

    /// A `b_info`, the header before each block: its sizes, compression method and filter.
    private struct BlockInfo {
        let uncompressed: Int
        let compressed: Int
        let method: UInt8
        let filter: UInt8
        let cto: UInt8
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
     The load commands of the decompressed headers, as `unpack` walks them: each must fit what is left of them.
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
                throw UnpackError.cantUnpack("bad packed Mach load_command @0x\(String(offset, radix: 16))")
            }
            let command = MachO.LoadCommand(cmd: cmd, data: headers.bytes(in: offset ..< offset + cmdsize))
            commands.append(Command(segment: Segment(command, in: self.image)))
            offset += cmdsize
        }
        return commands
    }

    /**
     Decompress blocks into `output` at `offset` until they make `wanted` bytes, as `unpackExtent` does: a block whose
     compressed size is its size is stored as it is, any other is decompressed by its method where it goes, then
     unfiltered there.
     */
    private func unpackExtent(_ wanted: Int, into output: inout Data, at offset: Int, cursor: inout Int, blocksize: Int) throws {
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
            let block = try self.read(at: cursor + 12, count: info.compressed)
            cursor += 12 + info.compressed
            if info.compressed < info.uncompressed {
                try output.withUnsafeMutableBytes { buffer in
                    let destination = UnsafeMutableRawBufferPointer(rebasing: buffer[offset ..< offset + info.uncompressed])
                    try Self.decompress(block, method: info.method, into: destination)
                    if info.filter != 0 {
                        try Self.unfilter(destination, id: info.filter, cto: info.cto)
                    }
                }
            } else {
                output.replaceSubrange(offset ..< offset + info.uncompressed, with: block)
            }
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
     `data` decompressed by UPX method `method` into `destination`, which it must fill: NRV2B, NRV2D and NRV2E by UCL
     (`UCLBridge`), LZMA by liblzma (`LZMABridge`).
     */
    private static func decompress(_ data: Data, method: UInt8, into destination: UnsafeMutableRawBufferPointer) throws {
        let decompressed = data.withUnsafeBytes { source in
            method == 14 ? LZMABridge.decompress(source, into: destination) : UCLBridge.decompress(source, method: method, into: destination) ?? false
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
            throw UnpackError.cantUnpack("unknown filter 0x\(String(id, radix: 16))")
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
        }

        /// The header at the start of `p`, checked as `getPackHeader` checks it; throws, in UPX's words, for one that
        /// does not hold.
        private static func decode(_ p: Data, fileSize: Int) throws -> (size: Int, version: UInt8, format: UInt8) {
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
                uncompressed >= 2
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
            return (size, version, format)
        }
    }
}

extension MachO {
    /// The 32-bit word at `offset` in `data`, in the image's byte order: UPX's `get_te32`.
    func word(_ data: Data, at offset: Int) -> UInt32 {
        self.sw(data.dropFirst(offset).withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) })
    }
}
