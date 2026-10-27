import Foundation
import MachO

/**
 What `verify` names about a Mach-O image: not what the parser refuses, the loader's own rules, which come out red, but
 what no loader refuses and a researcher wants named, one line each, read from the headers alone. The rules are
 dyld's where it has one, `validSegments` and its kin, Security's for what it only calls suspicious, and this tool's
 for what its other flags undo: bytes appended past the image, a signature that came out, UPX.
 */
extension MachO {
    /// A segment command's fields, in the image's byte order.
    private struct Segment {
        let name: String
        let vmaddr: UInt64
        let vmsize: UInt64
        let fileoff: UInt64
        let filesize: UInt64
        let initprot: Int32

        var protection: String {
            [(VM_PROT_READ, "r"), (VM_PROT_WRITE, "w"), (VM_PROT_EXECUTE, "x")].map { self.initprot & $0.0 != 0 ? $0.1 : "-" }.joined()
        }

        /// Whether the segment's address and vmsize add up past the address space, which no loader maps.
        var wraps: Bool {
            self.vmaddr.addingReportingOverflow(self.vmsize).overflow
        }

        /// Where the segment ends in memory, the address space's end where its range wraps around.
        var vmend: UInt64 {
            self.wraps ? UInt64.max : self.vmaddr + self.vmsize
        }
    }

    private var segments: [Segment] {
        self.loadCommands.compactMap { command in
            switch command.cmd {
            case UInt32(LC_SEGMENT):
                command.payload(as: segment_command.self).map { Segment(name: command.segmentName, vmaddr: UInt64(self.sw($0.vmaddr)), vmsize: UInt64(self.sw($0.vmsize)), fileoff: UInt64(self.sw($0.fileoff)), filesize: UInt64(self.sw($0.filesize)), initprot: self.sw($0.initprot)) }
            case UInt32(LC_SEGMENT_64):
                command.payload(as: segment_command_64.self).map { Segment(name: command.segmentName, vmaddr: self.sw($0.vmaddr), vmsize: self.sw($0.vmsize), fileoff: self.sw($0.fileoff), filesize: self.sw($0.filesize), initprot: self.sw($0.initprot)) }
            default:
                nil
            }
        }
    }

    /**
     What is odd about the image, in `file`, one line each and none for an image with nothing to say: segments out of
     order or overlapping, in the file or in memory, a file size past a vmsize, an address range that wraps around,
     `__TEXT` not at the file's start or too small for the load commands, `__LINKEDIT` not last, protections other than
     r-x, r-- and rw- on the three, an executable without an entry point or with one outside `__TEXT`, an image no
     version command dates, bytes appended past the image's end, a `__LINKEDIT` vmsize a signature rounded on an image
     that has none, and UPX, packed as is, by a modified UPX, or signed after packing. A dSYM companion, which dsymutil
     lays out with `__TEXT` empty and `__DWARF` after `__LINKEDIT`, and no loader maps, has nothing to say.
     */
    func anomalies(in file: File) -> [String] {
        guard self.filetype != UInt32(MH_DSYM) else {
            return []
        }
        var found: [String] = []
        let segments = self.segments
        let loaded = segments.filter { $0.filesize > 0 }
        let mapped = segments.filter { $0.vmsize > 0 }
        for (before, after) in zip(loaded, loaded.dropFirst()) where after.fileoff < before.fileoff {
            found.append("segment \(after.name)'s file offset \(after.fileoff.hex) is out of order after \(before.name)'s \(before.fileoff.hex)")
        }
        for (before, after) in zip(mapped, mapped.dropFirst()) where after.vmaddr < before.vmaddr {
            found.append("segment \(after.name)'s address \(after.vmaddr.hex) is out of order after \(before.name)'s \(before.vmaddr.hex)")
        }
        for (index, one) in loaded.enumerated() {
            for other in loaded.dropFirst(index + 1) where one.fileoff < other.fileoff + other.filesize && other.fileoff < one.fileoff + one.filesize {
                found.append("segments \(one.name) and \(other.name) overlap in the file")
            }
        }
        for (index, one) in mapped.enumerated() {
            for other in mapped.dropFirst(index + 1) where one.vmaddr < other.vmend && other.vmaddr < one.vmend {
                found.append("segments \(one.name) and \(other.name) overlap in memory")
            }
        }
        for segment in segments where segment.filesize > segment.vmsize {
            found.append("segment \(segment.name)'s file size \(segment.filesize.hex) exceeds its vmsize \(segment.vmsize.hex)")
        }
        for segment in mapped where segment.wraps {
            found.append("segment \(segment.name)'s address \(segment.vmaddr.hex) and vmsize \(segment.vmsize.hex) wrap around the address space")
        }

        let headerSize = self.is64 ? MemoryLayout<mach_header_64>.size : MemoryLayout<mach_header>.size
        let text = segments.first { $0.name == "__TEXT" }
        if let text {
            if text.fileoff != 0 {
                found.append("__TEXT starts at file offset \(text.fileoff.hex), not 0")
            }
            if text.filesize < UInt64(headerSize + self.sizeofcmds) {
                found.append("the load commands, \((headerSize + self.sizeofcmds).hex) bytes, do not fit in __TEXT's \(text.filesize.hex)")
            }
            if text.protection != "r-x" {
                found.append("__TEXT's protection is \(text.protection), not r-x")
            }
        } else if [MH_EXECUTE, MH_DYLIB, MH_BUNDLE].contains(Int32(self.filetype)) {
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

        if self.filetype == UInt32(MH_EXECUTE) {
            if let main = self.findCommand(UInt32(LC_MAIN))?.payload(as: entry_point_command.self) {
                let entry = self.sw(main.entryoff)
                if let text, entry < text.fileoff || entry >= text.fileoff + text.filesize {
                    found.append("LC_MAIN's entry at \(entry.hex) lies outside __TEXT")
                }
            } else if self.findCommand(UInt32(LC_UNIXTHREAD)) == nil {
                found.append("no LC_MAIN nor LC_UNIXTHREAD for an executable")
            }
        }
        if (try? self.version()) ?? nil == nil {
            found.append("no LC_BUILD_VERSION nor LC_VERSION_MIN_* dates it")
        }

        let end = self.logicalEnd()
        if end < self.length {
            found.append("\((self.length - end).hex) bytes appended past the image's end at \(end.hex)")
        }

        // codesign rounds __LINKEDIT's vmsize up to 16 KiB when it signs, and leaves it so when it removes the
        // signature, where ld64 and strip round it as `linkeditSizeRounding` says: more than that, on an image without a
        // signature, is a signature's residue.
        if self.findCommand(UInt32(LC_CODE_SIGNATURE)) == nil, let linkedit = segments.last(where: { $0.name == "__LINKEDIT" }), linkedit.filesize > 0 {
            let rounding = UInt64(self.linkeditSizeRounding)
            let expected = (linkedit.filesize + rounding - 1) & ~(rounding - 1)
            if linkedit.vmsize % 0x4000 == 0, linkedit.vmsize > expected {
                found.append("__LINKEDIT's vmsize \(linkedit.vmsize.hex) is a signature's 16 KiB rounding on an image without one: a signature came out")
            }
        }

        // UPX: as it is, or behind a signature added after packing, which hides the 16-byte __LINKEDIT UPX left.
        if let packed = try? PackMach(self) {
            found.append(packed.packer)
        } else if self.findCommand(UInt32(LC_CODE_SIGNATURE)) != nil, let pieces = (try? MachOEditor.unsigned(self, end: self.length)) ?? nil, let unsigned = (try? MachO(File(editing: file, pieces: pieces))) ?? nil, let packed = try? PackMach(unsigned) {
            found.append("\(packed.packer), signed after packing")
        }
        return found
    }
}

extension MachO.LoadCommand {
    /// A segment command's name, up to its first NUL.
    var segmentName: String {
        String(decoding: self.data.dropFirst(8).prefix(16).prefix { $0 != 0 }, as: UTF8.self)
    }
}
