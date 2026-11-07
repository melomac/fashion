import CMachOCompat // CPU_SUBTYPE_ARM64E_X1 on SDKs older than macOS 27
import Foundation
import MachO
import MachO.dyld.utils // macho_arch_name_for_cpu_type

/**
 What is wrong with one architecture of a universal file, and which: the error its Mach-O, its edit or its read threw,
 which a diagnostic names after the architecture, as verify names what it refuses, where the file alone would not say
 which slice is at fault. It describes itself as the error does.
 */
struct SliceError: Error {
    let arch: String
    let error: Error
}

extension SliceError: LocalizedError {
    var errorDescription: String? {
        File.message(for: self.error)
    }
}

/**
 A Mach-O file as Security's `Universal` reads it: a thin image, or a universal file's architectures. Anything else,
 including a file too short for a Mach-O header, is not Mach-O.

 A universal file, big-endian throughout, as `lipo` lays it out:

 ```text
  0x0000 +-----------------------------------------------+
         | fat_header (8): magic 0xcafebabe | nfat_arch  |  0xcafebabf for a table of fat_arch_64
  0x0008 +-----------------------------------------------+
         | fat_arch (20): cputype | cpusubtype |         |  fat_arch_64 (32): offset and size on 8 bytes,
         |                 offset | size | align         |  then reserved
         | fat_arch ...                                  |  nfat_arch entries, which the kernel reads
         +-----------------------------------------------+
         | fat_arch, one past the count                  |  read by Security and dyld, a slice when it names
         |                                               |  arm64: what `lipo -hideARM64` leaves (32-bit tables)
         +-----------------------------------------------+
         | padding to 2^align                            |
  offset +-----------------------------------------------+
         | slice: a thin Mach-O, or an ar archive        |  size bytes, which the table alone decides, as for
         +-----------------------------------------------+  `lipo -thin`; the next slice at its own offset
 ```
 */
enum Universal {
    case fat([Architecture])
    case thin(MachO)
    case notMachO

    /**
     One architecture of a universal file: its CPU, and where it lies as a `MachO` opens it.
     */
    struct Architecture {
        let cpuType: cpu_type_t
        let cpuSubtype: cpu_subtype_t
        /// Where the architecture lies in its file, which `parseFat` has checked it fits.
        let offset: Int
        let length: Int
        /// The entry's alignment, as a power of two, which `lipo` writes and Security bounds the padding before a slice by.
        let align: UInt32
        /// Whether the entry lies past the table's count: the arm64 slice `lipo -hideARM64` hides (see `parseFat`).
        let hidden: Bool

        /// Its name, as `codesign --arch` spells it (see `archName`), like Security's `Architecture::name`.
        var name: String {
            Universal.archName(cpuType: self.cpuType, cpuSubtype: self.cpuSubtype)
        }
    }

    /**
     Each architecture of a universal file with the name it goes by in what is said, hashed or written of it: its
     `name`, and for two slices of one architecture, which the kernel refuses, the second numbered, `x86_64_2`, so
     that a digest, a diagnostic or an artifact of either tells which one. The order is the table's.
     */
    static func named(_ archs: [Architecture]) -> [(arch: Architecture, name: String)] {
        var counts: [String: Int] = [:]
        return archs.map { arch in
            let count = counts[arch.name, default: 0] + 1
            counts[arch.name] = count
            return (arch, count == 1 ? arch.name : "\(arch.name)_\(count)")
        }
    }

    // MARK: - Open

    /**
     Open a Mach-O and reject an incomplete header, load-command table, or fat architecture table.

     A fat architecture is checked to lie inside the file; what it contains is left to each consumer,
     since a universal static library carries `ar` archives rather than Mach-O slices. A 32-bit table is read one
     entry past its count, as Security's `Universal` reads it, and that entry is an architecture when it names arm64,
     the only one of a table that counts none. One that names arm64 but does not lie in the file is no slice here,
     as hash mode takes the file, and `hiddenRefused` is told its name and what is wrong with it: dyld refuses the
     file for it, which verify says.
     */
    static func open(_ file: File, hiddenRefused: ((_ name: String, _ error: ParserError) -> Void)? = nil) throws -> Universal {
        // MachORep::candidate reads a 32-bit mach_header before it considers a file Mach-O code at all, so a magic-only
        // stub (a truncated Java class, say) is an ordinary file, which codesign signs as such.
        guard file.size >= MemoryLayout<mach_header>.size else {
            return .notMachO
        }

        // One read serves the magic, the header and load commands of a thin image, or the table of a universal file.
        let head = try file.read(at: 0, count: min(file.size, MachO.headSize))
        if let image = try MachO(file, head: head) {
            return .thin(image)
        }

        switch head.withUnsafeBytes({ $0.loadUnaligned(as: UInt32.self) }) {
        case FAT_MAGIC, FAT_CIGAM:
            return try self.parseFat(file, head: head, is64: false, hiddenRefused: hiddenRefused)
        case FAT_MAGIC_64, FAT_CIGAM_64:
            return try self.parseFat(file, head: head, is64: true, hiddenRefused: hiddenRefused)
        default:
            return .notMachO
        }
    }

    // MARK: - Architecture Naming

    /**
     The architecture name of a slice, as `codesign --arch` spells it.

     Names come from the OS's own Mach-O naming (`macho_arch_name_for_cpu_type`, the table `codesign` draws on),
     so every subtype the running OS knows — `arm64e.x1`, `x86_64h`, `armv7k`… — is spelled the way Apple's tools
     spell it, capability bits included.

     A slice the OS cannot name (newer than the OS, or legacy `ppc64`) falls
     back to a built-in table. The closed families there keep their base name for any subtype; the still-growing
     arm64 family labels an unrecognized subtype `unknown(cputype,cpusubtype)` like `lipo -archs`, because a
     base name `codesign --arch` would resolve to some other slice.
     */
    static func archName(cpuType: cpu_type_t, cpuSubtype: cpu_subtype_t) -> String {
        if let name = macho_arch_name_for_cpu_type(cpuType, cpuSubtype) {
            return String(cString: name)
        }

        let masked = cpuSubtype & ~cpu_subtype_t(bitPattern: CPU_SUBTYPE_MASK)
        switch cpuType {
        case CPU_TYPE_ARM64:
            switch masked {
            case CPU_SUBTYPE_ARM64_ALL, CPU_SUBTYPE_ARM64_V8:
                return "arm64"
            case CPU_SUBTYPE_ARM64E:
                return "arm64e"
            case CPU_SUBTYPE_ARM64E_X1:
                return "arm64e.x1"
            default:
                return self.unknownArchName(cpuType: cpuType, cpuSubtype: masked)
            }
        case CPU_TYPE_ARM64_32:
            return "arm64_32"
        case CPU_TYPE_X86_64:
            return "x86_64"
        case CPU_TYPE_I386:
            return "i386"
        case CPU_TYPE_ARM:
            return "arm"
        case CPU_TYPE_POWERPC:
            return "ppc"
        case CPU_TYPE_POWERPC64:
            return "ppc64"
        default:
            return self.unknownArchName(cpuType: cpuType, cpuSubtype: masked)
        }
    }

    // MARK: - Logical Extent

    /**
     The logical end of an entire file: a thin Mach-O ends where `MachO.logicalEnd()` ends its image,
     a fat binary trims to the end of its last architecture slice, and any other input is left whole.

     Bytes beyond this are trailing slack appended after the Mach-O content.
     Throws when a Mach-O is malformed or a fat architecture range cannot address bytes within the file.
     */
    static func fileEnd(_ file: File) throws -> Int {
        try self.fileEnd(of: self.open(file), size: file.size)
    }

    /// The same of a file `size` bytes long as `opened` lays it out, read already.
    static func fileEnd(of opened: Universal, size: Int) -> Int {
        switch opened {
        case let .thin(image):
            image.logicalEnd()
        case let .fat(archs):
            archs.map { $0.offset + $0.length }.max() ?? size
        case .notMachO:
            size
        }
    }

    // MARK: - Private

    /**
     Label for a slice neither the OS nor the fallback table can name, in `lipo -archs` style: `unknown(16777228,13)`.
     */
    private static func unknownArchName(cpuType: cpu_type_t, cpuSubtype: cpu_subtype_t) -> String {
        "unknown(\(cpuType),\(cpuSubtype))"
    }

    /// The most slices a universal file holds, dyld's `kMaxSliceCount`: a Java class, 0xCAFEBABE too, declares far more.
    static let maxSliceCount: UInt32 = 16

    /**
     The most entries the kernel reads, as many as fit after the header in the page it maps a file's head from
     (`fatfile_validate_fatarches`): 204 on a 4 KiB page, 818 on a 16 KiB one. A universal file of more entries than
     `maxSliceCount` runs, one slice of it.
     */
    static let kernelSliceCount = UInt32((16384 - MemoryLayout<fat_header>.size) / MemoryLayout<fat_arch>.size)

    /**
     The architectures of a universal file with more entries than `open` reads, up to `kernelSliceCount`, each
     checked as `open` checks them; nil for any other file, or a table an entry of which does not lie in the file,
     as a Java class, 0xCAFEBABE too, has its major version and then anything where the entries would be. What
     `verify` names, where hash mode takes the file for no Mach-O.
     */
    static func oversized(_ file: File) throws -> [Architecture]? {
        guard file.size >= MemoryLayout<fat_header>.size else {
            return nil
        }
        let head = try file.read(at: 0, count: min(file.size, MachO.headSize))
        let is64 = switch head.withUnsafeBytes({ $0.loadUnaligned(as: UInt32.self) }) {
        case FAT_MAGIC, FAT_CIGAM: false
        case FAT_MAGIC_64, FAT_CIGAM_64: true
        default: nil as Bool?
        }
        guard let is64 else {
            return nil
        }
        do {
            guard case let .fat(archs) = try self.parseFat(file, head: head, is64: is64, counting: self.maxSliceCount + 1 ... self.kernelSliceCount) else {
                return nil
            }
            return archs
        } catch is ParserError {
            return nil
        }
    }

    private static func parseFat(_ file: File, head: Data, is64: Bool, counting counts: ClosedRange<UInt32> = 0 ... Universal.maxSliceCount, hiddenRefused: ((_ name: String, _ error: ParserError) -> Void)? = nil) throws -> Universal {
        let nfatArch: UInt32 = head.withUnsafeBytes { ptr in
            UInt32(bigEndian: ptr.loadUnaligned(fromByteOffset: 4, as: UInt32.self))
        }

        guard counts ~= nfatArch else {
            return .notMachO
        }

        let entrySize = is64 ? MemoryLayout<fat_arch_64>.size : MemoryLayout<fat_arch>.size
        let tableSize = MemoryLayout<fat_header>.size + Int(nfatArch) * entrySize
        guard tableSize <= file.size else {
            throw ParserError.invalidFatArchitectureTable(count: nfatArch, fileSize: file.size)
        }

        // Security's `Universal` reads a 32-bit table one entry past its count, and counts that entry when it names
        // arm64 (its "Hack alert", 15001604): the layout `lipo -hideARM64` wrote, whose arm64 slice dyld loads too
        // ("Look for one more slice") where the kernel, `file` and most tools read the count alone. Neither has a
        // count below which it looks: a table that counts no entry and hides an arm64 slice is that slice to both.
        let extra = !is64 && tableSize + entrySize <= file.size
        let read = tableSize + (extra ? entrySize : 0)
        let table = read <= head.count ? head : try file.read(at: 0, count: read)
        return try table.withUnsafeBytes { ptr in
            var archs: [Architecture] = []

            for architectureIndex in 0 ..< Int(nfatArch) + (extra ? 1 : 0) {
                let hidden = architectureIndex == Int(nfatArch)
                let entry = 8 + architectureIndex * entrySize
                let cpuType = cpu_type_t(bigEndian: ptr.loadUnaligned(fromByteOffset: entry, as: cpu_type_t.self))
                if hidden, cpuType != CPU_TYPE_ARM64 {
                    break
                }
                let sliceOffset: UInt64
                let sliceSize: UInt64
                let align: UInt32
                if is64 {
                    sliceOffset = UInt64(bigEndian: ptr.loadUnaligned(fromByteOffset: entry + 8, as: UInt64.self))
                    sliceSize = UInt64(bigEndian: ptr.loadUnaligned(fromByteOffset: entry + 16, as: UInt64.self))
                    align = UInt32(bigEndian: ptr.loadUnaligned(fromByteOffset: entry + 24, as: UInt32.self))
                } else {
                    sliceOffset = UInt64(UInt32(bigEndian: ptr.loadUnaligned(fromByteOffset: entry + 8, as: UInt32.self)))
                    sliceSize = UInt64(UInt32(bigEndian: ptr.loadUnaligned(fromByteOffset: entry + 12, as: UInt32.self)))
                    align = UInt32(bigEndian: ptr.loadUnaligned(fromByteOffset: entry + 16, as: UInt32.self))
                }

                // Every slice must start after the table and end inside the file. Int(exactly:) and the
                // subtraction keep a crafted 64-bit fat from trapping on conversion or overflow. A hidden entry that
                // does not is no slice here, where the table's own are: dyld checks it as it checks them and refuses
                // the file (`Universal::valid`), which the caller is told for verify to say.
                guard
                    let start = Int(exactly: sliceOffset),
                    let size = Int(exactly: sliceSize),
                    start >= (hidden ? read : tableSize),
                    size > 0,
                    start <= file.size,
                    size <= file.size - start
                else {
                    let error = ParserError.invalidFatArchitectureRange(offset: sliceOffset, size: sliceSize, fileSize: file.size)
                    if hidden {
                        let cpuSubtype = cpu_subtype_t(bigEndian: ptr.loadUnaligned(fromByteOffset: entry + 4, as: cpu_subtype_t.self))
                        hiddenRefused?(self.archName(cpuType: cpuType, cpuSubtype: cpuSubtype), error)
                        break
                    }
                    throw error
                }

                archs.append(Architecture(
                    cpuType: cpuType,
                    cpuSubtype: cpu_subtype_t(bigEndian: ptr.loadUnaligned(fromByteOffset: entry + 4, as: cpu_subtype_t.self)),
                    offset: start,
                    length: size,
                    align: align,
                    hidden: hidden,
                ))
            }

            // A table that counts no entry is a universal file by its hidden slice alone.
            return archs.isEmpty ? .notMachO : .fat(archs)
        }
    }
}
