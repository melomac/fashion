import CMachOCompat // CPU_SUBTYPE_ARM64E_X1 on SDKs older than macOS 27
import Foundation
import MachO
import MachO.dyld.utils // macho_arch_name_for_cpu_type

/**
 A Mach-O file as Security's `Universal` reads it: a thin image, or a universal file's architectures. Anything else,
 including a file too short for a Mach-O header, is not Mach-O.
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

        /// Its name, as `codesign --arch` spells it (see `archName`), like Security's `Architecture::name`.
        var name: String {
            Universal.archName(cpuType: self.cpuType, cpuSubtype: self.cpuSubtype)
        }
    }

    // MARK: - Open

    /**
     Open a Mach-O and reject an incomplete header, load-command table, or fat architecture table.

     A fat architecture is checked to lie inside the file; what it contains is left to each consumer,
     since a universal static library carries `ar` archives rather than Mach-O slices.
     */
    static func open(_ file: File) throws -> Universal {
        // A file shorter than a 32-bit mach_header is not Mach-O code to Security (MachORep::candidate), so a
        // magic-only stub (a truncated Java class, say) is an ordinary file.
        guard file.size >= self.minimumSize else {
            return .notMachO
        }

        if let image = try MachO(file) {
            return .thin(image)
        }

        let head = try file.read(at: 0, count: 8)
        switch head.withUnsafeBytes({ $0.loadUnaligned(as: UInt32.self) }) {
        case FAT_MAGIC, FAT_CIGAM:
            return try self.parseFat(file, head: head, is64: false)
        case FAT_MAGIC_64, FAT_CIGAM_64:
            return try self.parseFat(file, head: head, is64: true)
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
        switch try self.open(file) {
        case let .thin(image):
            image.logicalEnd()
        case let .fat(archs):
            archs.map { $0.offset + $0.length }.max() ?? file.size
        case .notMachO:
            file.size
        }
    }

    // MARK: - Private

    /**
     Label for a slice neither the OS nor the fallback table can name, in `lipo -archs` style: `unknown(16777228,13)`.
     */
    private static func unknownArchName(cpuType: cpu_type_t, cpuSubtype: cpu_subtype_t) -> String {
        "unknown(\(cpuType),\(cpuSubtype))"
    }

    /**
     The fewest bytes a Mach-O file holds: `MachORep::candidate` reads a 32-bit `mach_header` before it considers a file
     Mach-O code at all, and `codesign` signs any shorter one as a generic file.
     */
    private static let minimumSize = MemoryLayout<mach_header>.size

    /**
     The most slices a universal file holds, dyld's `mach_o::Universal::kMaxSliceCount`.

     Compiled Java class data shares the 0xCAFEBABE magic.
     Universal binaries have a small, big-endian, architecture count.
     */
    static let maxSliceCount: UInt32 = 16

    private static func parseFat(_ file: File, head: Data, is64: Bool) throws -> Universal {
        let nfatArch: UInt32 = head.withUnsafeBytes { ptr in
            UInt32(bigEndian: ptr.loadUnaligned(fromByteOffset: 4, as: UInt32.self))
        }

        guard 1 ... self.maxSliceCount ~= nfatArch else {
            return .notMachO
        }

        // fat_arch: cputype(4) cpusubtype(4) offset(4) size(4) align(4) = 20 bytes.
        // fat_arch_64: cputype(4) cpusubtype(4) offset(8) size(8) align(4) reserved(4) = 32 bytes.
        let entrySize = is64 ? 32 : 20
        let tableSize = 8 + Int(nfatArch) * entrySize
        guard tableSize <= file.size else {
            throw ParserError.invalidFatArchitectureTable(count: nfatArch, fileSize: file.size)
        }

        return try file.read(at: 0, count: tableSize).withUnsafeBytes { ptr in
            var archs: [Architecture] = []

            for architectureIndex in 0 ..< Int(nfatArch) {
                let entry = 8 + architectureIndex * entrySize
                let sliceOffset: UInt64
                let sliceSize: UInt64
                if is64 {
                    sliceOffset = UInt64(bigEndian: ptr.loadUnaligned(fromByteOffset: entry + 8, as: UInt64.self))
                    sliceSize = UInt64(bigEndian: ptr.loadUnaligned(fromByteOffset: entry + 16, as: UInt64.self))
                } else {
                    sliceOffset = UInt64(UInt32(bigEndian: ptr.loadUnaligned(fromByteOffset: entry + 8, as: UInt32.self)))
                    sliceSize = UInt64(UInt32(bigEndian: ptr.loadUnaligned(fromByteOffset: entry + 12, as: UInt32.self)))
                }

                // Every slice must start after the table and end inside the file. Int(exactly:) and the
                // subtraction keep a crafted 64-bit fat from trapping on conversion or overflow.
                guard
                    let start = Int(exactly: sliceOffset),
                    let size = Int(exactly: sliceSize),
                    start >= tableSize,
                    size > 0,
                    start <= file.size,
                    size <= file.size - start
                else {
                    throw ParserError.invalidFatArchitectureRange(offset: sliceOffset, size: sliceSize, fileSize: file.size)
                }

                archs.append(Architecture(
                    cpuType: cpu_type_t(bigEndian: ptr.loadUnaligned(fromByteOffset: entry, as: cpu_type_t.self)),
                    cpuSubtype: cpu_subtype_t(bigEndian: ptr.loadUnaligned(fromByteOffset: entry + 4, as: cpu_subtype_t.self)),
                    offset: start,
                    length: size,
                ))
            }

            return .fat(archs)
        }
    }
}
