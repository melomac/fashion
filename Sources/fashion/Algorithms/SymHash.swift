import Foundation
import MachO

/// Extract external undefined symbols from Mach-O binaries and compute a hash.
enum SymHash {
    struct SymHashResult {
        let digest: String
        let arch: String?
    }

    static func compute(_ file: File, algorithm: ByteHash, separator: String, sortSymbols: Bool) throws -> [SymHashResult] {
        switch try MachOParser.open(file) {
        case let .fat(archs):
            return try archs.compactMap { arch in
                // A universal static library carries `ar` archives, which have no symbol table to hash.
                guard
                    let image = try MachO(file, offset: arch.range.lowerBound, length: arch.range.count),
                    let digest = try self.hash(image, algorithm: algorithm, separator: separator, sortSymbols: sortSymbols)
                else {
                    return nil
                }
                return SymHashResult(digest: digest, arch: MachOParser.archName(cpuType: arch.cpuType, cpuSubtype: arch.cpuSubtype))
            }
        case let .thin(image):
            guard let digest = try self.hash(image, algorithm: algorithm, separator: separator, sortSymbols: sortSymbols) else {
                return []
            }
            return [SymHashResult(digest: digest, arch: nil)]
        case .notMachO:
            return []
        }
    }

    // MARK: - Private

    /**
     The symhash of one image, or nil when it carries no symbol table.
     */
    private static func hash(_ image: MachO, algorithm: ByteHash, separator: String, sortSymbols: Bool) throws -> String? {
        guard
            let command = image.findCommand(UInt32(LC_SYMTAB)),
            let symtab = try MachOParser.parseSymtab(command: command, swap: image.swap)
        else {
            return nil
        }

        // The names stay bytes, sorted in byte order: text would replace invalid UTF-8 and order names as Unicode does.
        var names = try MachOParser.externalSymbolNames(file: image.file, offset: image.offset, length: image.length, symtab: symtab, is64: image.is64, swap: image.swap)
        if sortSymbols {
            names.sort { $0.lexicographicallyPrecedes($1) }
        }

        var joinedData = Data()
        for (index, name) in names.enumerated() {
            if index > 0 {
                joinedData.append(contentsOf: separator.utf8)
            }
            joinedData.append(name)
        }

        return try algorithm.digest(joinedData)
    }
}
