import Foundation
import MachO

/// Extract external undefined symbols from Mach-O binaries and compute a hash.
enum SymHash {
    struct SymHashResult {
        let digest: String
        let arch: String?
    }

    static func compute(path: String, algorithm: Algorithm, separator: String, sortSymbols: Bool) throws -> [SymHashResult] {
        // Peek at the magic first: mapping reads a whole file on a volume Foundation deems unsafe (a mounted disk image).
        guard try MachOParser.isMachO(path: path) else {
            return []
        }

        let data = try FileReader.map(path: path)

        switch try MachOParser.open(data: data) {
        case let .fat(archs):
            return try archs.compactMap { arch in
                // A universal static library carries `ar` archives, which have no symbol table to hash.
                guard
                    let slice = try MachOSlice(MachOParser.sliceData(fileData: data, arch: arch)),
                    let digest = try self.hash(slice, algorithm: algorithm, separator: separator, sortSymbols: sortSymbols)
                else {
                    return nil
                }
                return SymHashResult(digest: digest, arch: MachOParser.archName(cpuType: arch.cpuType, cpuSubtype: arch.cpuSubtype))
            }
        case let .thin(slice):
            guard let digest = try self.hash(slice, algorithm: algorithm, separator: separator, sortSymbols: sortSymbols) else {
                return []
            }
            return [SymHashResult(digest: digest, arch: nil)]
        case .notMachO:
            return []
        }
    }

    // MARK: - Private

    /**
     The symhash of one slice, or nil when it carries no symbol table.
     */
    private static func hash(_ slice: MachOSlice, algorithm: Algorithm, separator: String, sortSymbols: Bool) throws -> String? {
        guard
            let command = slice.findCommand(UInt32(LC_SYMTAB)),
            let symtab = try MachOParser.parseSymtab(command: command, swap: slice.swap)
        else {
            return nil
        }

        // The names stay bytes, sorted in byte order: text would replace invalid UTF-8 and order names as Unicode does.
        var names = try MachOParser.externalSymbolNames(data: slice.data, symtab: symtab, is64: slice.is64, swap: slice.swap)
        if sortSymbols {
            names.sort { slice.data.bytes(in: $0).lexicographicallyPrecedes(slice.data.bytes(in: $1)) }
        }

        var joinedData = Data()
        for (index, name) in names.enumerated() {
            if index > 0 {
                joinedData.append(contentsOf: separator.utf8)
            }
            joinedData.append(slice.data.bytes(in: name))
        }

        switch algorithm {
        case .ssdeep:
            return SSDeepBridge.hash(data: joinedData)
        case .tlsh:
            return TLSHBridge.hash(data: joinedData)
        default:
            return try CryptoDigest.hash(data: joinedData, algorithm: algorithm)
        }
    }
}
