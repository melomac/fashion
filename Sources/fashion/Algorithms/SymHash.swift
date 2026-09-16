import Foundation
import MachO

/// Extract external undefined symbols from Mach-O binaries and compute a hash.
enum SymHash {
    struct SymHashResult {
        let digest: String
        let arch: String?
    }

    static func compute(path: String, algorithm: Algorithm, separator: String, sortSymbols: Bool) throws -> [SymHashResult] {
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
        guard let symtab = slice.loadCommands.lazy.compactMap({ MachOParser.parseSymtab(command: $0, swap: slice.swap) }).first else {
            return nil
        }

        var names = try MachOParser.externalSymbolNames(data: slice.data, symtab: symtab, is64: slice.is64, swap: slice.swap)
        if sortSymbols {
            names.sort()
        }

        let joinedData = Data(names.joined(separator: separator).utf8)

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
