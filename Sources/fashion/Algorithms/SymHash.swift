import Foundation
import MachO

/// Extract external undefined symbols from Mach-O binaries and compute a hash.
enum SymHash {
    struct SymHashResult {
        let digest: String
        let arch: String?
    }

    static func compute(path: String, algorithm: Algorithm, separator: String, sortSymbols: Bool) throws -> [SymHashResult] {
        let data = try Data(contentsOf: URL(fileURLWithPath: path), options: .mappedIfSafe)
        let binaryType = MachOParser.open(data: data)

        switch binaryType {
        case let .fat(archs):
            var results: [SymHashResult] = []
            for arch in archs {
                let slice = MachOParser.sliceData(fileData: data, arch: arch)
                if let digest = try hashSlice(data: slice, algorithm: algorithm, separator: separator, sortSymbols: sortSymbols) {
                    let name = MachOParser.archName(cpuType: arch.cpuType, cpuSubtype: arch.cpuSubtype)
                    results.append(SymHashResult(digest: digest, arch: name))
                }
            }
            return results

        case .thin:
            if let digest = try hashSlice(data: data, algorithm: algorithm, separator: separator, sortSymbols: sortSymbols) {
                return [SymHashResult(digest: digest, arch: nil)]
            }
            return []

        case .notMachO:
            return []
        }
    }

    // MARK: - Private

    private static func hashSlice(data: Data, algorithm: Algorithm, separator: String, sortSymbols: Bool) throws -> String? {
        let commands = MachOParser.loadCommands(data: data)

        guard
            let symtabCmd = commands.first(where: { $0.cmd == UInt32(LC_SYMTAB) }),
            let symtab = MachOParser.parseSymtab(command: symtabCmd)
        else {
            return nil
        }

        let symbols = MachOParser.readSymbols(data: data, symtab: symtab)
        let mask = UInt8(N_STAB | N_EXT | N_TYPE)

        var names: [String] = symbols.compactMap { symbol in
            guard symbol.n_type & mask == UInt8(N_EXT) else {
                return nil
            }
            return MachOParser.symbolName(data: data, stroff: symtab.stroff, strx: symbol.n_un.n_strx)
        }

        if sortSymbols {
            names.sort()
        }

        let joined = names.joined(separator: separator)
        let joinedData = Data(joined.utf8)

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
