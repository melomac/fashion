import Foundation
import MachO

/// Extract external undefined symbols from Mach-O binaries and compute a hash.
enum SymHash {
    /**
     The symhash of a thin Mach-O, or of each architecture of a universal one, labeled with its name.
     */
    static func compute(_ file: File, algorithm: ByteHash, separator: String, sortSymbols: Bool) throws -> [DigestResult] {
        switch try Universal.open(file) {
        case let .fat(archs):
            return try archs.compactMap { arch in
                // A universal static library carries `ar` archives, which have no symbol table to hash.
                guard
                    let image = try MachO(file, offset: arch.range.lowerBound, length: arch.range.count),
                    let digest = try self.hash(image, algorithm: algorithm, separator: separator, sortSymbols: sortSymbols)
                else {
                    return nil
                }
                return DigestResult(digest: digest, label: arch.name)
            }
        case let .thin(image):
            guard let digest = try self.hash(image, algorithm: algorithm, separator: separator, sortSymbols: sortSymbols) else {
                return []
            }
            return [DigestResult(digest: digest)]
        case .notMachO:
            return []
        }
    }

    // MARK: - Symbol Table

    /**
     The most bytes of external symbol names a symbol table may add up to (64 MiB): overlapping names let a small crafted
     table reach gigabytes.
     */
    static let maxSymbolNamesLength = 64 << 20

    /**
     The `symtab_command` of an `LC_SYMTAB`, nil for any other command. Throws for one too short to hold it: Security
     checks a symbol table command only before `__LINKEDIT`, so a slice can parse with a later one cut short.
     */
    static func parseSymtab(command: MachO.LoadCommand, swap: Bool = false) throws -> symtab_command? {
        guard command.cmd == UInt32(LC_SYMTAB) else {
            return nil
        }

        let raw = try command.load(symtab_command.self)

        guard swap else {
            return raw
        }

        return symtab_command(
            cmd: raw.cmd.byteSwapped,
            cmdsize: raw.cmdsize.byteSwapped,
            symoff: raw.symoff.byteSwapped,
            nsyms: raw.nsyms.byteSwapped,
            stroff: raw.stroff.byteSwapped,
            strsize: raw.strsize.byteSwapped,
        )
    }

    /**
     The names of the external undefined symbols in a symbol table, in table order: entries whose type is exactly
     `N_EXT`, with no `N_STAB` bits and the `N_UNDF` section type, and each name up to its NUL or the end of the table.

     Neither table is held whole: the entries are read in chunks, and the string table in windows that start at the names
     wanted, skipping what lies between them. Names may overlap in a string table, so one NUL can end several: they share
     one buffer, bounded by `maxSymbolNamesLength` rather than by the file. The names are checked in table order, as they
     would be one at a time: an index past the string table is an error unless the names before it already went beyond
     the limit.

     The image is `length` bytes at `offset` in `file`, which its `symtab` offsets count from; `is64` and `swap` describe
     its header.
     */
    static func externalSymbolNames(file: File, offset: Int, length: Int, symtab: symtab_command, is64: Bool, swap: Bool) throws -> [Data] {
        // 32-bit slices use the 12-byte `nlist`, 64-bit the 16-byte `nlist_64`; n_strx and n_type sit at the
        // same offsets in both.
        let entrySize = is64 ? MemoryLayout<nlist_64>.size : MemoryLayout<nlist>.size
        let symbolOffset = Int(symtab.symoff)
        guard
            symbolOffset <= length,
            Int(symtab.nsyms) <= (length - symbolOffset) / entrySize
        else {
            throw ParserError.invalidSymbolTableRange(offset: symtab.symoff, count: symtab.nsyms, fileSize: length)
        }
        let tableOffset = Int(symtab.stroff)
        let tableSize = Int(symtab.strsize)
        guard
            tableOffset <= length,
            tableSize <= length - tableOffset
        else {
            throw ParserError.invalidStringTableRange(offset: symtab.stroff, size: symtab.strsize, fileSize: length)
        }

        // The string index of each external undefined symbol, up to the first one past the table.
        let mask = UInt8(N_STAB | N_EXT | N_TYPE)
        let batch = File.chunkSize / entrySize
        var indexes: [Int] = []
        var badIndex: ParserError?
        for first in stride(from: 0, to: Int(symtab.nsyms), by: batch) where badIndex == nil {
            let count = min(batch, Int(symtab.nsyms) - first)
            let entries = try file.read(at: offset + symbolOffset + first * entrySize, count: count * entrySize)
            entries.withUnsafeBytes { raw in
                for base in stride(from: 0, to: count * entrySize, by: entrySize) where badIndex == nil {
                    guard raw.loadUnaligned(fromByteOffset: base + 4, as: UInt8.self) & mask == UInt8(N_EXT) else {
                        continue
                    }
                    let strx = raw.loadUnaligned(fromByteOffset: base, as: UInt32.self)
                    let index = swap ? strx.byteSwapped : strx
                    guard index < symtab.strsize else {
                        badIndex = .invalidStringTableIndex(index: index, tableSize: symtab.strsize)
                        continue
                    }
                    indexes.append(Int(index))
                }
            }
        }

        // Each wanted name opens where it starts and closes, with every other one open, at the next NUL. The symbols
        // are visited in the order of their names in the table, which several may share.
        var names = [Data](repeating: Data(), count: indexes.count)
        var order = indexes.indices.sorted { indexes[$0] < indexes[$1] }[...]
        var open: [Int] = []
        var pending = Data()
        var pendingStart = 0
        var windowStart = order.first.map { indexes[$0] } ?? tableSize
        windows: while windowStart < tableSize {
            // A window reaches 16 KiB past the last name wanted, where the names of real tables end; a longer name
            // reads on from where the window ends.
            let count = min(File.chunkSize, tableSize - windowStart, order.last.map { indexes[$0] - windowStart + 16384 } ?? File.chunkSize)
            let window = try file.read(at: offset + tableOffset + windowStart, count: count)
            let windowEnd = windowStart + window.count
            var at = windowStart
            while at < windowEnd {
                if open.isEmpty {
                    guard let symbol = order.first else {
                        break windows
                    }
                    at = indexes[symbol]
                    guard at < windowEnd else {
                        break
                    }
                    pending = Data()
                    pendingStart = at
                }
                while let symbol = order.first, indexes[symbol] == at {
                    open.append(order.removeFirst())
                }

                let stop = min(windowEnd, order.first.map { indexes[$0] } ?? windowEnd)
                let nul = window[(at - windowStart) ..< (stop - windowStart)].firstIndex(of: 0)
                let end = nul.map { windowStart + $0 } ?? stop
                pending.append(window[(at - windowStart) ..< (end - windowStart)])
                guard pending.count <= self.maxSymbolNamesLength else {
                    throw ParserError.symbolNamesTooLong(limit: self.maxSymbolNamesLength)
                }
                at = end
                if nul != nil {
                    for symbol in open {
                        names[symbol] = pending[(indexes[symbol] - pendingStart)...]
                    }
                    open.removeAll()
                    at += 1
                }
            }
            windowStart = at
        }
        // Names still open run to the end of the table.
        for symbol in open {
            names[symbol] = pending[(indexes[symbol] - pendingStart)...]
        }

        let total = names.reduce(0) { $0 + $1.count }
        guard total <= self.maxSymbolNamesLength else {
            throw ParserError.symbolNamesTooLong(limit: self.maxSymbolNamesLength)
        }
        if let badIndex {
            throw badIndex
        }
        return names
    }

    // MARK: - Private

    /**
     The symhash of one image, or nil when it carries no symbol table.
     */
    private static func hash(_ image: MachO, algorithm: ByteHash, separator: String, sortSymbols: Bool) throws -> String? {
        guard
            let command = image.findCommand(UInt32(LC_SYMTAB)),
            let symtab = try self.parseSymtab(command: command, swap: image.swap)
        else {
            return nil
        }

        // The names stay bytes, sorted in byte order: text would replace invalid UTF-8 and order names as Unicode does.
        var names = try self.externalSymbolNames(file: image.file, offset: image.offset, length: image.length, symtab: symtab, is64: image.is64, swap: image.swap)
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
