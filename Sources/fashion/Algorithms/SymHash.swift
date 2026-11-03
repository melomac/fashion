import Foundation
import MachO

/// Extract external undefined symbols from Mach-O binaries and compute a hash.
enum SymHash {
    /**
     The symhash of a thin Mach-O, or of each architecture of a universal one, labeled with its name
     (`Universal.named`), by each of `algorithms`. `caveat` hears what TLSH leaves out of a symbol list, with the name
     of its architecture. Hash mode goes through `digests(of:)` instead, state by state, and labels each itself.
     */
    static func compute(_ file: File, algorithms: [ByteHash], separator: String, sortSymbols: Bool, caveat: (_ arch: String?, _ message: String) -> Void = { _, _ in }) throws -> [DigestResult] {
        switch try Universal.open(file) {
        case let .fat(archs):
            try Universal.named(archs).flatMap { arch, name -> [DigestResult] in
                // A universal static library carries `ar` archives, which have no symbol table to hash.
                guard let image = try MachO(file, offset: arch.offset, length: arch.length) else {
                    return []
                }
                return try self.hash(image, algorithms: algorithms, separator: separator, sortSymbols: sortSymbols, caveat: { caveat(name, $0) })
                    .map { DigestResult(digest: $0.digest, algorithm: $0.hash.algorithm, label: name) }
            }
        case let .thin(image):
            try self.hash(image, algorithms: algorithms, separator: separator, sortSymbols: sortSymbols, caveat: { caveat(nil, $0) })
                .map { DigestResult(digest: $0.digest, algorithm: $0.hash.algorithm) }
        case .notMachO:
            []
        }
    }

    /**
     The symhash of `file` as one thin image, a state of a slice as `ArtifactWriter.slices` cuts it, by each of
     `algorithms`; none for what is not a thin Mach-O, an archive among a universal file's slices say.
     */
    static func digests(of file: File, algorithms: [ByteHash], separator: String, sortSymbols: Bool, caveat: (String) -> Void) throws -> [(hash: ByteHash, digest: String)] {
        guard let image = try MachO(file) else {
            return []
        }
        return try self.hash(image, algorithms: algorithms, separator: separator, sortSymbols: sortSymbols, caveat: caveat)
    }

    // MARK: - Symbol Table

    /**
     The most bytes of external symbol names a symbol table may add up to (64 MiB): overlapping names let a small crafted
     table reach gigabytes.
     */
    static let maxSymbolNamesLength = 64 << 20

    /**
     The most external symbols a symbol table may hold (a million): each costs some 40 bytes of the arrays that index,
     hold and order its name before a byte of it is read, which names that are empty, or one name shared, never count
     against `maxSymbolNamesLength`; a 64 MB table of four million nameless symbols took 216 MiB. The largest binary at
     hand, swift-frontend, holds some 49,000.
     */
    static let maxExternalSymbols = 1_000_000

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

     Neither table is held whole: the entries are read in chunks, no more than `maxExternalSymbols` of them wanted, and
     the string table in windows that start at the names wanted, skipping what lies between them. Names may overlap in
     a string table, so one NUL can end several: they share one buffer, bounded by `maxSymbolNamesLength` rather than by
     the file. The names are checked in table order, as they would be one at a time: an index past the string table is
     an error unless the names before it already went beyond the limit.

     The image is `length` bytes at `offset` in `file`, which its `symtab` offsets count from; `is64` and `swap` describe
     its header.

     ```text
      LC_SYMTAB (24): cmd | cmdsize | symoff | nsyms | stroff | strsize
                                        |                 |
      symoff ---------------------------+                 +--------------------------- stroff
        |                                                                                |
        v  nlist_64 (16), nlist (12) in a 32-bit image      v  the string table, strsize bytes
        +-------------------------------------------+      +-----------------------------------+
        | n_strx (4)  ------------------------------+----> | \0 | name \0 | name \0 | ...       |
        | n_type (1)   N_EXT set, no N_STAB bits,   |      +-----------------------------------+
        |              N_TYPE N_UNDF: wanted        |        index 0 is the empty name; a name is read to
        | n_sect (1) | n_desc (2) | n_value (8)     |        its NUL, and several indexes may share one
        +-------------------------------------------+
        × nsyms, read in chunks                              read in windows starting at the names wanted
     ```
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
            try entries.withUnsafeBytes { raw in
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
                    guard indexes.count < self.maxExternalSymbols else {
                        throw ParserError.tooManyExternalSymbols(limit: self.maxExternalSymbols)
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
        var total = 0
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
                    try close()
                    at += 1
                }
            }
            windowStart = at
        }
        // Names still open run to the end of the table.
        try close()

        /// The names open, each a copy of its bytes, since a slice would keep the group's whole buffer alive, counted
        /// against the limit as they close rather than at the end, so that no more than the limit is ever held.
        func close() throws {
            for symbol in open {
                names[symbol] = Data(pending[(indexes[symbol] - pendingStart)...])
                total += names[symbol].count
                guard total <= self.maxSymbolNamesLength else {
                    throw ParserError.symbolNamesTooLong(limit: self.maxSymbolNamesLength)
                }
            }
            open.removeAll()
        }
        if let badIndex {
            throw badIndex
        }
        return names
    }

    // MARK: - Private

    /**
     The symhash of one image by each algorithm; none when it carries no symbol table, as a UPX stub carries none,
     which `caveat` is told, "no external symbol table", as `verify` names it.
     */
    private static func hash(_ image: MachO, algorithms: [ByteHash], separator: String, sortSymbols: Bool, caveat: (String) -> Void) throws -> [(hash: ByteHash, digest: String)] {
        guard
            let command = image.findCommand(UInt32(LC_SYMTAB)),
            let symtab = try self.parseSymtab(command: command, swap: image.swap)
        else {
            caveat("no external symbol table")
            return []
        }

        // The names stay bytes, sorted in byte order: text would replace invalid UTF-8 and order names as Unicode does.
        var names = try self.externalSymbolNames(file: image.file, offset: image.offset, length: image.length, symtab: symtab, is64: image.is64, swap: image.swap)
        if sortSymbols {
            names.sort { $0.lexicographicallyPrecedes($1) }
        }

        // The hashers are fed the names one by one, the separator between them, rather than a joined copy of them all.
        let separator = Data(separator.utf8)
        let length = names.reduce(0) { $0 + $1.count } + max(0, names.count - 1) * separator.count
        return try ByteHash.digests(algorithms, length: length, caveat: caveat) { fanOut in
            for (index, name) in names.enumerated() {
                if index > 0 {
                    separator.withUnsafeBytes { fanOut.update($0) }
                }
                name.withUnsafeBytes { fanOut.update($0) }
            }
        }
    }
}
