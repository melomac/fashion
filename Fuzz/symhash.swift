@testable import fashion
import Foundation

/**
 `SymHash.compute`: the symbol table and the string table of each slice, the names windowed out of the latter, then
 joined and hashed, sorted by a CryptoKit hash and in table order by TLSH.
 */
@_cdecl("LLVMFuzzerTestOneInput")
public func fuzzSymHash(_ start: UnsafeRawPointer, _ count: Int) -> CInt {
    guard let file = Fuzz.file(start, count) else {
        return 0
    }

    _ = try? SymHash.compute(file, algorithms: [.md5], separator: ",", sortSymbols: true)
    _ = try? SymHash.compute(file, algorithms: [.tlsh], separator: "\n", sortSymbols: false)

    return 0
}
