@testable import fashion
import Foundation

/**
 `Universal.open` and what the scan reads from a `MachO`: the fat architecture table, the header and load-command
 table, every command an accessor loads, and the logical end of each ending.
 */
@_cdecl("LLVMFuzzerTestOneInput")
public func fuzzMachO(_ start: UnsafeRawPointer, _ count: Int) -> CInt {
    guard let file = Fuzz.file(start, count) else {
        return 0
    }
    Fuzz.walk(file)
    _ = try? Universal.fileEnd(file)
    _ = try? MachO(lenient: file)?.logicalEnd()
    return 0
}
