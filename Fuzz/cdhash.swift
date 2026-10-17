@testable import fashion
import Foundation

/**
 `CDHash.hash`: the embedded signature's superblob and code directories, the slot validator streaming the code past
 them, and the ad-hoc synthesis of an unsigned or rejected slice, whole and trimmed to its logical end (--exact).
 */
@_cdecl("LLVMFuzzerTestOneInput")
public func fuzzCDHash(_ start: UnsafeRawPointer, _ count: Int) -> CInt {
    guard let file = Fuzz.file(start, count) else {
        return 0
    }

    _ = try? CDHash.hash(file, path: "input", exact: false)
    _ = try? CDHash.hash(file, path: "input", exact: true)

    return 0
}
