@testable import fashion
import Foundation

/**
 The digest comparisons of --match: `TLSHBridge.diff` on two strings, with and without the length they record, and
 `SSDeepBridge.compare`. The input is two strings around its first NUL, or one string against itself.
 */
@_cdecl("LLVMFuzzerTestOneInput")
public func fuzzDiff(_ start: UnsafeRawPointer, _ count: Int) -> CInt {
    let bytes = UnsafeRawBufferPointer(start: start, count: count)
    let parts = bytes.split(separator: 0, maxSplits: 1, omittingEmptySubsequences: false)
    let first = String(decoding: parts[0], as: UTF8.self)
    let second = parts.count > 1 ? String(decoding: parts[1], as: UTF8.self) : first

    _ = TLSHBridge.diff(first, second)
    _ = TLSHBridge.diff(second, first, length: false)
    _ = TLSHBridge.caveat(length: count, digest: first)
    _ = SSDeepBridge.compare(first, second)

    return 0
}
