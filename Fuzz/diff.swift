@testable import fashion
import Foundation

/**
 The digests --match is given: their shape, which names their algorithm without `--algo` (`Targets.shape`, `fits`),
 their typing into `Targets`, and the comparisons it makes, `TLSHBridge.diff` on two strings, with and without the
 length they record, and `SSDeepBridge.compare`. The input is two strings around its first NUL, or one string against
 itself.
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

    _ = Targets.shape(of: first)
    for algorithm in Algorithm.allCases {
        _ = Targets.fits(first, algorithm)
    }
    let targets = Targets([first, second])
    for algorithm in targets.algorithms {
        _ = targets.match(second, algorithm: algorithm, threshold: 50)
        _ = targets.match(second, algorithm: algorithm, threshold: 50, xlen: true)
    }
    for algorithm in Algorithm.allCases {
        _ = Targets([first], algorithm: algorithm).match(second, algorithm: algorithm, threshold: 0)
    }
    return 0
}
