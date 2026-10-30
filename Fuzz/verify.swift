@testable import fashion
import Foundation

/**
 `fashion verify` over the input as a file: `Universal.open`, then `MachOVerifier` over the universal file and each
 slice against its table entry, and over each image, every group of rules, the padding and the signature's pages
 read, the superblob's blobs against their slots, and `Signer` over the CMS blob, through Security's decoder and
 trustd; what the parser or Security refuses, the way the command reports it. The findings are dropped.
 */
@_cdecl("LLVMFuzzerTestOneInput")
public func fuzzVerify(_ start: UnsafeRawPointer, _ count: Int) -> CInt {
    try? Verify.verify(Fuzz.file(start, count)) { _, _ in } refused: { _, _ in }
    return 0
}
