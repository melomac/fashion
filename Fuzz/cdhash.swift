@testable import fashion
import Foundation

/**
 `CDHash.hash` over the input, whole and cut at its logical end (--exact). It reaches:

 - the superblob of the embedded signature, and its code directories;
 - the slot validator, which checks every page of code against its slot, and lists the pages that fail with the
   names of what they hold;
 - the rehash of an invalid signature: the hashes of the failed pages and of the sealed blobs, written into a copy
   of each code directory;
 - the ad-hoc directory built for an unsigned slice, and for a slice whose signature is rejected.
 */
@_cdecl("LLVMFuzzerTestOneInput")
public func fuzzCDHash(_ start: UnsafeRawPointer, _ count: Int) -> CInt {
    let file = Fuzz.file(start, count)

    _ = try? CDHash.hash(file, path: "input", exact: false)
    _ = try? CDHash.hash(file, path: "input", exact: true)

    return 0
}
