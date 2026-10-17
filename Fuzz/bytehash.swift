@testable import fashion
import Foundation

/**
 The byte hashes whose C code reads the bytes themselves, ssdeep's and TLSH's, and git's, which writes a header
 first: over the input streamed from a file, whole in memory, and from its second byte on.
 */
@_cdecl("LLVMFuzzerTestOneInput")
public func fuzzByteHash(_ start: UnsafeRawPointer, _ count: Int) -> CInt {
    let data = Fuzz.data(start, count)
    guard let file = Fuzz.file(start, count) else {
        return 0
    }

    for hash in [ByteHash.ssdeep, .tlsh, .git] {
        _ = try? hash.digest(file)
        _ = try? hash.digest(data)
        if count > 1 {
            _ = try? hash.digest(file, range: 1 ..< count)
        }
    }

    return 0
}
