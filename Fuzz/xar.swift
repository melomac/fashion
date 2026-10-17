@testable import fashion
import Foundation

/**
 `XARParser.hashToc`: the header, then the table of contents as stored and inflated through zlib, hashed by a
 CryptoKit hash and by each fuzzy hash.
 */
@_cdecl("LLVMFuzzerTestOneInput")
public func fuzzXAR(_ start: UnsafeRawPointer, _ count: Int) -> CInt {
    _ = try? XARParser.parseHeader(data: Fuzz.data(start, count))
    guard let file = Fuzz.file(start, count) else {
        return 0
    }

    _ = try? XARParser.hashToc(file, algorithm: .sha1, decompress: false)
    for algorithm in [ByteHash.sha1, .ssdeep, .tlsh] {
        _ = try? XARParser.hashToc(file, algorithm: algorithm, decompress: true)
    }

    return 0
}
