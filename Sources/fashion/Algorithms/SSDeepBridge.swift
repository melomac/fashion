import CSSDeep
import Foundation

/**
 Bridge to libfuzzy (ssdeep) for fuzzy hashing.
 */
enum SSDeepBridge {
    /**
     Compute ssdeep hash for a file.
     */
    static func hash(path: String) -> String? {
        var result = [CChar](repeating: 0, count: Int(148))

        let rc = fuzzy_hash_filename(path, &result)
        guard rc == 0 else {
            return nil
        }

        let truncated = result.prefix(while: { $0 != 0 })
        return String(decoding: truncated.map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }

    /**
     Compute ssdeep hash for raw data.
     */
    static func hash(data: Data) -> String? {
        var result = [CChar](repeating: 0, count: Int(148))

        let rc = data.withUnsafeBytes { ptr -> Int32 in
            guard let base = ptr.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                return -1
            }
            return fuzzy_hash_buf(base, UInt32(ptr.count), &result)
        }
        guard rc == 0 else {
            return nil
        }

        let truncated = result.prefix(while: { $0 != 0 })
        return String(decoding: truncated.map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }

    /**
     Compare two ssdeep signatures. Returns similarity score 0–100.
     */
    static func compare(_ sig1: String, _ sig2: String) -> Int {
        let score = fuzzy_compare(sig1, sig2)
        return Int(score)
    }
}
