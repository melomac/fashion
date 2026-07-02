import CSSDeep
import Foundation

/**
 Bridge to libfuzzy (ssdeep) for fuzzy hashing.
 */
enum SSDeepBridge {
    /// Result buffer size mandated by libfuzzy (`FUZZY_MAX_RESULT` = 2 * SPAMSUM_LENGTH + 20).
    private static let resultSize = 2 * 64 + 20

    /**
     Compute ssdeep hash for a file.
     */
    static func hash(path: String) -> String? {
        var result = [CChar](repeating: 0, count: self.resultSize)

        guard fuzzy_hash_filename(path, &result) == 0 else {
            return nil
        }

        return self.decode(result)
    }

    /**
     Compute ssdeep hash for raw data.

     Uses the streaming API so the input is not bounded by `fuzzy_hash_buf`'s 32-bit length argument;
     the digest is identical to hashing the whole buffer in one call.
     */
    static func hash(data: Data) -> String? {
        guard let state = fuzzy_new() else {
            return nil
        }
        defer {
            fuzzy_free(state)
        }

        let updated = data.withUnsafeBytes { ptr -> Bool in
            guard let base = ptr.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                // Empty input has no base address; feeding zero bytes is valid and yields the "3::" signature.
                return ptr.count == 0
            }
            return fuzzy_update(state, base, ptr.count) == 0
        }
        guard updated else {
            return nil
        }

        var result = [CChar](repeating: 0, count: self.resultSize)
        guard fuzzy_digest(state, &result, 0) == 0 else {
            return nil
        }

        return self.decode(result)
    }

    /**
     Compare two ssdeep signatures. Returns similarity score 0–100.
     */
    static func compare(_ sig1: String, _ sig2: String) -> Int {
        let score = fuzzy_compare(sig1, sig2)
        return Int(score)
    }

    // MARK: - Private

    private static func decode(_ result: [CChar]) -> String {
        let truncated = result.prefix(while: { $0 != 0 })
        return String(decoding: truncated.map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }
}
