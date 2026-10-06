import CSSDeep
import Foundation
import System

enum SSDeepError: Error, Equatable {
    case fileHashFailed(status: Int)
}

extension SSDeepError: LocalizedError {
    var errorDescription: String? {
        switch self {
        case let .fileHashFailed(status):
            "ssdeep failed to hash the file (status \(status))"
        }
    }
}

/**
 Bridge to libfuzzy (ssdeep) for fuzzy hashing.
 */
enum SSDeepBridge {
    /// Result buffer size mandated by libfuzzy: `FUZZY_MAX_RESULT`, which Swift cannot import, from the `SPAMSUM_LENGTH` it can.
    fileprivate static let resultSize = 2 * Int(SPAMSUM_LENGTH) + 20

    /**
     Compare two ssdeep signatures. Returns similarity score 0–100.
     */
    static func compare(_ sig1: String, _ sig2: String) -> Int {
        let score = fuzzy_compare(sig1, sig2)
        return Int(score)
    }
}

/**
 A running ssdeep hash, told its length up front as `fuzzy_hash_buf` and `fuzzy_hash_file` do: libfuzzy then skips the
 block sizes it cannot use, and fails the digest when it is fed any other length.
 */
final class SSDeepHasher: ByteHasher {
    private let state: OpaquePointer

    init(length: Int) throws {
        guard let state = fuzzy_new() else {
            throw Errno(rawValue: errno)
        }
        self.state = state
        guard fuzzy_set_total_input_length(state, UInt64(length)) == 0 else {
            throw Errno(rawValue: errno)
        }
    }

    deinit {
        fuzzy_free(self.state)
    }

    func update(_ bytes: UnsafeRawBufferPointer) {
        // Empty input has no base address, and feeding it nothing yields the "3::" signature.
        if let base = bytes.baseAddress?.assumingMemoryBound(to: UInt8.self) {
            _ = fuzzy_update(self.state, base, bytes.count) // only counts and steps: never fails
        }
    }

    func finalize() throws -> String? {
        var result = [CChar](repeating: 0, count: SSDeepBridge.resultSize)
        let status = fuzzy_digest(self.state, &result, 0)
        guard status == 0 else {
            throw SSDeepError.fileHashFailed(status: Int(status))
        }
        return String(decoding: result.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }
}
