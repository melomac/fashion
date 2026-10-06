import CTLSHWrapper
import Foundation

/**
 Bridge to libtlsh for fuzzy hashing (Trend Micro Locality Sensitive Hash).

 The upstream C++ library (trendmicro/tlsh) has two related issues with large files:

 1. The total data length accumulator is an unsigned int (32-bit) in `tlsh_impl.h` line 160, which wraps past ~4 GiB.

 2. The Lvalue is computed by `l_capturing()` (`tlsh_util.cpp` line 4877), a binary search over a hardcoded lookup table (topval[170])
   The last entry is topval[169] = 4,224,281,216 (~3.93 GiB).
   Data lengths beyond this cause an out-of-bounds read — undefined behavior in C++.

 Trend Micro acknowledged the issue (GitHub issue #99, version 4.6.0) and defined the TLSH of a file as the TLSH of its first ~4 GiB.
 The Java port enforces this via `MAX_DATA_LENGTH` = topval[169]; `ByteHash.maximumLength` applies the same cap.

 The cap is applied unconditionally (fail-closed): capping never changes a result for the common
 sub-4 GiB case and can only ever truncate a pathologically large input, so it is always safe — unlike
 gating it on a runtime version string, which would silently re-expose the C++ undefined behavior if the
 string ever changed.
 */
enum TLSHBridge {
    /**
     Minimum data size for TLSH computation.
     */
    static let minimumDataSize = 50

    /**
     Maximum data size fed to libtlsh when linked against a T1 build.

     This is topval[169] from `tlsh_util.cpp` — the last entry in the `l_capturing()` lookup table.
     Beyond this value, the binary search in `l_capturing()` reads out of bounds (UB in C++).
     The Java port enforces the same limit as `TlshUtil.MAX_DATA_LENGTH`.

     See:
     https://github.com/trendmicro/tlsh/blob/master/src/tlsh_util.cpp#L4872
     https://github.com/trendmicro/tlsh/blob/master/include/tlsh_impl.h#L160
     */
    static let maximumDataSize: UInt64 = 4_224_281_216

    /**
     Expected digest version prefix.
     */
    static let digestPrefix = "T1"

    /**
     Compute distance between two TLSH hashes. Lower = more similar. Returns -1 on error, including for a string that is
     not a whole digest.
     */
    static func diff(_ hash1: String, _ hash2: String) -> Int {
        guard
            let h1 = self.digits(of: hash1),
            let h2 = self.digits(of: hash2)
        else {
            return -1
        }

        let t1 = tlsh_new()
        let t2 = tlsh_new()
        defer {
            tlsh_free(t1)
            tlsh_free(t2)
        }

        guard
            tlsh_from_str(t1, h1) == 0,
            tlsh_from_str(t2, h2) == 0
        else {
            return -1
        }

        return Int(tlsh_total_diff(t1, t2, 1))
    }

    /**
     Close a running hash and return its upper-case `T1` digest, or nil when libtlsh produced none.
     */
    fileprivate static func digest(of context: tlsh_t?) -> String? {
        tlsh_final(context)

        guard let cString = tlsh_get_hash(context, 1) else {
            return nil
        }

        let hash = String(cString: cString)
        return hash.isEmpty ? nil : hash.uppercased()
    }

    /**
     The 70 hex digits of a digest as this build makes them (128 buckets, a 1-byte checksum), after an optional `T1`
     prefix; nil for any other string. `tlsh_from_str` reads the digits it needs and refuses only a 71st one, so it would
     take a digest followed by anything else.
     */
    private static func digits(of hash: String) -> String? {
        let digits = hash.uppercased().hasPrefix(self.digestPrefix) ? hash.dropFirst(self.digestPrefix.count) : hash[...]
        let isHexDigit = { (byte: UInt8) in (UInt8(ascii: "0") ... UInt8(ascii: "9")).contains(byte) || (UInt8(ascii: "a") ... UInt8(ascii: "f")).contains(byte | 0x20) }
        guard
            digits.utf8.count == 70,
            digits.utf8.allSatisfy(isHexDigit)
        else {
            return nil
        }
        return String(digits)
    }
}

/**
 A running TLSH hash, fed at most `TLSHBridge.maximumDataSize` bytes (see `ByteHash.maximumLength`).
 */
final class TLSHHasher: ByteHasher {
    private let context = tlsh_new()
    private var length = 0

    deinit {
        tlsh_free(self.context)
    }

    func update(_ bytes: UnsafeRawBufferPointer) {
        guard let base = bytes.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
            return
        }
        tlsh_update(self.context, base, UInt32(bytes.count))
        self.length += bytes.count
    }

    /**
     The digest, or nil below `TLSHBridge.minimumDataSize` bytes or when libtlsh makes none.
     */
    func finalize() -> String? {
        guard self.length >= TLSHBridge.minimumDataSize else {
            return nil
        }
        return TLSHBridge.digest(of: self.context)
    }
}
