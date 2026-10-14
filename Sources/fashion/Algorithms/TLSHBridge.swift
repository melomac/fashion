import CTLSH
import Foundation

/**
 Bridge to libtlsh (Trend Micro Locality Sensitive Hash), fed through `TLSHHasher`.

 fashion feeds libtlsh at most `maximumDataSize` bytes of a file (`ByteHash.maximumLength`), where a naive caller
 would feed it the whole file. Two things in the library make a longer input undefined:

 - `TlshImpl` counts its input in a 32-bit `data_len` (`tlsh_impl.h`), which every `update` advances: past 4 GiB it
   wraps, and the digest then describes a length the data does not have.
 - `final` turns that length into the digest's L value with `l_capturing` (`tlsh_util.cpp`), a binary search over the
   170-entry `topval` table, whose last entry is 4,224,281,216 (3.93 GiB): a longer input makes the search read past
   the table, undefined behaviour in C++, before the counter even wraps.

 Trend Micro left the C++ library as it is and defined the TLSH of a longer input as that of its first
 `maximumDataSize` bytes (trendmicro/tlsh#88), the Java port's `TlshUtil.MAX_DATA_LENGTH` since TLSH 4.6.0. fashion
 applies that definition whatever libtlsh it is built against: the cap changes no digest under it, and two files
 that differ only past it share a digest, where the Java port, which refuses more, makes none.

 Two more things are this build's rather than the library's. The digest is the 70-digit `T1` form of a 128-bucket,
 1-byte-checksum build (`BUCKETS_128` and `CHECKSUM_1B` in Package.swift, see `tlsh_version.h`), the form the `tlsh`
 tool prints. And libtlsh makes no digest for an input under its `MIN_DATA_LENGTH` of 50 bytes, or with too little
 variety: `TLSHHasher.finalize` reports that as nil, not as the empty string `getHash` returns, and `caveat` says which.
 */
enum TLSHBridge {
    /**
     Maximum data size fed to libtlsh.

     This is `topval[169]` from `tlsh_util.cpp` — the last entry in the `l_capturing()` lookup table.
     Beyond this value, the binary search in `l_capturing()` reads out of bounds (UB in C++), before `data_len`, the
     32-bit counter in `tlsh_impl.h`, would even wrap past 4 GiB.
     The Java port enforces the same limit as `TlshUtil.MAX_DATA_LENGTH`.

     - the bug, a file past 2 GiB crashing the Java port and "too small" for the tlsh tool:
       https://github.com/trendmicro/tlsh/issues/84
     - the Java fix of TLSH 4.6.0 (branch `bugfix_issue_99`), counting up to this limit and refusing any more:
       https://github.com/trendmicro/tlsh/pull/100
     - the decision, "TLSH is the TLSH of the first 4GB of a file":
       https://github.com/trendmicro/tlsh/issues/88#issuecomment-870946795
     */
    static let maximumDataSize: UInt64 = 4_224_281_216

    /**
     Expected digest version prefix.
     */
    static let digestPrefix = "T1"

    /**
     The bug an input past `maximumDataSize` runs into (trendmicro/tlsh#84), named when one is hashed; Trend Micro
     settled on the cap in trendmicro/tlsh#88.
     */
    static let maximumDataSizeIssue = "https://github.com/trendmicro/tlsh/issues/84"

    /**
     What the digest of `length` bytes leaves out, which libtlsh never says: every byte when it made no `digest`, too
     few for its `MIN_DATA_LENGTH` or with too little variation, or those past `maximumDataSize`. Nil when the digest
     is of every byte.

     Worded after the TLSH tools: the tlsh tool's "cannot hash" and "file too small", the Python port's "less than 50 of
     input" and "not enough variation in input", the Java port's "Can only compute length portion of TLSH for data
     lengths up to 4224281216 bytes".
     */
    static func caveat(length: Int, digest: String?) -> String? {
        let hashed = min(length, Int(self.maximumDataSize))
        guard digest != nil else {
            // `TlshImpl::final` checks the length first, then that more than half of its buckets are filled.
            let minimum = Int(tlsh_min_data_length())
            if hashed < minimum {
                return "TLSH cannot hash: input too small (\(String(hashed, pluralizing: "byte")), minimum \(minimum))"
            }
            return "TLSH cannot hash: not enough variation in \(hashed < length ? "the first \(hashed) bytes" : "input")"
        }
        return hashed < length ? "TLSH hashed the first \(hashed) bytes only, it's a known issue: \(self.maximumDataSizeIssue)" : nil
    }

    /**
     Compute distance between two TLSH hashes. Lower = more similar. Returns -1 on error, including for a string that is
     not a whole digest.

     Without `length`, the file lengths the digests record are left out, like the tlsh tool's `-xlen`: a file padded
     with zeros is then as close as its content.
     */
    static func diff(_ hash1: String, _ hash2: String, length: Bool = true) -> Int {
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

        return Int(tlsh_total_diff(t1, t2, length ? 1 : 0))
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

    deinit {
        tlsh_free(self.context)
    }

    func update(_ bytes: UnsafeRawBufferPointer) {
        guard let base = bytes.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
            return
        }
        tlsh_update(self.context, base, UInt32(bytes.count))
    }

    /**
     The upper-case `T1` digest, or nil when libtlsh makes none: for an input under `MIN_DATA_LENGTH` (50 bytes) or
     too uniform for one.
     */
    func finalize() -> String? {
        tlsh_final(self.context)
        guard let cString = tlsh_get_hash(self.context, 1) else {
            return nil
        }
        let hash = String(cString: cString)
        return hash.isEmpty ? nil : hash.uppercased()
    }
}
