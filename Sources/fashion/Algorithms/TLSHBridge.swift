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
 `maximumDataSize` bytes (trendmicro/tlsh#99), the Java port's `TlshUtil.MAX_DATA_LENGTH` since TLSH 4.6.0. fashion
 applies that definition whatever libtlsh it is built against: the cap changes no digest under it, and two files
 that differ only past it share a digest, as they do in Java, rather than have none that is defined.

 Two more things are this build's rather than the library's. The digest is the 70-digit `T1` form of a 128-bucket,
 1-byte-checksum build (`BUCKETS_128` and `CHECKSUM_1B` in Package.swift, see `tlsh_version.h`), the form the `tlsh`
 tool prints. And libtlsh makes no digest for an input under its `MIN_DATA_LENGTH` of 50 bytes, or with too little
 variety: `TLSHHasher.finalize` reports that as nil, not as the empty string `getHash` returns.
 */
enum TLSHBridge {
    /**
     Maximum data size fed to libtlsh.

     This is `topval[169]` from `tlsh_util.cpp` — the last entry in the `l_capturing()` lookup table.
     Beyond this value, the binary search in `l_capturing()` reads out of bounds (UB in C++), before `data_len`, the
     32-bit counter in `tlsh_impl.h`, would even wrap past 4 GiB.
     The Java port enforces the same limit as `TlshUtil.MAX_DATA_LENGTH`.

     See, at the submodule's commit:
     https://github.com/trendmicro/tlsh/blob/ebdec8fde93a4ac359437f4f3796c78d3ae433bf/src/tlsh_util.cpp#L4872
     https://github.com/trendmicro/tlsh/blob/ebdec8fde93a4ac359437f4f3796c78d3ae433bf/include/tlsh_impl.h#L163
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
