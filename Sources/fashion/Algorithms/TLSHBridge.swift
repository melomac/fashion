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
 The Java port enforces this via `MAX_DATA_LENGTH` = topval[169]; we apply the same cap here.

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
     Compute TLSH hash for a file. Streams in chunks to avoid loading the entire file into memory.
     Data beyond maximumDataSize (~3.93 GiB) is ignored per the TLSH specification (issue #99).
     Returns nil if file is too small or hashing fails.
     */
    static func hash(path: String) throws -> String? {
        let t = tlsh_new()
        defer {
            tlsh_free(t)
        }

        // Cap the data fed to libtlsh at maximumDataSize (~3.93 GiB) per issue #99 (fail-closed).
        let limit = Int(clamping: self.maximumDataSize)
        var totalSize = 0
        try FileReader.read(path: path, limit: limit) { chunk in
            guard let base = chunk.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                return
            }
            tlsh_update(t, base, UInt32(chunk.count))
            totalSize += chunk.count
        }

        guard totalSize >= self.minimumDataSize else {
            return nil
        }

        tlsh_final(t)

        guard let cStr = tlsh_get_hash(t, 1) else {
            return nil
        }

        let hashStr = String(cString: cStr)
        guard !hashStr.isEmpty else {
            return nil
        }

        return hashStr.uppercased()
    }

    /**
     Compute TLSH hash for raw data. Returns nil if data is too small.

     Data beyond maximumDataSize (~3.93 GiB) is ignored per the TLSH specification (issue #99).
     */
    static func hash(data: Data) -> String? {
        guard data.count >= self.minimumDataSize else {
            return nil
        }

        let t = tlsh_new()
        defer {
            tlsh_free(t)
        }

        let usableCount = min(data.count, Int(clamping: self.maximumDataSize))

        data.withUnsafeBytes { ptr in
            guard let base = ptr.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                return
            }
            let chunkSize = 1 << 20 // 1MB
            var offset = 0
            while offset < usableCount {
                let len = min(chunkSize, usableCount - offset)
                tlsh_update(t, base.advanced(by: offset), UInt32(len))
                offset += len
            }
        }
        tlsh_final(t)

        guard let cStr = tlsh_get_hash(t, 1) else {
            return nil
        }

        let hashStr = String(cString: cStr)
        guard !hashStr.isEmpty else {
            return nil
        }

        return hashStr.uppercased()
    }

    /**
     Compute distance between two TLSH hashes. Lower = more similar. Returns -1 on error.
     */
    static func diff(_ hash1: String, _ hash2: String) -> Int {
        let h1 = self.stripPrefix(hash1)
        let h2 = self.stripPrefix(hash2)

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

    private static func stripPrefix(_ hash: String) -> String {
        let upper = hash.uppercased()
        if upper.hasPrefix(self.digestPrefix) {
            return String(hash.dropFirst(self.digestPrefix.count))
        }
        return hash
    }
}
