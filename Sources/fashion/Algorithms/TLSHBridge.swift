import CTLSHWrapper
import Foundation
import System

/**
 Bridge to libtlsh for fuzzy hashing (Trend Micro Locality Sensitive Hash).

 The upstream C++ library (trendmicro/tlsh) has two related issues with large files:

 1. The total data length accumulator is an unsigned int (32-bit) in `tlsh_impl.h` line 160, which wraps past ~4 GiB.

 2. The Lvalue is computed by `l_capturing()` (`tlsh_util.cpp` line 4877), a binary search over a hardcoded lookup table (topval[170])
   The last entry is topval[169] = 4,224,281,216 (~3.93 GiB).
   Data lengths beyond this cause an out-of-bounds read — undefined behavior in C++.

 Trend Micro acknowledged the issue (GitHub issue #99, version 4.6.0) and defined the TLSH of a file as the TLSH of its first ~4 GiB.
 The Java port enforces this via `MAX_DATA_LENGTH` = topval[169]; we apply the same cap here for T1 builds.

 The T1 digest format (128 buckets, 1-byte checksum) is identified at init time via Tlsh::version().
 A future format (e.g. T2) may widen the length field, at which point this cap should be revisited.
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
     True when the linked libtlsh produces T1 digests (compact hash, 1-byte checksum).
     Checked once from `Tlsh::version()` which returns a string like `5.0.0 compact hash 1 byte checksum sliding_window=5`.
     */
    static let isT1Build: Bool = {
        guard let cStr = tlsh_version() else {
            return false
        }
        let version = String(cString: cStr)
        return version.contains("compact hash") && version.contains("1 byte checksum")
    }()

    /**
     Compute TLSH hash for a file. Streams in chunks to avoid loading the entire file into memory.
     For T1 builds, data beyond maximumDataSize (~3.93 GiB) is ignored per the TLSH specification (issue #99).
     Returns nil if file is too small or hashing fails.
     */
    static func hash(path: String) throws -> String? {
        let fd = try FileDescriptor.open(path, .readOnly)
        defer {
            try? fd.close()
        }

        _ = fcntl(fd.rawValue, F_NOCACHE, 1)

        let t = tlsh_new()
        defer {
            tlsh_free(t)
        }

        let chunkSize = 1 << 20 // 1 MiB
        let buffer = UnsafeMutableRawBufferPointer.allocate(byteCount: chunkSize, alignment: 1)
        defer {
            buffer.deallocate()
        }

        var totalSize: UInt64 = 0

        while true {
            if self.isT1Build, totalSize >= self.maximumDataSize {
                break
            }

            let n = try fd.read(into: buffer)
            if n == 0 {
                break
            }

            var usable = n
            if self.isT1Build {
                let remaining = self.maximumDataSize - totalSize
                usable = min(usable, Int(clamping: remaining))
            }

            tlsh_update(t, buffer.baseAddress?.assumingMemoryBound(to: UInt8.self), UInt32(usable))
            totalSize += UInt64(usable)

            if usable < n {
                break
            }
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

     For T1 builds, data beyond maximumDataSize (~3.93 GiB) is ignored per the TLSH specification (issue #99).
     */
    static func hash(data: Data) -> String? {
        guard data.count >= self.minimumDataSize else {
            return nil
        }

        let t = tlsh_new()
        defer {
            tlsh_free(t)
        }

        let usableCount: Int = if self.isT1Build {
            min(data.count, Int(clamping: self.maximumDataSize))
        } else {
            data.count
        }

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
