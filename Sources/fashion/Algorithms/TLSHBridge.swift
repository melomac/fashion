import CTLSHWrapper
import Foundation

/**
 Bridge to libtlsh for fuzzy hashing (Trend Micro Locality Sensitive Hash).
 */
enum TLSHBridge {
    /**
     Minimum data size for TLSH computation.
     */
    static let minimumDataSize = 50

    /**
     Compute TLSH hash for a file. Streams in chunks to avoid loading the entire file into memory.
     Returns nil if file is too small or hashing fails.
     */
    static func hash(path: String) throws -> String? {
        let fh = try FileHandle(forReadingFrom: URL(fileURLWithPath: path))
        defer { try? fh.close() }

        let t = tlsh_new()
        defer { tlsh_free(t) }

        let chunkSize = 1024 * 1024 // 1 MiB
        var totalSize = 0

        while true {
            let done = try autoreleasepool {
                guard let chunk = try fh.read(upToCount: chunkSize), !chunk.isEmpty else {
                    return true
                }
                chunk.withUnsafeBytes { ptr in
                    guard let base = ptr.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                        return
                    }
                    tlsh_update(t, base, UInt32(ptr.count))
                }
                totalSize += chunk.count
                return false
            }
            if done { break }
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
     */
    static func hash(data: Data) -> String? {
        guard data.count >= self.minimumDataSize else {
            return nil
        }

        let t = tlsh_new()
        defer {
            tlsh_free(t)
        }

        data.withUnsafeBytes { ptr in
            guard let base = ptr.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                return
            }
            let chunkSize = 1024 * 1024
            var offset = 0
            while offset < ptr.count {
                let len = min(chunkSize, ptr.count - offset)
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
        let lower = hash.lowercased()
        if lower.hasPrefix("t1") {
            return String(hash.dropFirst(2))
        }
        return hash
    }
}
