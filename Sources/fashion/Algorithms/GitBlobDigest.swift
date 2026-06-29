import CommonCrypto
import Foundation

// MARK: - GitBlobDigest

/**
 Git blob hashing: prefixes content with `blob <size>\0` before hashing.
 */
enum GitBlobDigest {
    /**
     Compute git blob hash for a file.
     */
    static func hash(path: String, useSHA256: Bool) throws -> String {
        // Stream "blob <size>\0" + content rather than reading the whole file into memory and copying it.
        let size = try FileReader.size(path: path)
        let prefix = Data("blob \(size)\0".utf8)
        return try CryptoDigest.hash(path: path, algorithm: useSHA256 ? .sha256 : .sha1, prefix: prefix, limit: size)
    }

    /**
     Compute git blob hash for raw data.
     */
    static func hashData(_ data: Data, useSHA256: Bool) throws -> String {
        let prefix = Data("blob \(data.count)\0".utf8)
        var combined = prefix
        combined.append(data)

        return try CryptoDigest.hash(data: combined, algorithm: useSHA256 ? .sha256 : .sha1)
    }
}
