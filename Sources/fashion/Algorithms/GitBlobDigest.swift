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
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        return try self.hashData(data, useSHA256: useSHA256)
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
