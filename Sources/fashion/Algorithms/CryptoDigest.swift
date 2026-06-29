import CryptoKit
import Foundation

enum AlgorithmError: LocalizedError {
    case unsupported(Algorithm)

    var errorDescription: String? {
        switch self {
        case let .unsupported(algorithm):
            "CryptoDigest does not support \(algorithm)"
        }
    }
}

/**
 Cryptographic hash computation using CryptoKit.
 */
enum CryptoDigest {
    /**
     Compute the hex digest of a file at the given path using the specified algorithm.

     `prefix` is hashed before the file content (used by git blob hashing); `limit` caps the number of
     file bytes consumed (used by --exact to digest a Mach-O's trimmed extent).
     */
    static func hash(path: String, algorithm: Algorithm, prefix: Data = Data(), limit: Int? = nil) throws -> String {
        switch algorithm {
        case .md5: try self.hashFile(path: path, using: Insecure.MD5.self, prefix: prefix, limit: limit)
        case .sha1: try self.hashFile(path: path, using: Insecure.SHA1.self, prefix: prefix, limit: limit)
        case .sha256: try self.hashFile(path: path, using: SHA256.self, prefix: prefix, limit: limit)
        case .sha384: try self.hashFile(path: path, using: SHA384.self, prefix: prefix, limit: limit)
        case .sha512: try self.hashFile(path: path, using: SHA512.self, prefix: prefix, limit: limit)
        default: throw AlgorithmError.unsupported(algorithm)
        }
    }

    /**
     Compute the hex digest of raw data using the specified algorithm.
     */
    static func hash(data: Data, algorithm: Algorithm) throws -> String {
        switch algorithm {
        case .md5: Insecure.MD5.hash(data: data).hexString
        case .sha1: Insecure.SHA1.hash(data: data).hexString
        case .sha256: SHA256.hash(data: data).hexString
        case .sha384: SHA384.hash(data: data).hexString
        case .sha512: SHA512.hash(data: data).hexString
        default: throw AlgorithmError.unsupported(algorithm)
        }
    }

    // MARK: - Private

    /**
     Hash an optional `prefix` followed by the (optionally length-capped) file content.

     The file is streamed uncached through `FileReader`, so large inputs never load into memory.
     `prefix` supports git blob hashing; `limit` supports --exact's trimmed Mach-O extent.
     */
    private static func hashFile<H: HashFunction>(path: String, using _: H.Type, prefix: Data, limit: Int?) throws -> String {
        var hasher = H()
        if !prefix.isEmpty {
            prefix.withUnsafeBytes { hasher.update(bufferPointer: $0) }
        }
        try FileReader.read(path: path, limit: limit) { chunk in
            hasher.update(bufferPointer: chunk)
        }
        return hasher.finalize().hexString
    }
}
