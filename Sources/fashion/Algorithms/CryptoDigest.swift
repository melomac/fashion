import CryptoKit
import Foundation
import System

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
    private static let chunkSize = 1 << 20 // 1MB

    /**
     Compute the hex digest of a file at the given path using the specified algorithm.
     */
    static func hash(path: String, algorithm: Algorithm) throws -> String {
        switch algorithm {
        case .md5: try self.hashFile(path: path, using: Insecure.MD5.self)
        case .sha1: try self.hashFile(path: path, using: Insecure.SHA1.self)
        case .sha256: try self.hashFile(path: path, using: SHA256.self)
        case .sha384: try self.hashFile(path: path, using: SHA384.self)
        case .sha512: try self.hashFile(path: path, using: SHA512.self)
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

    private static func hashFile<H: HashFunction>(path: String, using _: H.Type) throws -> String {
        let fd = try FileDescriptor.open(path, .readOnly)
        defer {
            try? fd.close()
        }

        _ = fcntl(fd.rawValue, F_NOCACHE, 1)

        let buffer = UnsafeMutableRawBufferPointer.allocate(byteCount: self.chunkSize, alignment: 1)
        defer {
            buffer.deallocate()
        }

        var hasher = H()
        while true {
            let n = try fd.read(into: buffer)
            if n == 0 {
                break
            }
            hasher.update(bufferPointer: UnsafeRawBufferPointer(rebasing: buffer[..<n]))
        }

        return hasher.finalize().hexString
    }
}
