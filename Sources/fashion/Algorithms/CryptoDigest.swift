import CMD5Wrapper
import CommonCrypto
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
 Streaming cryptographic hash computation using CommonCrypto.
 */
enum CryptoDigest {
    private static let chunkSize = 65536

    /**
     Compute the hex digest of a file at the given path using the specified algorithm.
     */
    static func hash(path: String, algorithm: Algorithm) throws -> String {
        let ops = try operations(for: algorithm)
        let handle = try FileHandle(forReadingFrom: URL(fileURLWithPath: path))
        defer {
            handle.closeFile()
        }

        var ctx = [UInt8](repeating: 0, count: ops.contextSize)
        ctx.withUnsafeMutableBytes {
            ops.init_fn($0)
        }

        while true {
            let done = autoreleasepool {
                let chunk = handle.readData(ofLength: self.chunkSize)
                if chunk.isEmpty {
                    return true
                }
                chunk.withUnsafeBytes { ptr in
                    ctx.withUnsafeMutableBytes { ctxPtr in
                        ops.update_fn(ctxPtr, ptr)
                    }
                }
                return false
            }
            if done { break }
        }

        var digest = [UInt8](repeating: 0, count: ops.digestLength)
        ctx.withUnsafeMutableBytes { ctxPtr in
            ops.final_fn(&digest, ctxPtr)
        }

        return digest.hexString
    }

    /**
     Compute the hex digest of raw data using the specified algorithm.
     */
    static func hash(data: Data, algorithm: Algorithm) throws -> String {
        let ops = try operations(for: algorithm)

        var digest = [UInt8](repeating: 0, count: ops.digestLength)
        data.withUnsafeBytes { ptr in
            ops.oneshot_fn(ptr, &digest)
        }

        return digest.hexString
    }

    // MARK: - Private

    private struct Operations {
        let contextSize: Int
        let digestLength: Int
        let init_fn: (UnsafeMutableRawBufferPointer) -> Void
        let update_fn: (UnsafeMutableRawBufferPointer, UnsafeRawBufferPointer) -> Void
        let final_fn: (UnsafeMutablePointer<UInt8>, UnsafeMutableRawBufferPointer) -> Void
        let oneshot_fn: (UnsafeRawBufferPointer, UnsafeMutablePointer<UInt8>) -> Void
    }

    private static func operations(for algorithm: Algorithm) throws -> Operations {
        switch algorithm {
        case .md5:
            self.makeOperations(CC_MD5_CTX.self, Int(CC_MD5_DIGEST_LENGTH), CMD5_Init, CMD5_Update, CMD5_Final, CMD5_Oneshot)
        case .sha1:
            self.makeOperations(CC_SHA1_CTX.self, Int(CC_SHA1_DIGEST_LENGTH), CC_SHA1_Init, CC_SHA1_Update, CC_SHA1_Final, CC_SHA1)
        case .sha224:
            self.makeOperations(CC_SHA256_CTX.self, Int(CC_SHA224_DIGEST_LENGTH), CC_SHA224_Init, CC_SHA224_Update, CC_SHA224_Final, CC_SHA224)
        case .sha256:
            self.makeOperations(CC_SHA256_CTX.self, Int(CC_SHA256_DIGEST_LENGTH), CC_SHA256_Init, CC_SHA256_Update, CC_SHA256_Final, CC_SHA256)
        case .sha384:
            self.makeOperations(CC_SHA512_CTX.self, Int(CC_SHA384_DIGEST_LENGTH), CC_SHA384_Init, CC_SHA384_Update, CC_SHA384_Final, CC_SHA384)
        case .sha512:
            self.makeOperations(CC_SHA512_CTX.self, Int(CC_SHA512_DIGEST_LENGTH), CC_SHA512_Init, CC_SHA512_Update, CC_SHA512_Final, CC_SHA512)
        default:
            throw AlgorithmError.unsupported(algorithm)
        }
    }

    private static func makeOperations<CTX>(
        _: CTX.Type,
        _ digestLength: Int,
        _ initFn: @escaping (UnsafeMutablePointer<CTX>?) -> Int32,
        _ updateFn: @escaping (UnsafeMutablePointer<CTX>?, UnsafeRawPointer?, CC_LONG) -> Int32,
        _ finalFn: @escaping (UnsafeMutablePointer<UInt8>?, UnsafeMutablePointer<CTX>?) -> Int32,
        _ oneshotFn: @escaping (UnsafeRawPointer?, CC_LONG, UnsafeMutablePointer<UInt8>?) -> UnsafeMutablePointer<UInt8>?,
    ) -> Operations {
        Operations(
            contextSize: MemoryLayout<CTX>.size, digestLength: digestLength, init_fn: { buf in
                _ = initFn(buf.baseAddress?.assumingMemoryBound(to: CTX.self))
            },
            update_fn: { ctx, data in
                _ = updateFn(ctx.baseAddress?.assumingMemoryBound(to: CTX.self), data.baseAddress, CC_LONG(data.count))
            },
            final_fn: { digest, ctx in
                _ = finalFn(digest, ctx.baseAddress?.assumingMemoryBound(to: CTX.self))
            },
            oneshot_fn: { data, digest in
                _ = oneshotFn(data.baseAddress, CC_LONG(data.count), digest)
            },
        )
    }
}
