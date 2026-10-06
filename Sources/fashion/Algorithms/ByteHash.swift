import CryptoKit
import Foundation

/**
 An algorithm that hashes bytes: every `Algorithm` but cdhash, which hashes a Mach-O's code directories instead (see
 `CDHash`). A file, an architecture of a universal binary, a list of symbol names and a XAR table of contents all
 stream through the same `ByteHasher`.
 */
enum ByteHash: String {
    case md5
    case sha1
    case sha256
    case sha384
    case sha512
    case git
    case git256
    case ssdeep
    case tlsh

    /**
     The byte hash `algorithm` names, which goes by the same name; nil for cdhash.
     */
    init?(_ algorithm: Algorithm) {
        self.init(rawValue: algorithm.rawValue)
    }

    /**
     The most bytes the algorithm reads: TLSH defines the digest of a larger input as that of its first
     `TLSHBridge.maximumDataSize` bytes.
     */
    var maximumLength: Int {
        self == .tlsh ? Int(TLSHBridge.maximumDataSize) : .max
    }

    /**
     A hasher for `length` bytes: git writes the length into its blob header, and ssdeep skips the block sizes it
     cannot use.
     */
    func hasher(length: Int) throws -> any ByteHasher {
        switch self {
        case .md5: CryptoHasher<Insecure.MD5>()
        case .sha1: CryptoHasher<Insecure.SHA1>()
        case .sha256: CryptoHasher<SHA256>()
        case .sha384: CryptoHasher<SHA384>()
        case .sha512: CryptoHasher<SHA512>()
        case .git: CryptoHasher<Insecure.SHA1>(prefix: "blob \(length)\0")
        case .git256: CryptoHasher<SHA256>(prefix: "blob \(length)\0")
        case .ssdeep: try SSDeepHasher(length: length)
        case .tlsh: TLSHHasher()
        }
    }

    /**
     The digest of a file, or of `range` of it: an architecture of a universal binary, or a Mach-O trimmed by --exact.
     Streamed from the file at the range's offset, so hashing neither maps nor copies it.

     The length is the size the file had when it was opened, and a file that no longer holds it by the time it is read
     fails closed: git writes the length into its digest, and ssdeep chooses its block size from it.
     */
    func digest(_ file: File, range: Range<Int>? = nil) throws -> String? {
        let range = range ?? 0 ..< file.size
        let length = min(range.count, self.maximumLength)
        var hasher = try self.hasher(length: length)
        let count = try file.stream(range.lowerBound ..< range.lowerBound + length) { hasher.update($0) }
        guard count == length else {
            throw FileError.sizeChanged(expected: length, actual: count)
        }
        return try hasher.finalize()
    }

    /**
     The digest of bytes in memory: a list of symbol names, or a XAR table of contents.
     */
    func digest(_ data: Data) throws -> String? {
        let bytes = data.prefix(self.maximumLength)
        var hasher = try self.hasher(length: bytes.count)
        bytes.withUnsafeBytes { hasher.update($0) }
        return try hasher.finalize()
    }
}

// MARK: -

/**
 A byte hash in progress: bytes go in as they are read, and the digest comes out once at the end.
 */
protocol ByteHasher {
    mutating func update(_ bytes: UnsafeRawBufferPointer)

    /**
     The printable digest, or nil when the algorithm makes none for so few bytes (TLSH).
     */
    mutating func finalize() throws -> String?
}

/**
 A CryptoKit hash, after a `prefix`: git hashes a blob header before the content.
 */
private struct CryptoHasher<Function: HashFunction>: ByteHasher {
    private var function = Function()

    init(prefix: String = "") {
        self.function.update(data: Data(prefix.utf8))
    }

    mutating func update(_ bytes: UnsafeRawBufferPointer) {
        self.function.update(bufferPointer: bytes)
    }

    func finalize() -> String? {
        self.function.finalize().hexString
    }
}
