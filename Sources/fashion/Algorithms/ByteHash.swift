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
     The algorithm of the same name, which every byte hash has.
     */
    var algorithm: Algorithm {
        Algorithm(rawValue: self.rawValue)!
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

     `caveat` hears what TLSH leaves out: every byte when it makes no digest, or those past its `maximumLength`.
     */
    func digest(_ file: File, range: Range<Int>? = nil, caveat: (String) -> Void = { _ in }) throws -> String? {
        let range = range ?? 0 ..< file.size
        let length = min(range.count, self.maximumLength)
        var hasher = try self.hasher(length: length)
        try file.stream(range.lowerBound ..< range.lowerBound + length) { hasher.update($0) }
        return try self.finalize(&hasher, length: range.count, caveat: caveat)
    }

    /**
     The digest of bytes in memory: a list of symbol names, or a XAR table of contents.
     */
    func digest(_ data: Data, caveat: (String) -> Void = { _ in }) throws -> String? {
        let bytes = data.prefix(self.maximumLength)
        var hasher = try self.hasher(length: bytes.count)
        bytes.withUnsafeBytes { hasher.update($0) }
        return try self.finalize(&hasher, length: data.count, caveat: caveat)
    }

    /**
     The digests of several hashes from one read of a file, or of `range` of it, each with its hash in the order given:
     a `FanOutHasher` feeds every hasher the same chunks, TLSH's up to its `maximumLength` while the others go on to the
     end. A hash that makes no digest (TLSH) is left out, and `caveat` hears why. One hash reads the file as
     `digest(_:range:caveat:)` does.
     */
    static func digests(_ hashes: [ByteHash], _ file: File, range: Range<Int>? = nil, caveat: (String) -> Void = { _ in }) throws -> [(hash: ByteHash, digest: String)] {
        if hashes.count == 1, let hash = hashes.first {
            return try hash.digest(file, range: range, caveat: caveat).map { [(hash, $0)] } ?? []
        }
        let range = range ?? 0 ..< file.size
        var fanOut = try FanOutHasher(hashes.map { ($0, min(range.count, $0.maximumLength)) })
        try file.stream(range.lowerBound ..< range.lowerBound + fanOut.length) { fanOut.update($0) }
        return try zip(hashes, fanOut.finalize()).compactMap { hash, digest in
            hash.note(digest, length: range.count, caveat: caveat)
            return digest.map { (hash, $0) }
        }
    }

    /**
     The digests of several hashes of bytes in memory, each with its hash in the order given, without those TLSH makes none of.
     */
    static func digests(_ hashes: [ByteHash], _ data: Data, caveat: (String) -> Void = { _ in }) throws -> [(hash: ByteHash, digest: String)] {
        try hashes.compactMap { hash in try hash.digest(data, caveat: caveat).map { (hash, $0) } }
    }

    /**
     The digest of `length` bytes, of which `hasher` was fed at most `maximumLength`.
     */
    private func finalize(_ hasher: inout any ByteHasher, length: Int, caveat: (String) -> Void) throws -> String? {
        let digest = try hasher.finalize()
        self.note(digest, length: length, caveat: caveat)
        return digest
    }

    /**
     Tell `caveat` what the digest of `length` bytes leaves out, which only TLSH's does: every byte when it made none, or
     those past its `maximumLength`.
     */
    private func note(_ digest: String?, length: Int, caveat: (String) -> Void) {
        if self == .tlsh, let message = TLSHBridge.caveat(length: length, digest: digest) {
            caveat(message)
        }
    }
}

// MARK: -

/**
 Several hashers fed from one read, each up to its own `length`: TLSH's stops at its `maximumLength` while the others
 go on to the end of the file.
 */
struct FanOutHasher {
    private var hashers: [(hasher: any ByteHasher, remaining: Int)]

    /**
     A hasher per hash, for the `length` bytes it will be fed.
     */
    init(_ hashes: [(hash: ByteHash, length: Int)]) throws {
        self.hashers = try hashes.map { try ($0.hash.hasher(length: $0.length), $0.length) }
    }

    /**
     The most bytes any hasher has yet to take: what feeding the hashers further may read.
     */
    var length: Int {
        self.hashers.map(\.remaining).max() ?? 0
    }

    /**
     Feed each hasher as many of the bytes as it has yet to take.
     */
    mutating func update(_ bytes: UnsafeRawBufferPointer) {
        for index in self.hashers.indices where self.hashers[index].remaining > 0 {
            let count = min(bytes.count, self.hashers[index].remaining)
            self.hashers[index].hasher.update(UnsafeRawBufferPointer(rebasing: bytes[..<count]))
            self.hashers[index].remaining -= count
        }
    }

    /**
     Each hasher's digest, in the order given; nil where the algorithm makes none (TLSH).
     */
    mutating func finalize() throws -> [String?] {
        var digests: [String?] = []
        for index in self.hashers.indices {
            try digests.append(self.hashers[index].hasher.finalize())
        }
        return digests
    }
}

// MARK: -

/**
 A byte hash in progress: bytes go in as they are read, and the digest comes out once at the end.
 */
protocol ByteHasher {
    mutating func update(_ bytes: UnsafeRawBufferPointer)

    /**
     The printable digest, or nil when the algorithm makes none for so few bytes, or so little variation (TLSH).
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
