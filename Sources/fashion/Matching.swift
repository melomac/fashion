import Foundation

/**
 The `--match` targets of a run, typed and normalised once at startup. Each is compared with one algorithm: `--algo`'s
 when given, or without it the one the shape of the target names, so a list that mixes MD5, SHA-256, ssdeep and TLSH
 digests is searched for in one run. A byte hash's targets are lowercased and kept in a set, which an exact match looks
 up; a cdhash's are lowercased for the prefix rule; ssdeep's and TLSH's are kept as given, for the libraries that score
 them.
 */
struct Targets {
    /// The hex lengths of a cdhash target: the 20-byte CDHash Apple's tools show, or the full digest of a SHA-1,
    /// SHA-256, SHA-384 or SHA-512 directory, as fashion prints it.
    static let cdhashHexLengths = [40, 64, 96, 128]

    /// How many targets were given, whatever their shape: any means match mode.
    let count: Int
    /// The algorithms the targets need, in `Algorithm.allCases` order: every file is hashed with each.
    let algorithms: [Algorithm]
    /// Exact digests by algorithm, lowercased.
    private var exact: [Algorithm: Set<String>] = [:]
    /// Full or truncated cdhashes, lowercased.
    private var prefixes: [String] = []
    private var ssdeep: [String] = []
    private var tlsh: [String] = []

    /**
     Type each target by `algorithm` or, without one, by its shape. A target that fits neither is left out, and
     matches nothing: `Fashion.validate()` refuses the run over it first.
     */
    init(_ targets: [String] = [], algorithm: Algorithm? = nil) {
        self.count = targets.count
        var algorithms: Set<Algorithm> = []
        for target in targets {
            guard Self.fits(target, algorithm), let algorithm = algorithm ?? Self.shape(of: target) else {
                continue
            }
            algorithms.insert(algorithm)
            switch algorithm {
            case .ssdeep: self.ssdeep.append(target)
            case .tlsh: self.tlsh.append(target)
            case .cdhash: self.prefixes.append(target.lowercased())
            default: self.exact[algorithm, default: []].insert(target.lowercased())
            }
        }
        self.algorithms = Algorithm.allCases.filter(algorithms.contains)
    }

    var isEmpty: Bool {
        self.count == 0
    }

    // MARK: - Shapes

    /**
     The algorithm whose digests have the shape of `target`: a byte hash by its count of hex digits (32 MD5, 40 SHA-1,
     64 SHA-256, 96 SHA-384, 128 SHA-512), TLSH by its `T1` version and 70 digits, or 70 alone as before TLSH 4.0,
     ssdeep by its `blocksize:chunk:chunk` form. Nil for any other string, and for git, git256 and cdhash, whose digests
     have the SHA-1 and SHA-256 shapes and take `--algo`.
     */
    static func shape(of target: String) -> Algorithm? {
        let bytes = target.utf8
        if bytes.allSatisfy(self.isHexDigit) {
            return switch bytes.count {
            case 32: .md5
            case 40: .sha1
            case 64: .sha256
            case 70: .tlsh
            case 96: .sha384
            case 128: .sha512
            default: nil
            }
        }
        // The version a TLSH digest starts with, in either case like its digits.
        if bytes.count == 72, target.hasPrefix("T1") || target.hasPrefix("t1"), bytes.dropFirst(2).allSatisfy(self.isHexDigit) {
            return .tlsh
        }
        // An ssdeep signature: the block size in decimal, then two chunks in ssdeep's base64 alphabet, either possibly
        // empty ("3::" is the empty file's).
        let parts = target.split(separator: ":", omittingEmptySubsequences: false)
        if parts.count == 3, !parts[0].isEmpty, parts[0].utf8.allSatisfy(self.isDigit), parts[1].utf8.allSatisfy(self.isBase64), parts[2].utf8.allSatisfy(self.isBase64) {
            return .ssdeep
        }
        return nil
    }

    /**
     Whether `target` can be a digest of `algorithm`'s: git's and git256's have the SHA-1 and SHA-256 shapes, a cdhash's
     is the 20-byte CDHash Apple's tools show or a whole directory digest (`cdhashHexLengths`); any other algorithm's
     has its own shape. With no algorithm, whether any shape names one.
     */
    static func fits(_ target: String, _ algorithm: Algorithm?) -> Bool {
        guard let algorithm else {
            return self.shape(of: target) != nil
        }
        return switch algorithm {
        case .git: self.shape(of: target) == .sha1
        case .git256: self.shape(of: target) == .sha256
        case .cdhash: self.cdhashHexLengths.contains(target.utf8.count) && target.utf8.allSatisfy(self.isHexDigit)
        default: self.shape(of: target) == algorithm
        }
    }

    // MARK: - Matching

    /**
     The match of a digest of `algorithm` against the targets of that algorithm, nil without one: the same digest for a
     byte hash, a target the digest starts with for a cdhash, an ssdeep similarity of at least `threshold` or a TLSH
     distance of at most `threshold`, the best of them scored. With `xlen`, TLSH digests are compared without the file
     length they record.
     */
    func match(_ digest: String, algorithm: Algorithm, threshold: Int, xlen: Bool = false) -> MatchResult? {
        switch algorithm {
        case .ssdeep:
            self.matchSSDeep(digest, threshold: threshold)
        case .tlsh:
            self.matchTLSH(digest, threshold: threshold, xlen: xlen)
        case .cdhash:
            self.matchPrefix(digest)
        default:
            self.exact[algorithm]?.contains(digest.lowercased()) == true ? MatchResult(score: nil) : nil
        }
    }

    // MARK: - Private

    private static func isHexDigit(_ byte: UInt8) -> Bool {
        self.isDigit(byte) || (UInt8(ascii: "a") ... UInt8(ascii: "f")).contains(byte | 0x20)
    }

    private static func isDigit(_ byte: UInt8) -> Bool {
        (UInt8(ascii: "0") ... UInt8(ascii: "9")).contains(byte)
    }

    private static func isBase64(_ byte: UInt8) -> Bool {
        self.isDigit(byte) || (UInt8(ascii: "a") ... UInt8(ascii: "z")).contains(byte | 0x20) || byte == UInt8(ascii: "+") || byte == UInt8(ascii: "/")
    }

    /**
     A truncated CDHash is a hex prefix of the full digest, so a target is only accepted as a prefix of the computed
     digest, never the reverse.
     */
    private func matchPrefix(_ digest: String) -> MatchResult? {
        let lower = digest.lowercased()
        return self.prefixes.contains { lower.hasPrefix($0) } ? MatchResult(score: nil) : nil
    }

    private func matchSSDeep(_ digest: String, threshold: Int) -> MatchResult? {
        var bestScore = 0
        var matched = false
        for target in self.ssdeep {
            let score = SSDeepBridge.compare(digest, target)
            if score >= threshold {
                matched = true
                if score > bestScore {
                    bestScore = score
                }
            }
        }

        return matched ? MatchResult(score: bestScore) : nil
    }

    private func matchTLSH(_ digest: String, threshold: Int, xlen: Bool) -> MatchResult? {
        var bestScore = Int.max
        var matched = false
        for target in self.tlsh {
            let distance = TLSHBridge.diff(digest, target, length: !xlen)
            if distance >= 0, distance <= threshold {
                matched = true
                if distance < bestScore {
                    bestScore = distance
                }
            }
        }

        return matched ? MatchResult(score: bestScore) : nil
    }
}

// MARK: -

/**
 A match, which `Targets.match` returns only when there is one.
 */
struct MatchResult {
    /// The ssdeep similarity or TLSH distance; nil for an exact or prefix match.
    let score: Int?
}
