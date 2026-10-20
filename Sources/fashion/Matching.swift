import Foundation

/**
 Exact and fuzzy match logic for digests.
 */
enum Matching {
    /// The hex lengths of a cdhash target: the 20-byte CDHash Apple's tools show, or the full digest of a SHA-1,
    /// SHA-256, SHA-384 or SHA-512 directory, as fashion prints it.
    static let cdhashHexLengths = [40, 64, 96, 128]

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
     has its own shape.
     */
    static func fits(_ target: String, _ algorithm: Algorithm) -> Bool {
        switch algorithm {
        case .git: self.shape(of: target) == .sha1
        case .git256: self.shape(of: target) == .sha256
        case .cdhash: self.cdhashHexLengths.contains(target.utf8.count) && target.utf8.allSatisfy(self.isHexDigit)
        default: self.shape(of: target) == algorithm
        }
    }

    /**
     Check if a digest matches any of the target digests for the given algorithm. With `xlen`, TLSH digests are compared
     without the file length they record.
     */
    static func check(digest: String, against targets: [String], algorithm: Algorithm, threshold: Int, xlen: Bool = false) -> MatchResult? {
        switch algorithm {
        case .ssdeep:
            self.checkSSDeep(digest: digest, targets: targets, threshold: threshold)
        case .tlsh:
            self.checkTLSH(digest: digest, targets: targets, threshold: threshold, xlen: xlen)
        case .cdhash:
            self.checkPrefix(digest: digest, targets: targets)
        default:
            self.checkExact(digest: digest, targets: targets)
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

    private static func checkExact(digest: String, targets: [String]) -> MatchResult? {
        let lower = digest.lowercased()

        for target in targets {
            if lower == target.lowercased() {
                return MatchResult(score: nil)
            }
        }

        return nil
    }

    private static func checkPrefix(digest: String, targets: [String]) -> MatchResult? {
        let lower = digest.lowercased()

        for target in targets {
            // A target is a whole CDHash, truncated to 20 bytes as Apple's tools show it or in full: anything else would
            // prefix-match (nearly) every digest. The truncated form is a hex prefix of the full digest, so a target is
            // only accepted as a prefix of the computed digest — never the reverse.
            guard self.fits(target, .cdhash) else {
                continue
            }
            if lower.hasPrefix(target.lowercased()) {
                return MatchResult(score: nil)
            }
        }

        return nil
    }

    private static func checkSSDeep(digest: String, targets: [String], threshold: Int) -> MatchResult? {
        var bestScore = 0
        var matched = false
        for target in targets {
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

    private static func checkTLSH(digest: String, targets: [String], threshold: Int, xlen: Bool) -> MatchResult? {
        var bestScore = Int.max
        var matched = false
        for target in targets {
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
 A match, which `Matching.check` returns only when there is one.
 */
struct MatchResult {
    /// The ssdeep similarity or TLSH distance; nil for an exact or prefix match.
    let score: Int?
}
