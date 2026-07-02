import Foundation

/**
 Exact and fuzzy match logic for digests.
 */
enum Matching {
    /// Minimum length (hex characters) for a truncated CDHash target, to avoid degenerate prefix matches.
    static let minPrefixHexLength = 8

    /**
     Check if a digest matches any of the target digests for the given algorithm.
     */
    static func check(digest: String, against targets: [String], algorithm: Algorithm, threshold: Int) -> MatchResult? {
        switch algorithm {
        case .ssdeep:
            self.checkSSDeep(digest: digest, targets: targets, threshold: threshold)
        case .tlsh:
            self.checkTLSH(digest: digest, targets: targets, threshold: threshold)
        case .cdhash:
            self.checkPrefix(digest: digest, targets: targets)
        default:
            self.checkExact(digest: digest, targets: targets)
        }
    }

    // MARK: - Private

    private static func checkExact(digest: String, targets: [String]) -> MatchResult? {
        let lower = digest.lowercased()

        for target in targets {
            if lower == target.lowercased() {
                return MatchResult(matched: true, score: nil)
            }
        }

        return nil
    }

    private static func checkPrefix(digest: String, targets: [String]) -> MatchResult? {
        let lower = digest.lowercased()

        for target in targets {
            let t = target.lowercased()
            // Reject degenerate targets: an empty or ultra-short string, or a non-hex value, would
            // prefix-match (nearly) every digest. A truncated CDHash is a hex prefix of the full digest,
            // so we only accept the target as a prefix of the computed digest — never the reverse.
            guard t.count >= self.minPrefixHexLength, t.allSatisfy(\.isHexDigit) else {
                continue
            }
            if lower.hasPrefix(t) {
                return MatchResult(matched: true, score: nil)
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

        return matched ? MatchResult(matched: true, score: bestScore) : nil
    }

    private static func checkTLSH(digest: String, targets: [String], threshold: Int) -> MatchResult? {
        var bestScore = Int.max
        var matched = false
        for target in targets {
            let distance = TLSHBridge.diff(digest, target)
            if distance >= 0, distance <= threshold {
                matched = true
                if distance < bestScore {
                    bestScore = distance
                }
            }
        }

        return matched ? MatchResult(matched: true, score: bestScore) : nil
    }
}

// MARK: -

struct MatchResult {
    let matched: Bool
    let score: Int?
}
