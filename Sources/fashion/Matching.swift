import Foundation

/**
 Exact and fuzzy match logic for digests.
 */
enum Matching {
    /**
     Check if a digest matches any of the target digests for the given algorithm.
     */
    static func check(digest: String, against targets: [String], algorithm: Algorithm, threshold: Int) -> MatchResult? {
        switch algorithm {
        case .ssdeep:
            self.checkSSDeep(digest: digest, targets: targets, threshold: threshold)
        case .tlsh:
            self.checkTLSH(digest: digest, targets: targets, threshold: threshold)
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
