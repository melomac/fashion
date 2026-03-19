import Foundation

/**
 Line formatting, padding, and score display for output.
 */
enum OutputFormatter {
    static let ssdeepPadWidth = 107
    static let ssdeepScoreWidth = 3
    static let tlshScoreWidth = 4

    /**
     Format a standard result line: "<digest>  <path>"
     */
    static func formatLine(digest: String, path: String, algorithm: Algorithm) -> String {
        let paddedDigest = self.padDigest(digest, algorithm: algorithm)
        return "\(paddedDigest)  \(path)"
    }

    /**
     Format a match result line with score: "<digest> <score>  <path>"
     */
    static func formatMatchLine(digest: String, score: Int, path: String, algorithm: Algorithm) -> String {
        let paddedDigest = self.padDigest(digest, algorithm: algorithm)
        let scoreStr = if algorithm == .ssdeep {
            String(format: "%\(self.ssdeepScoreWidth)d", score)
        } else if algorithm == .tlsh {
            String(format: "%\(self.tlshScoreWidth)d", score)
        } else {
            ""
        }
        return "\(paddedDigest) \(scoreStr)  \(path)"
    }

    /**
     Format quiet output without matching: digest only (no padding).
     */
    static func formatQuiet(digest: String, algorithm _: Algorithm) -> String {
        digest
    }

    /**
     Format quiet match output: path only
     */
    static func formatQuietMatch(path: String) -> String {
        path
    }

    // MARK: - Private

    private static func padDigest(_ digest: String, algorithm: Algorithm) -> String {
        if algorithm == .ssdeep {
            let padding = max(0, ssdeepPadWidth - digest.count)
            return digest + String(repeating: " ", count: padding)
        }
        return digest
    }
}
