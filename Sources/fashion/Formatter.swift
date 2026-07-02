import Foundation

/**
 Line formatting, padding, and score display for output.
 */
enum OutputFormatter {
    static let ssdeepPadWidth = 107 // 64 (hash1) + 32 (hash2) + 2 (the two ':') + ~9 (blocksize digits)
    static let cdhashPadWidth = 64 // SHA-256 hex length, the common case
    static let ssdeepScoreWidth = 3
    static let tlshScoreWidth = 4

    /**
     Format a standard result line: "<digest>  <path>"
     */
    static func formatLine(digest: String, path: String, algorithm: Algorithm) -> String {
        let paddedDigest = self.padDigest(digest, algorithm: algorithm)
        let (escaped, prefix) = self.escapePath(path)
        return "\(prefix)\(paddedDigest)  \(escaped)"
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
        let (escaped, prefix) = self.escapePath(path)
        return "\(prefix)\(paddedDigest) \(scoreStr)  \(escaped)"
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
        let (escaped, prefix) = self.escapePath(path)
        return "\(prefix)\(escaped)"
    }

    // MARK: - Private

    private static func padDigest(_ digest: String, algorithm: Algorithm) -> String {
        let width = switch algorithm {
        case .ssdeep: self.ssdeepPadWidth
        case .cdhash: self.cdhashPadWidth
        default: digest.count
        }
        let padding = max(0, width - digest.count)
        return digest + String(repeating: " ", count: padding)
    }

    /**
     Escape newlines/backslashes in a path so a crafted filename cannot forge an output line.

     Mirrors GNU coreutils `sha256sum`: when a path contains a backslash or a line break, escape those
     characters and prefix the line with a single backslash so consumers can detect and reverse it.
     */
    private static func escapePath(_ path: String) -> (escaped: String, prefix: String) {
        guard path.contains("\\") || path.contains("\n") || path.contains("\r") else {
            return (path, "")
        }
        let escaped = path
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\n", with: "\\n")
            .replacingOccurrences(of: "\r", with: "\\r")
        return (escaped, "\\")
    }
}
