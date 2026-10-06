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
     Format a result line: "<digest>  <path>", or "<digest> <score>  <path>" for a match with a similarity score.
     */
    static func formatLine(digest: String, score: Int? = nil, path: String, algorithm: Algorithm) -> String {
        let paddedDigest = self.padDigest(digest, algorithm: algorithm)
        let (escaped, prefix) = self.escapePath(path)
        guard let score else {
            return "\(prefix)\(paddedDigest)  \(escaped)"
        }
        let scoreStr = switch algorithm {
        case .ssdeep: String(format: "%\(self.ssdeepScoreWidth)ld", score)
        case .tlsh: String(format: "%\(self.tlshScoreWidth)ld", score)
        default: ""
        }
        return "\(prefix)\(paddedDigest) \(scoreStr)  \(escaped)"
    }

    /**
     Escape a path for safe display as a complete field.
     */
    static func formatPath(_ path: String) -> String {
        let (escaped, prefix) = self.escapePath(path)
        return "\(prefix)\(escaped)"
    }

    /**
     Keep a diagnostic message on one physical output line.
     */
    static func formatDiagnostic(_ message: String) -> String {
        message
            .replacingOccurrences(of: "\n", with: "\\n")
            .replacingOccurrences(of: "\r", with: "\\r")
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
        // A byte test: "\r\n" is a single Character, which String.contains finds neither "\r" nor "\n" in.
        guard path.utf8.contains(where: { $0 == UInt8(ascii: "\\") || $0 == UInt8(ascii: "\n") || $0 == UInt8(ascii: "\r") }) else {
            return (path, "")
        }
        let escaped = path
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\n", with: "\\n")
            .replacingOccurrences(of: "\r", with: "\\r")
        return (escaped, "\\")
    }
}
