import Darwin
import Foundation
import os

/**
 File tree walking using POSIX fts(3).
 */
enum FileEnumerator {
    private static let logger = Logger(subsystem: "fashion", category: "walk")

    /**
     Collect all file paths, sort them, and return as an array.
     */
    static func collectSorted(paths: [String], follow: Bool) -> [String] {
        var allPaths: [String] = []
        for path in paths {
            self.enumeratePath(path, follow: follow) { filePath in
                allPaths.append(filePath)
            }
        }
        allPaths.sort()
        return allPaths
    }

    /**
     Walk the given paths and produce an AsyncStream of file paths (streaming, unsorted).
     */
    static func walk(paths: [String], follow: Bool) -> AsyncStream<String> {
        AsyncStream(bufferingPolicy: .unbounded) { continuation in
            Task {
                for path in paths {
                    self.enumeratePath(path, follow: follow) { filePath in
                        continuation.yield(filePath)
                    }
                }
                continuation.finish()
            }
        }
    }

    // MARK: - Private

    private static func enumeratePath(_ path: String, follow: Bool, emit: (String) -> Void) {
        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: path, isDirectory: &isDir) else {
            self.logger.info("Path does not exist: \(path, privacy: .public)")
            return
        }

        if isDir.boolValue {
            self.ftsWalk(path, follow: follow, emit: emit)
        } else {
            emit(path)
        }
    }

    private static func ftsWalk(_ root: String, follow: Bool, emit: (String) -> Void) {
        let options: Int32 = (follow ? FTS_LOGICAL : FTS_PHYSICAL) | FTS_NOCHDIR

        // fts_open expects a null-terminated array of C strings
        guard let cPath = root.withCString({ strndup($0, root.utf8.count) }) else {
            return
        }
        defer {
            free(cPath)
        }

        var argv: [UnsafeMutablePointer<CChar>?] = [cPath, nil]
        guard let fts = fts_open(&argv, options, nil) else {
            self.logger.info("fts_open failed for \(root, privacy: .public)")
            return
        }
        defer {
            fts_close(fts)
        }

        while let entry = fts_read(fts) {
            let info = Int32(entry.pointee.fts_info)

            switch info {
            case FTS_F:
                emit(String(cString: entry.pointee.fts_path))

            case FTS_SL, FTS_SLNONE:
                // FTS_LOGICAL: symlinks are followed, so these only appear for broken targets
                // FTS_PHYSICAL: we skip symlinks (follow=false)
                break

            case FTS_DC:
                let cyclePath = String(cString: entry.pointee.fts_path)
                self.logger.info("Cycle detected, skipping: \(cyclePath, privacy: .public)")

            case FTS_DNR, FTS_ERR, FTS_NS:
                let errPath = String(cString: entry.pointee.fts_path)
                let errCode = entry.pointee.fts_errno
                self.logger.info("Error accessing \(errPath, privacy: .public): errno \(errCode, privacy: .public)")

            default:
                // FTS_D (pre-order), FTS_DP (post-order), FTS_DOT — skip
                break
            }
        }
    }
}
