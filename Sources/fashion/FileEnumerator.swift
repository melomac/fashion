import Darwin
import Foundation
import os

/**
 File tree walking using POSIX fts(3).

 Enumeration is pull-based (`FileWalker.next()`), so the streaming path buffers only one path at a time
 instead of running the whole walk ahead of the (slower) hashing stage.
 */
enum FileEnumerator {
    /**
     Collect all file paths, sort them, and return as an array.
     */
    static func collectSorted(paths: [String], follow: Bool, reporter: ErrorReporter? = nil) -> [String] {
        let walker = FileWalker(paths: paths, follow: follow, reporter: reporter)
        var allPaths: [String] = []
        while let path = walker.next() {
            allPaths.append(path)
        }
        allPaths.sort()
        return allPaths
    }

    /**
     Walk the given paths and produce an AsyncStream of file paths (streaming, unsorted).

     The stream is demand-driven: each `next()` on the consumer side advances the walk by one path, so
     enumeration cannot run arbitrarily ahead of hashing and pile paths up in memory.
     */
    static func walk(paths: [String], follow: Bool, reporter: ErrorReporter? = nil) -> AsyncStream<String> {
        let walker = FileWalker(paths: paths, follow: follow, reporter: reporter)
        return AsyncStream(unfolding: { walker.next() })
    }
}

/**
 A pull-based file-tree iterator over one or more root paths.
 Not thread-safe: `next()` must be called serially (the `AsyncStream` consumer does exactly this).
 */
final class FileWalker: @unchecked Sendable {
    private let follow: Bool
    private let reporter: ErrorReporter?
    private var roots: IndexingIterator<[String]>
    private var fts: UnsafeMutablePointer<FTS>?

    private static let logger = Logger(subsystem: "fashion", category: "walk")

    init(paths: [String], follow: Bool, reporter: ErrorReporter?) {
        self.follow = follow
        self.reporter = reporter
        self.roots = paths.makeIterator()
    }

    deinit {
        // Close the fts handle if the walk was abandoned before it drained.
        if let fts = self.fts {
            fts_close(fts)
        }
    }

    /**
     The next regular file path, or nil when every root has been fully walked.
     */
    func next() -> String? {
        while true {
            if let fts = self.fts {
                if let path = self.readNext(from: fts) {
                    return path
                }
                fts_close(fts)
                self.fts = nil
                continue
            }

            guard let root = self.roots.next() else {
                return nil
            }
            if let immediate = self.start(root: root) {
                return immediate
            }
        }
    }

    // MARK: - Private

    /**
     Begin a root: returns a path to emit immediately (a single regular file), or nil after opening an
     fts walk for a directory or skipping/reporting the root.
     */
    private func start(root: String) -> String? {
        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: root, isDirectory: &isDir) else {
            self.reporter?.report(path: root, message: "No such file or directory")
            return nil
        }

        if isDir.boolValue {
            self.openFTS(root: root)
            return nil
        }

        if self.isRegularFile(root) {
            return root
        }

        // A directly-named FIFO, device, or socket would block or spin forever in the read path.
        Self.logger.info("Skipping non-regular file: \(root, privacy: .public)")
        return nil
    }

    private func openFTS(root: String) {
        let options: Int32 = (self.follow ? FTS_LOGICAL : FTS_PHYSICAL) | FTS_NOCHDIR

        // fts_open expects a null-terminated array of C strings.
        guard let cPath = root.withCString({ strndup($0, root.utf8.count) }) else {
            return
        }
        defer {
            free(cPath)
        }

        var argv: [UnsafeMutablePointer<CChar>?] = [cPath, nil]
        guard let handle = fts_open(&argv, options, nil) else {
            self.reporter?.report(path: root, message: String(cString: strerror(errno)))
            return
        }
        self.fts = handle
    }

    private func readNext(from fts: UnsafeMutablePointer<FTS>) -> String? {
        while let entry = fts_read(fts) {
            switch Int32(entry.pointee.fts_info) {
            case FTS_F:
                return String(cString: entry.pointee.fts_path)

            case FTS_SL, FTS_SLNONE:
                // FTS_LOGICAL: symlinks are followed, so these only appear for broken targets.
                // FTS_PHYSICAL: we skip symlinks (follow=false).
                break

            case FTS_DC:
                let cyclePath = String(cString: entry.pointee.fts_path)
                Self.logger.info("Cycle detected, skipping: \(cyclePath, privacy: .public)")

            case FTS_DNR, FTS_ERR, FTS_NS:
                let errPath = String(cString: entry.pointee.fts_path)
                self.reporter?.report(path: errPath, message: String(cString: strerror(entry.pointee.fts_errno)))

            default:
                // FTS_D (pre-order), FTS_DP (post-order), FTS_DOT — skip.
                break
            }
        }
        return nil
    }

    private func isRegularFile(_ path: String) -> Bool {
        var info = stat()
        guard stat(path, &info) == 0 else {
            return false
        }
        return (info.st_mode & S_IFMT) == S_IFREG
    }
}
