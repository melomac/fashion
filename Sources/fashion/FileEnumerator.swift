import CMachOCompat
import Darwin
import Foundation
import os

/**
 A pull-based file-tree iterator over one or more root paths, using POSIX fts(3).

 Enumeration is pull-based (`next()`), so the walk stays a short queue ahead of the (slower) hashing stage instead of
 running the whole tree ahead of it. Sorted, it lists files in the byte order of their paths as it goes: the roots are
 ordered once, and each directory as fts reads it (see `fashion_fts_compare`). Roots nested in one another are walked
 one after the other, not merged.

 Not thread-safe: `next()` must be called serially (the walking thread does exactly this).
 */
final class FileWalker: Sequence, IteratorProtocol {
    private let follow: Bool
    private let reporter: Reporter?
    private let sorted: Bool
    private var roots: IndexingIterator<[String]>
    private var fts: UnsafeMutablePointer<FTS>?

    private static let logger = Logger(subsystem: "fashion", category: "walk")

    init(paths: [String], follow: Bool, reporter: Reporter? = nil, sorted: Bool = false) {
        self.follow = follow
        self.reporter = reporter
        self.sorted = sorted
        self.roots = (sorted ? Self.sortedRoots(paths) : paths).makeIterator()
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
            self.reporter?.report(path: root, message: NSLocalizedString("No such file or directory", comment: "Missing scan root"))
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
        // fts builds child paths as the root exactly as given plus "/" plus the entry name. Below a macOS 26
        // deployment target libc appends the slash unconditionally, so `dir/` walks as `dir//file`; newer libc
        // collapses one trailing slash but not two. Trim them all here, keeping a bare "/".
        let root = Self.trimmingTrailingSlashes(root)

        // FTS_COMFOLLOW follows a symlink named as a root (`find -H`), which start() already resolved to a
        // directory; under FTS_PHYSICAL inner symlinks are still skipped, and under FTS_LOGICAL it is a no-op.
        let options: Int32 = (self.follow ? FTS_LOGICAL : FTS_PHYSICAL) | FTS_NOCHDIR | FTS_COMFOLLOW

        // fts_open expects a null-terminated array of C strings.
        guard let cPath = root.withCString({ strndup($0, root.utf8.count) }) else {
            return
        }
        defer {
            free(cPath)
        }

        var argv: [UnsafeMutablePointer<CChar>?] = [cPath, nil]
        guard let handle = fts_open(&argv, options, self.sorted ? fashion_fts_compare : nil) else {
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

    /**
     Drop trailing slashes from a root path, keeping a bare "/". Runs once per root, before the walk starts.
     */
    private static func trimmingTrailingSlashes(_ path: String) -> String {
        var trimmed = path[...]
        while trimmed.utf8.count > 1, trimmed.last == "/" {
            trimmed.removeLast()
        }
        return String(trimmed)
    }

    /**
     Roots in the byte order of the paths under them: a directory's, trimmed, followed by "/" as within the walk.
     */
    private static func sortedRoots(_ paths: [String]) -> [String] {
        paths
            .map { root -> (key: [UInt8], root: String) in
                var isDirectory: ObjCBool = false
                let directory = FileManager.default.fileExists(atPath: root, isDirectory: &isDirectory) && isDirectory.boolValue
                return (Array(self.trimmingTrailingSlashes(root).utf8) + (directory ? [UInt8(ascii: "/")] : []), root)
            }
            .sorted { $0.key.lexicographicallyPrecedes($1.key) }
            .map(\.root)
    }
}
