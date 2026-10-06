import CMachOCompat
import Darwin
import Foundation
import os

/**
 A pull-based file-tree iterator over one or more root paths, using POSIX fts(3).

 Enumeration is pull-based (`next()`), so the walk stays a short queue ahead of the (slower) hashing stage instead of
 running the whole tree ahead of it. Every root goes to one fts walk, which reports each one that cannot be walked with
 its own error. Sorted, it lists files in the byte order of their paths as it goes: fts orders the roots and each
 directory as it reads it (see `fashion_fts_compare`). Roots nested in one another are walked one after the other, not
 merged.

 Not thread-safe: `next()` must be called serially (the walking thread does exactly this).
 */
final class FileWalker: Sequence, IteratorProtocol {
    private let reporter: Reporter?
    private var fts: UnsafeMutablePointer<FTS>?
    /// The root being walked, which an error fts reports without an entry is about.
    private var root = ""

    private static let logger = Logger(subsystem: "fashion", category: "walk")

    init(paths: [String], follow: Bool, reporter: Reporter? = nil, sorted: Bool = false) {
        self.reporter = reporter

        // FTS_COMFOLLOW follows a symlink named as a root (`find -H`); under FTS_PHYSICAL inner symlinks are still
        // skipped, and under FTS_LOGICAL it is a no-op.
        let options: Int32 = (follow ? FTS_LOGICAL : FTS_PHYSICAL) | FTS_NOCHDIR | FTS_COMFOLLOW

        var roots = paths.map(Self.root)
        self.fts = Self.open(roots, options: options, sorted: sorted)
        if self.fts == nil, errno == ENAMETOOLONG {
            // fts reports a root it cannot look up in order with the others, but refuses all of them when one is
            // longer than its path buffer (about 64 KiB). The roots the kernel could not look up either, PATH_MAX
            // bytes or more, are reported here instead, and the walk is retried with the others.
            for root in roots where root.utf8.count >= PATH_MAX {
                reporter?.report(path: root, message: String(cString: strerror(ENAMETOOLONG)))
            }
            roots.removeAll { $0.utf8.count >= PATH_MAX }
            self.fts = Self.open(roots, options: options, sorted: sorted)
        }
        if self.fts == nil {
            let message = String(cString: strerror(errno))
            for root in roots {
                reporter?.report(path: root, message: message)
            }
        }
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
        guard let fts = self.fts else {
            return nil
        }

        while true {
            errno = 0
            guard let entry = fts_read(fts) else {
                // The end of the walk, unless fts failed.
                if errno != 0 {
                    self.reporter?.report(path: self.root, message: String(cString: strerror(errno)))
                }
                fts_close(fts)
                self.fts = nil
                return nil
            }

            var path: String {
                String(cString: entry.pointee.fts_path)
            }
            let isRoot = entry.pointee.fts_level == FTS_ROOTLEVEL
            if isRoot {
                self.root = path
            }

            switch Int32(entry.pointee.fts_info) {
            case FTS_F:
                if let file = String(validatingCString: entry.pointee.fts_path) {
                    return file
                }
                // A name that is not UTF-8 (on NFS, say) would come back with replacement characters, as another path
                // that might name another file: report it rather than hash something else.
                self.reporter?.report(path: path, message: String(cString: strerror(EILSEQ)))

            case FTS_SLNONE where isRoot:
                // A root is followed: one whose target is missing does not exist.
                self.reporter?.report(path: path, message: String(cString: strerror(ENOENT)))

            case FTS_SL, FTS_SLNONE:
                // FTS_LOGICAL: symlinks are followed, so these only appear for broken targets.
                // FTS_PHYSICAL: we skip symlinks (follow=false).
                break

            case FTS_DC:
                Self.logger.info("Cycle detected, skipping: \(path, privacy: .public)")

            case FTS_DNR, FTS_ERR, FTS_NS:
                self.reporter?.report(path: path, message: String(cString: strerror(entry.pointee.fts_errno)))

            default:
                // FTS_D (pre-order), FTS_DP (post-order), FTS_DOT, and non-regular files, named or found — skip.
                break
            }
        }
    }

    // MARK: - Private

    /**
     `fts_open` over `roots`, or nil with `errno` set when it fails. It expects a null-terminated array of C strings,
     which it copies. An empty list opens, but the first `fts_read` on it crashes: it is no walk at all.
     */
    private static func open(_ roots: [String], options: Int32, sorted: Bool) -> UnsafeMutablePointer<FTS>? {
        guard !roots.isEmpty else {
            return nil
        }
        var argv = roots.map { strdup($0) } + [nil]
        defer {
            for path in argv {
                free(path)
            }
        }
        return fts_open(&argv, options, sorted ? fashion_fts_compare : nil)
    }

    /**
     A root as fts walks it. fts builds child paths as the root exactly as given plus "/" plus the entry name: below a
     macOS 26 deployment target libc appends the slash unconditionally, so `dir/` walks as `dir//file`, and newer libc
     collapses one trailing slash but not two. A directory's are trimmed, keeping a bare "/"; anything else keeps
     them, so `file/` is reported as not a directory rather than hashed.
     */
    private static func root(_ path: String) -> String {
        var trimmed = path[...]
        while trimmed.utf8.count > 1, trimmed.last == "/" {
            trimmed.removeLast()
        }

        var info = stat()
        guard
            trimmed.count < path.count,
            stat(path, &info) == 0,
            info.st_mode & S_IFMT == S_IFDIR
        else {
            return path
        }
        return String(trimmed)
    }
}
