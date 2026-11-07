import CryptoKit
import Foundation
import os
import System

private let logger = Logger(subsystem: "fashion", category: "artifacts")

enum ArtifactError: Error, Equatable {
    /// Something that is not a regular file, a symlink say, stands where the artifact goes: it is left alone.
    case notRegularFileInTheWay
}

extension ArtifactError: LocalizedError {
    var errorDescription: String? {
        switch self {
        case .notRegularFileInTheWay:
            "exists and is not a regular file, left alone"
        }
    }
}

/**
 One artifact of a file: its bytes, and its name after the file's in parts, the architecture of a universal file's
 slice, `x86_64` or `x86_64_2`, then each thing done to it in the order done. The parts make the file's `suffix`,
 `_x86_64_unsigned_unpacked`, and hash mode's `label` for the state, `x86_64, unsigned, unpacked`.
 */
struct Artifact {
    let name: [String]
    let bytes: File

    var suffix: String {
        self.name.map { "_\($0)" }.joined()
    }

    var label: String {
        self.name.joined(separator: ", ")
    }
}

/**
 What `thinr`, `unsign` and `unpack` write beside a file, and how.

 The file is first edited in memory by `MachOEditor`, as the flags ask: its signatures out with `unsign`, what UPX
 packed unpacked with `unpack`, each image cut where it ends with `exact`. That is what hash mode reads under the same
 flags. Then it is written out, `split` into one file per architecture, as `thinr` writes a universal file, or whole,
 as `unsign` and `unpack` write it.

 Split, every state an image goes through is an artifact of its own: the slice as the fat table places it, then cut,
 then without its signature, then unpacked, then the unpacked image cut and without its own signature, as far as the
 flags go. So `thinr` leaves the whole way behind it: `ls_x86_64`, `ls_x86_64_unsigned`,
 `ls_x86_64_unsigned_unpacked`. Whole, only the end of the way is written, the file as the edits leave it.

 The artifacts are computed either way, so a file that cannot be read or edited is reported the same. Without
 --write, `thinr` writes nothing: its `mode` is `.list`, and each artifact is listed by its label, `ls (x86_64,
 unsigned)`, with no look at the disk. `unsign` and `unpack` write without the flag, `.write`, and leave a different
 file under an artifact's name alone. With the flag, `.replace`, the artifact takes the name, and the file is kept
 beside it as the conflict backup.

 An artifact is named after the file, with a suffix for each thing done to it, in the order it was done: `_exact`,
 `_unsigned`, `_unpacked`, then the unpacked image's own `_exact` and `_unsigned`. A slice's name carries its
 architecture first, `ls_x86_64_unsigned`; a thin file's does not, `sample_unsigned`. A slice nothing was done to
 keeps its name, `ls_x86_64`, and a file nothing was done to gets no artifact, since it would be the file itself.
 The names add up: a later run with other flags over an artifact makes what one run with all the flags would,
 `ls_x86_64` unsigned being `ls_x86_64_unsigned` either way.

 Without `exact`, the cut and the padding come where an edit needs them (`MachOEditor.Exact.asNeeded`), and the
 artifact is named `_exact` for them all the same. Bytes appended past an image's end keep its signature from coming
 out, as they keep `codesign` from removing it: `unsign` cuts the bytes off and writes `sample_exact_unsigned`,
 `unpack` cuts them off and unpacks, and hash mode's --unsign and --unpack cut the same way, naming the state
 `(exact, unsigned)`. A file cut short of its last page is padded to be read, when an edit comes of it.

 With `keep`, what decompressed of a UPX image that fails a check after, a sum or its headers, is written as it is,
 `_decompressed`, after the slice's architecture and the edits before it, for analysis by hand; the refusal is reported
 as without it, red and counted, so that its digest is never taken for the original's.

 An artifact written is noted in the unified log with its size and SHA-256, a record of what a run left behind. One
 already in place, byte for byte, is left as it is and only noted there, so a second run over a tree is as quiet on
 the terminal as the first. A different file under an artifact's name is left alone and reported, with its size and
 SHA-256 and the artifact's, unless `.replace` takes the name for the artifact: the file is kept beside it as the
 conflict backup, renamed to its name, `~`, and the time in seconds since the epoch with milliseconds,
 `ls_x86_64_unsigned~1762160000.123`, which no artifact's name takes, and its path is printed after the artifact's;
 the unified log records both. A symbolic link, or anything that is not a regular file, is never followed nor
 replaced: it is reported and left alone, a safety rule for analysis.
 */
struct ArtifactWriter {
    let exact: Bool
    let unsign: Bool
    let unpack: Bool
    /// Whether each architecture of a universal file comes out as a file of its own, or the file comes out whole.
    let split: Bool
    /// Whether the artifacts are listed, written, or written over a different file under their name.
    let mode: Mode
    /// Whether what decompressed of a UPX image that fails a check is written as it is, `_decompressed`, to look at by
    /// hand.
    var keep = false
    /// Whether the file is named once, its own path, for its artifacts' lines, as --quiet shortens standard output;
    /// what is reported about it stands (`Line.quiet`).
    var quiet = false

    /// What is done with an artifact.
    enum Mode {
        /// It is listed as hash mode labels the state, `ls (x86_64, unsigned)`, nothing is written: what `thinr` does
        /// without --write.
        case list
        /// It is written, unless a different file is under its name, which is reported and left alone: what
        /// `unsign` and `unpack` do without --write.
        case write
        /// It is written, and a different file under its name is kept beside it as the conflict backup: what --write
        /// does.
        case replace
    }

    /**
     The lines to print for one file: the label of each artifact listed, the path of each written or found in place,
     or a diagnostic for each that could not be written, or that a different file stands for under `.write`. A file that cannot be read,
     whose Mach-O or UPX data is malformed (red), or whose signature `unsign` cannot remove, is reported instead,
     after the architecture of the slice at fault in a universal file, and nothing is written, but what decompressed
     of a UPX image under `keep`, before the report. An image a modified UPX packed is warned about before its
     artifacts, which are written. With `quiet`, the file's path stands for its artifacts' lines, once.
     */
    func lines(for read: File, reporter: Reporter) -> [Line] {
        let subject = reporter.subject(read.path)
        // What decompressed of an image that fails a check, or decoded under no key where a key was applied, under
        // keep, named for its slice and the edits before it.
        var kept: [Artifact] = []
        do {
            // With exact alone, the editor pads a file cut short of its last page, an edit of its own, and names it;
            // with no flag at all, the file as read, its slices as the table places them.
            let edit = try self.unsign || self.unpack || self.exact
                ? MachOEditor.edit(read, exact: self.exact ? .always : .asNeeded, unsign: self.unsign, unpack: self.unpack, caveat: { subject.warn($1, arch: $0) }, keep: self.keep ? { arch, edits, data in
                    kept.append(Artifact(name: (arch.map { [$0] } ?? []) + edits.words, bytes: File(editing: read, pieces: [.bytes(data)])))
                } : nil)
                : MachOEditor.Edit(unedited: read, opened: Universal.open(read))
            let artifacts = self.split ? Self.slices(of: edit) : Self.whole(of: edit, exact: self.exact)
            self.written(kept + artifacts, for: subject.path, reporter: reporter).forEach(subject.show)
        } catch {
            // What an earlier image had to say stands, as hash mode keeps its diagnostics before the error, and what
            // decompressed under keep is written before it.
            self.written(kept, for: subject.path, reporter: reporter).forEach(subject.show)
            subject.refuse(error)
        }
        return self.quiet ? Line.quiet(subject.lines, naming: subject.path) : subject.lines
    }

    /// The lines for `artifacts` written beside `path`, each named after it with its suffix: its path, or what kept it
    /// from being written. Listed, the file's path with the artifact's label, `ls (x86_64, unsigned)`, as hash mode
    /// prints the state, and nothing on disk is looked at.
    private func written(_ artifacts: [Artifact], for path: String, reporter: Reporter) -> [Line] {
        artifacts.flatMap { made -> [Line] in
            let (bytes, artifact) = (made.bytes, path + made.suffix)
            guard self.mode != .list else {
                return [Line(text: "\(OutputFormatter.formatPath(path)) (\(made.label))")]
            }
            Self.writing.claim(artifact)
            defer {
                Self.writing.release(artifact)
            }
            do {
                switch try Self.write(bytes, to: artifact, overwrite: self.mode == .replace) {
                case let .written(identity):
                    logger.info("\(artifact, privacy: .public): written, \(identity.description, privacy: .public)")
                    return [Line(text: OutputFormatter.formatPath(artifact))]
                case let .identical(identity):
                    logger.info("\(artifact, privacy: .public): already in place, \(identity.description, privacy: .public)")
                    return [Line(text: OutputFormatter.formatPath(artifact))]
                case let .replaced(before, after, backup):
                    logger.info("\(artifact, privacy: .public): replaced, was \(before.description, privacy: .public), now \(after.description, privacy: .public); conflict backup \(backup, privacy: .public)")
                    return [Line(text: OutputFormatter.formatPath(artifact)), Line(text: OutputFormatter.formatPath(backup))]
                case let .differs(before, after):
                    return [reporter.report(path: artifact, message: "exists and differs, \(before) where the artifact is \(after); left alone without --write")]
                }
            } catch {
                return [reporter.report(path: artifact, message: File.message(for: error))]
            }
        }
    }

    // MARK: - Private

    /**
     The artifacts a file yields split, as `edit` left it, each named after the file by its slice and what was done to
     it, its bytes an edit of the file: a universal file's slice its architecture, as the fat table places it, then
     each state `MachOEditor` took it through, for what was done to it, or the `exact` cut alone of a slice the
     editor left alone, or a thin image, which takes the bytes appended to an image off, when it shortens it; a thin
     file's artifacts are named by what was done to it alone, since one nothing was done to would be the file. The
     states follow the table as the editor read it, so the slices are named by that read and not by another, which a
     file rewritten in the meantime could make differ.
     */
    static func slices(of edit: MachOEditor.Edit) -> [Artifact] {
        let file = edit.source
        switch edit.opened {
        case let .fat(table):
            // Each slice is named as Universal.named names it, the second of one architecture apart, `_x86_64_2`. The
            // fat table alone decides a slice's bytes, as for lipo -thin.
            return Universal.named(table.archs).enumerated().flatMap { index, named -> [Artifact] in
                let (arch, name) = (named.arch, named.name)
                let chain = edit.states[index].isEmpty ? edit.cuts[index].map { [$0] } ?? [] : edit.states[index]
                let whole = Artifact(name: [name], bytes: File(editing: file, pieces: [.range(arch.offset ..< arch.offset + arch.length)]))
                return [whole] + chain.map { Artifact(name: [name] + $0.edits.words, bytes: File(editing: file, pieces: $0.pieces)) }
            }
        case .thin:
            let chain = edit.states[0].isEmpty ? edit.cuts[0].map { [$0] } ?? [] : edit.states[0]
            return chain.map { Artifact(name: $0.edits.words, bytes: File(editing: file, pieces: $0.pieces)) }
        case .notMachO:
            return []
        }
    }

    /**
     The artifact a file yields whole, as `edit` left it: every architecture of a universal file laid out again, cut
     where it ends with `exact` as hash mode cuts it (`Universal.fileEnd`), by the editor's read, named for what was
     done to any of its images, the last of its states; none when nothing was done, since it would be the file.
     */
    static func whole(of edit: MachOEditor.Edit, exact: Bool) -> [Artifact] {
        let file = edit.file
        let end = exact ? Universal.fileEnd(of: edit.opened, size: file.size) : file.size
        var done = edit.states.reduce(into: MachOEditor.Edits()) { $0.formUnion($1.last?.edits ?? []) }
        if end < file.size {
            done.insert(.exact)
        }
        guard !done.isEmpty else {
            return []
        }
        return [Artifact(name: done.words, bytes: end < file.size ? File(editing: file, pieces: [.range(0 ..< end)]) : file)]
    }

    /// What became of an artifact's path.
    private enum Outcome {
        /// A new file: what it is.
        case written(Identity)
        /// The same bytes were there already: what they are.
        case identical(Identity)
        /// Another file was there and gave the name up: what it was, what the name holds now, and where it was kept.
        case replaced(before: Identity, after: Identity, backup: String)
        /// Another file is there and stays: what it is, and what the artifact is.
        case differs(before: Identity, after: Identity)
    }

    /// A file's size and SHA-256, as the log names an artifact written, and the overwrite line what was replaced and by
    /// what: "10 bytes, sha256 c1…".
    struct Identity: CustomStringConvertible, Equatable {
        let size: Int
        let digest: String

        var description: String {
            "\(String(self.size, pluralizing: "byte")), sha256 \(self.digest)"
        }
    }

    /// An artifact's permissions: no execute bit, since it is for analysis, not to run.
    private static let permissions: FilePermissions = [.ownerReadWrite, .groupRead, .otherRead]

    /// The artifacts being written, each by one thread at a time.
    private static let writing = Writing()

    /**
     Two files can yield one artifact: a thin Mach-O with appended bytes and its universal file under --exact, or an
     earlier artifact and its file under a later run's flags. Handed to two threads at once, the second to reach the
     artifact waits for the first, and finds it in place, rather than half written and reported as a different file.
     */
    private final class Writing: @unchecked Sendable {
        private let condition = NSCondition()
        private var paths: Set<String> = []
        /// The temporary files being written, for a run that dies to remove.
        private var temporaries: Set<String> = []

        /// Wait until no other thread writes `path`, then claim it.
        func claim(_ path: String) {
            self.condition.lock()
            while !self.paths.insert(path).inserted {
                self.condition.wait()
            }
            self.condition.unlock()
        }

        /// Give `path` up, and wake whoever waits for it.
        func release(_ path: String) {
            self.condition.lock()
            self.paths.remove(path)
            self.condition.broadcast()
            self.condition.unlock()
        }

        /// Note `temporary` as being written, for `abandon` to remove if the run dies.
        func begin(_ temporary: String) {
            self.condition.lock()
            self.temporaries.insert(temporary)
            self.condition.unlock()
        }

        /// `temporary` is placed or gone: nothing to remove.
        func end(_ temporary: String) {
            self.condition.lock()
            self.temporaries.remove(temporary)
            self.condition.unlock()
        }

        /// Remove every temporary file being written: the run dies, and none is to be found beside an artifact.
        func abandon() {
            self.condition.lock()
            self.temporaries.forEach { unlink($0) }
            self.temporaries.removeAll()
            self.condition.unlock()
        }
    }

    /// Remove the temporary files being written, from a run that dies of a signal or a write error.
    static func abandonInProgress() {
        self.writing.abandon()
    }

    /**
     Write `file` to `path`: a new file, or with `overwrite` a new file under the name a regular file holding other
     bytes gave up, kept beside as the conflict backup (`conflictBackup`); the same bytes are left as they are. The
     old file is renamed, not written into, so it keeps its inode, its bytes and its mode, and another link to it, to
     a file elsewhere say, is untouched; a write that fails leaves it under its backup name. What is there decides
     first, read and not written; a file that appears under the name as the artifact is placed decides the same way.
     */
    private static func write(_ file: File, to path: String, overwrite: Bool) throws -> Outcome {
        // lstat sees a symbolic link as itself, where open would follow it.
        var info = stat()
        guard lstat(path, &info) == 0 else {
            // Nothing under the name, or no directory on the way to it; anything else lstat says is an error.
            guard errno == ENOENT || errno == ENOTDIR else {
                throw Errno(rawValue: errno)
            }
            do {
                return try .written(Self.place(file, at: path, exclusively: true))
            } catch let error as Errno where error == .fileExists {
                return try Self.write(file, to: path, overwrite: overwrite)
            }
        }
        guard info.st_mode & S_IFMT == S_IFREG else {
            throw ArtifactError.notRegularFileInTheWay
        }

        // What is there decides first, read and not written: the same bytes stay, different ones are reported.
        let before = try Self.identity(of: File(path: path))
        let after = try Self.identity(of: file)
        if before.size == after.size, before.digest == after.digest {
            return .identical(after)
        }
        guard overwrite else {
            return .differs(before: before, after: after)
        }

        // The other file gives the name up, kept beside as the conflict backup, and the artifact takes it.
        let backup = try Self.conflictBackup(path)
        _ = try Self.place(file, at: path, exclusively: false)
        return .replaced(before: before, after: after, backup: backup)
    }

    /**
     The file under `path` renamed aside, to keep a different file found under an artifact's name when --write gives
     the name to the artifact: its name, `~`, and the time in seconds since the epoch with milliseconds,
     `ls_x86_64_unsigned~1762160000.123`, a name no artifact takes; one taken already, in the same millisecond, gets
     the next. A name too long to take the suffix, past the 255 bytes a name may have, is an error: the file keeps
     its name, and the artifact is not written.
     */
    private static func conflictBackup(_ path: String) throws -> String {
        var now = Int(Date().timeIntervalSince1970 * 1000)
        while true {
            let backup = "\(path)~\(now / 1000).\(String(format: "%03d", now % 1000))"
            guard renamex_np(path, backup, UInt32(RENAME_EXCL)) == 0 else {
                guard errno == EEXIST else {
                    throw Errno(rawValue: errno)
                }
                now += 1
                continue
            }
            return backup
        }
    }

    /**
     `file` written beside `path` under a temporary name and renamed into it, so that a run ended mid-way, by a
     signal or a write error, leaves no part of an artifact under its name: the temporary file is removed as the run
     dies. Its name is the directory's own, 45 bytes, whatever the artifact's, which may run to the 255 a name may
     have. `exclusively` refuses a file that has appeared under the name since (`RENAME_EXCL`), as `Errno.fileExists`.
     Returns what was placed, its size and SHA-256, summed as it was written.
     */
    private static func place(_ file: File, at path: String, exclusively: Bool) throws -> Identity {
        let temporary = URL(fileURLWithPath: path).deletingLastPathComponent().appendingPathComponent(".fashion-\(UUID().uuidString)").path
        let fd = try FileDescriptor.open(temporary, .writeOnly, options: [.create, .exclusiveCreate], permissions: Self.permissions)
        Self.writing.begin(temporary)
        defer {
            Self.writing.end(temporary)
        }
        let identity = try Self.copy(file, to: fd, at: temporary)
        guard (exclusively ? renamex_np(temporary, path, UInt32(RENAME_EXCL)) : rename(temporary, path)) == 0 else {
            let error = Errno(rawValue: errno)
            unlink(temporary)
            throw error
        }
        return identity
    }

    /**
     Stream `file` into `fd` and close it, summed as it goes for the identity the log names it by, in the one read; a
     write that fails leaves no file at `path`, a close that fails either. The descriptor is closed once: a close that
     fails has given its number up all the same, and another thread may hold it by then.
     */
    private static func copy(_ file: File, to fd: FileDescriptor, at path: String) throws -> Identity {
        var sha256 = SHA256()
        do {
            try file.stream(0 ..< file.size) { chunk in
                _ = try fd.writeAll(chunk)
                sha256.update(bufferPointer: chunk)
            }
        } catch {
            try? fd.close()
            unlink(path)
            throw error
        }
        do {
            try fd.close()
        } catch {
            unlink(path)
            throw error
        }
        return Identity(size: file.size, digest: sha256.finalize().hexString)
    }

    /**
     The size and SHA-256 of `file`, the digest as `fashion -q` prints it.
     */
    static func identity(of file: File) throws -> Identity {
        let sha256 = ByteHash(.sha256)! // nil for cdhash alone
        return try Identity(size: file.size, digest: ByteHash.digests([sha256], file).first?.digest ?? "")
    }
}
