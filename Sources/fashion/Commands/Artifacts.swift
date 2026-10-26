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
 What `thin`, `unsign` and `unpack` write beside a file, and how: the file as `MachOEditor` edits it, `unsign` and
 `unpack`, cut where its image ends with `exact`, as hash mode reads it under the same flags, then `split` into one
 file per architecture of a universal file, as `thin` writes them, or written whole, as `unsign` and `unpack` do.

 Split, every state an image goes through is an artifact: a universal file's slice as the fat table places it, then
 cut, then without its signature, then unpacked, then the unpacked image cut and without its own signature, as far as
 the flags take it; so `thin` leaves the way behind it, `ls_x86_64`, `ls_x86_64_unsigned`,
 `ls_x86_64_unsigned_unpacked`, where `unsign` and `unpack` write the file as the edits leave it, whole.

 An artifact is named after the file for what was done to it, in the order it was done: `_exact`, `_unsigned`, then
 `_unpacked`, and the unpacked image's own `_exact` and `_unsigned`, after the architecture of a slice `split` out,
 `ls_x86_64_unsigned`, or after the name of the file itself, `sample_unsigned` or `ls_unsigned`. A slice nothing was
 done to keeps its name, `ls_x86_64`, and a file nothing was done to yields no artifact, since it would be the file.
 A later run with other flags over an artifact names what it makes as one run with them all would: `ls_x86_64`
 unsigned is `ls_x86_64_unsigned` either way.

 An artifact already in place, byte for byte, is left as it is and noted in the unified log alone, so a second run over
 a tree is as quiet on the terminal as the first was. A different file under an artifact's name is left alone and
 reported, with its size and SHA-256 and the artifact's, unless `overwrite` replaces it, in which case the unified log
 alone records the same. A symbolic link, or anything that is not a regular file, is never followed nor replaced: it
 is reported and left alone, a safety rule for analysis.
 */
struct ArtifactWriter {
    let exact: Bool
    let unsign: Bool
    let unpack: Bool
    /// Whether each architecture of a universal file comes out as a file of its own, or the file comes out whole.
    let split: Bool
    let overwrite: Bool

    /**
     The lines to print for one file: the path of each artifact written or found in place, or a diagnostic for each
     that could not be written, or that a different file stands for without `overwrite`. A file that cannot be read,
     whose Mach-O or UPX data is malformed (red), or whose signature `unsign` cannot remove, is reported instead, and
     nothing is written. An image a modified UPX packed is warned about before its artifacts, which are written.
     */
    func lines(for path: String, reporter: Reporter) -> [Line] {
        let artifacts: [(suffix: String, bytes: File)]
        var caveats: [Line] = []
        do {
            let opened = try File(path: path)
            let edited = try self.unsign || self.unpack ? MachOEditor.edit(opened, exact: self.exact, unsign: self.unsign, unpack: self.unpack, caveat: { arch, message in
                caveats.append(reporter.warn(path: arch.map { "\(path) (\($0))" } ?? path, message: message))
            }) : nil
            artifacts = try self.split ? Self.slices(of: opened, exact: self.exact, states: edited?.states) : Self.whole(edited?.file ?? opened, exact: self.exact, states: edited?.states)
        } catch {
            return [reporter.report(path: path, message: File.message(for: error), tint: Digester.tint(for: error))]
        }

        return caveats + artifacts.flatMap { suffix, bytes -> [Line] in
            let artifact = path + suffix
            Self.writing.claim(artifact)
            defer {
                Self.writing.release(artifact)
            }
            do {
                switch try Self.write(bytes, to: artifact, overwrite: self.overwrite) {
                case .written:
                    return [Line(text: OutputFormatter.formatPath(artifact))]
                case let .identical(identity):
                    logger.info("\(artifact, privacy: .public): already in place, \(identity.description, privacy: .public)")
                    return [Line(text: OutputFormatter.formatPath(artifact))]
                case let .overwritten(before, after):
                    logger.info("\(artifact, privacy: .public): overwritten, was \(before.description, privacy: .public), now \(after.description, privacy: .public)")
                    return [Line(text: OutputFormatter.formatPath(artifact))]
                case let .differs(before, after):
                    return [reporter.report(path: artifact, message: "exists and differs, \(before) where the artifact is \(after); left alone without --overwrite")]
                }
            } catch {
                return [reporter.report(path: artifact, message: File.message(for: error))]
            }
        }
    }

    // MARK: - Private

    /// The suffix an artifact's name takes for `edits`, in the order the edits are done.
    private static func suffix(_ edits: MachOEditor.Edits) -> String {
        MachOEditor.Edits.suffixes.filter { edits.contains($0.0) }.map(\.1).joined()
    }

    /**
     The artifacts a file yields split, each with the suffix its name takes after the file's, and its bytes as an edit
     of `file`: a universal file's slice its architecture, as the fat table places it, then each state `MachOEditor`
     took it through, `states`, for what was done to it. A slice the editor left alone, or a thin image, gets the
     `exact` cut here, which takes the bytes appended to an image off, when it shortens it; a thin file's artifacts
     are named by what was done to it alone, since one nothing was done to would be the file. Throws for a Mach-O
     that does not parse.
     */
    private static func slices(of file: File, exact: Bool, states: [[MachOEditor.State]]?) throws -> [(suffix: String, bytes: File)] {
        /// The cut alone, as a state of an image the editor left alone, when it shortens the image.
        func cut(_ image: MachO) -> MachOEditor.State? {
            let end = image.logicalEnd()
            guard exact, end < image.length else {
                return nil
            }
            return MachOEditor.State(edits: .exact, pieces: [.range(image.offset ..< image.offset + end)])
        }

        switch try Universal.open(file) {
        case let .fat(archs):
            return try archs.enumerated().flatMap { index, arch -> [(suffix: String, bytes: File)] in
                var chain = states?[index] ?? []
                if chain.isEmpty, let image = try MachO(file, offset: arch.offset, length: arch.length), let cut = cut(image) {
                    chain = [cut]
                }
                let whole = (suffix: "_\(arch.name)", bytes: File(editing: file, pieces: [.range(arch.offset ..< arch.offset + arch.length)]))
                return [whole] + chain.map { ("_\(arch.name)" + Self.suffix($0.edits), File(editing: file, pieces: $0.pieces)) }
            }
        case let .thin(image):
            var chain = states?[0] ?? []
            if chain.isEmpty, let cut = cut(image) {
                chain = [cut]
            }
            return chain.map { (Self.suffix($0.edits), File(editing: file, pieces: $0.pieces)) }
        case .notMachO:
            return []
        }
    }

    /**
     The artifact a file yields whole: the file as the edits left it, every architecture of a universal file laid out
     again, cut where it ends with `exact` as hash mode cuts it (`Universal.fileEnd`), named for what was done to any
     of its images, the last of its `states`; none when nothing was done, since it would be the file. Throws for a
     Mach-O that does not parse.
     */
    private static func whole(_ file: File, exact: Bool, states: [[MachOEditor.State]]?) throws -> [(suffix: String, bytes: File)] {
        let end = try exact ? Universal.fileEnd(file) : file.size
        var done = states?.reduce(into: MachOEditor.Edits()) { $0.formUnion($1.last?.edits ?? []) } ?? []
        if end < file.size {
            done.insert(.exact)
        }
        guard !done.isEmpty else {
            return []
        }
        return [(Self.suffix(done), end < file.size ? File(editing: file, pieces: [.range(0 ..< end)]) : file)]
    }

    /// What became of an artifact's path.
    private enum Outcome {
        /// A new file.
        case written
        /// The same bytes were there already: what they are.
        case identical(Identity)
        /// Another file was there and was replaced: what it was, and what it is now.
        case overwritten(before: Identity, after: Identity)
        /// Another file is there and stays: what it is, and what the artifact is.
        case differs(before: Identity, after: Identity)
    }

    /// A file's size and SHA-256, as the overwrite line names what was replaced and by what: "10 bytes, sha256 c1…".
    private struct Identity: CustomStringConvertible {
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
     Two files can yield one artifact: a thin Mach-O with appended bytes and its universal file under `--exact`, or an
     earlier artifact and its file under a later run's flags. Handed to two threads at once, the second to reach the
     artifact waits for the first, and finds it in place, rather than half written and reported as a different file.
     */
    private final class Writing: @unchecked Sendable {
        private let condition = NSCondition()
        private var paths: Set<String> = []

        /// Wait until no other thread writes `path`, then claim it.
        func claim(_ path: String) {
            self.condition.lock()
            while !self.paths.insert(path).inserted {
                self.condition.wait()
            }
            self.condition.unlock()
        }

        func release(_ path: String) {
            self.condition.lock()
            self.paths.remove(path)
            self.condition.broadcast()
            self.condition.unlock()
        }
    }

    /**
     Write `file` to `path`: a new file, or with `overwrite` a new file renamed over the regular file already
     there when it holds other bytes, as `lipo` writes its output; the same bytes are left as they are. The rename gives
     the name another inode rather than writing into the old one, so another link to it, to a file elsewhere say, keeps
     its bytes and its mode, and a write that fails leaves the old file as it was.
     */
    private static func write(_ file: File, to path: String, overwrite: Bool) throws -> Outcome {
        do {
            let fd = try FileDescriptor.open(path, .writeOnly, options: [.create, .exclusiveCreate], permissions: Self.permissions)
            try Self.copy(file, to: fd, at: path)
            return .written
        } catch let error as Errno where error == .fileExists {
            // What is there decides.
        }

        // lstat sees a symbolic link as itself, where open would follow it.
        var info = stat()
        guard lstat(path, &info) == 0, info.st_mode & S_IFMT == S_IFREG else {
            throw ArtifactError.notRegularFileInTheWay
        }
        let before = try Self.identity(of: File(path: path))
        let after = try Self.identity(of: file)
        if before.size == after.size, before.digest == after.digest {
            return .identical(after)
        }
        guard overwrite else {
            return .differs(before: before, after: after)
        }

        let replacement = "\(path).fashion-\(UUID().uuidString)"
        let fd = try FileDescriptor.open(replacement, .writeOnly, options: [.create, .exclusiveCreate], permissions: Self.permissions)
        try Self.copy(file, to: fd, at: replacement)
        guard rename(replacement, path) == 0 else {
            let error = Errno(rawValue: errno)
            unlink(replacement)
            throw error
        }
        return .overwritten(before: before, after: after)
    }

    /**
     Stream `file` into `fd` and close it; a write that fails leaves no file at `path`.
     */
    private static func copy(_ file: File, to fd: FileDescriptor, at path: String) throws {
        do {
            try file.stream(0 ..< file.size) { chunk in
                _ = try fd.writeAll(chunk)
            }
            try fd.close()
        } catch {
            try? fd.close()
            unlink(path)
            throw error
        }
    }

    /**
     The size and SHA-256 of `file`, the digest as `fashion -q` prints it.
     */
    private static func identity(of file: File) throws -> Identity {
        let sha256 = ByteHash(.sha256)! // nil for cdhash alone
        return try Identity(size: file.size, digest: ByteHash.digests([sha256], file).first?.digest ?? "")
    }
}
