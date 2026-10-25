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

 An artifact is named after the file for what was done to it, in the order it was done: `_unpacked`, `_exact`, then
 `_unsigned`, after the architecture of a slice `split` out, `ls_x86_64_unsigned`, or after the name of the file
 itself, `sample_unsigned` or `ls_unsigned`. A slice nothing was done to keeps its name, `ls_x86_64`, and a file
 nothing was done to yields no artifact, since it would be the file. A later run with other flags over an artifact
 names what it makes as one run with them all would: `ls_x86_64` unsigned is `ls_x86_64_unsigned` either way.

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
     nothing is written.
     */
    func lines(for path: String, reporter: Reporter) -> [Line] {
        let file: File
        let artifacts: [(suffix: String, range: Range<Int>)]
        do {
            let opened = try File(path: path)
            let edited = try self.unsign || self.unpack ? MachOEditor.edit(opened, exact: self.exact, unsign: self.unsign, unpack: self.unpack) : nil
            file = edited?.file ?? opened
            artifacts = try self.split ? Self.slices(of: file, exact: self.exact, edits: edited?.edits) : Self.whole(file, exact: self.exact, edits: edited?.edits)
        } catch {
            return [reporter.report(path: path, message: File.message(for: error), tint: Digester.tint(for: error))]
        }

        return artifacts.flatMap { suffix, range -> [Line] in
            let artifact = path + suffix
            Self.writing.claim(artifact)
            defer {
                Self.writing.release(artifact)
            }
            do {
                switch try Self.write(range, of: file, to: artifact, overwrite: self.overwrite) {
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

    /// The suffix an artifact's name takes for `edits`, in the order the edits are made: unpacked, then cut, then
    /// without the signature.
    private static func suffix(_ edits: MachOEditor.Edits) -> String {
        let suffixes: [(MachOEditor.Edits, String)] = [(.unpacked, "_unpacked"), (.exact, "_exact"), (.unsigned, "_unsigned")]
        return suffixes.filter { edits.contains($0.0) }.map(\.1).joined()
    }

    /**
     The artifacts a file yields split, each with the suffix its name takes after the file's: a universal file's slice
     its architecture, then for any artifact what was done to it, `edits`, the edits of a file `MachOEditor` made, and
     the `exact` cut, which takes the bytes appended to an image off. Every slice of a universal file, as the fat table
     places it or cut, a slice that is not Mach-O staying whole; a thin image when it was edited or cut. Throws for a
     Mach-O that does not parse.
     */
    private static func slices(of file: File, exact: Bool, edits: [MachOEditor.Edits]?) throws -> [(suffix: String, range: Range<Int>)] {
        func suffix(_ index: Int, cut: Bool) -> String {
            var done = edits.flatMap { $0.indices.contains(index) ? $0[index] : nil } ?? []
            if cut {
                done.insert(.exact)
            }
            return Self.suffix(done)
        }

        switch try Universal.open(file) {
        case let .fat(archs):
            return try archs.enumerated().map { index, arch in
                var length = arch.length
                if exact, let image = try MachO(file, offset: arch.offset, length: arch.length) {
                    length = image.logicalEnd()
                }
                return ("_\(arch.name)" + suffix(index, cut: length < arch.length), arch.offset ..< arch.offset + length)
            }
        case let .thin(image):
            // A thin file's artifact is named by what was done to it alone: one nothing was done to would be the file.
            let end = exact ? image.logicalEnd() : image.length
            let name = suffix(0, cut: end < image.length)
            guard !name.isEmpty else {
                return []
            }
            return [(name, 0 ..< end)]
        case .notMachO:
            return []
        }
    }

    /**
     The artifact a file yields whole: the file as `edits` left it, every architecture of a universal file laid out
     again, cut where it ends with `exact` as hash mode cuts it (`Universal.fileEnd`), named for what was done to any
     of its images; none when nothing was done, since it would be the file. Throws for a Mach-O that does not parse.
     */
    private static func whole(_ file: File, exact: Bool, edits: [MachOEditor.Edits]?) throws -> [(suffix: String, range: Range<Int>)] {
        let end = try exact ? Universal.fileEnd(file) : file.size
        var done = edits?.reduce(into: MachOEditor.Edits()) { $0.formUnion($1) } ?? []
        if end < file.size {
            done.insert(.exact)
        }
        guard !done.isEmpty else {
            return []
        }
        return [(Self.suffix(done), 0 ..< end)]
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
     Write `range` of `file` to `path`: a new file, or with `overwrite` a new file renamed over the regular file already
     there when it holds other bytes, as `lipo` writes its output; the same bytes are left as they are. The rename gives
     the name another inode rather than writing into the old one, so another link to it, to a file elsewhere say, keeps
     its bytes and its mode, and a write that fails leaves the old file as it was.
     */
    private static func write(_ range: Range<Int>, of file: File, to path: String, overwrite: Bool) throws -> Outcome {
        do {
            let fd = try FileDescriptor.open(path, .writeOnly, options: [.create, .exclusiveCreate], permissions: Self.permissions)
            try Self.copy(range, of: file, to: fd, at: path)
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
        let after = try Self.identity(of: file, range: range)
        if before.size == after.size, before.digest == after.digest {
            return .identical(after)
        }
        guard overwrite else {
            return .differs(before: before, after: after)
        }

        let replacement = "\(path).fashion-\(UUID().uuidString)"
        let fd = try FileDescriptor.open(replacement, .writeOnly, options: [.create, .exclusiveCreate], permissions: Self.permissions)
        try Self.copy(range, of: file, to: fd, at: replacement)
        guard rename(replacement, path) == 0 else {
            let error = Errno(rawValue: errno)
            unlink(replacement)
            throw error
        }
        return .overwritten(before: before, after: after)
    }

    /**
     Stream `range` of `file` into `fd` and close it; a write that fails leaves no file at `path`.
     */
    private static func copy(_ range: Range<Int>, of file: File, to fd: FileDescriptor, at path: String) throws {
        do {
            try file.stream(range) { chunk in
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
     The size and SHA-256 of `range` of `file`, the whole file by default, the digest as `fashion -q` prints it.
     */
    private static func identity(of file: File, range: Range<Int>? = nil) throws -> Identity {
        let sha256 = ByteHash(.sha256)! // nil for cdhash alone
        return try Identity(size: range?.count ?? file.size, digest: ByteHash.digests([sha256], file, range: range).first?.digest ?? "")
    }
}
