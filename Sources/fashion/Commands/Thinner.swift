import ArgumentParser
import Foundation
import os
import System

private let logger = Logger(subsystem: "fashion", category: "thin")

enum ThinError: Error, Equatable {
    /// Something that is not a regular file, a symlink say, stands where the artifact goes: it is left alone.
    case notRegularFileInTheWay
}

extension ThinError: LocalizedError {
    var errorDescription: String? {
        switch self {
        case .notRegularFileInTheWay:
            "exists and is not a regular file, left alone"
        }
    }
}

/**
 `fashion thin`: each architecture of a universal Mach-O written out beside it, as a file of its own.
 */
struct Thinner: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "thin",
        abstract: "Write each architecture of a universal Mach-O out beside it, as a file of its own.",
        helpNames: .shortAndLong,
    )

    @OptionGroup
    var scan: ScanOptions

    @Flag(help: "Write the exact Mach-O image, dropping appended bytes.")
    var exact = false

    @Flag(help: "Replace a different file found under an artifact's name; otherwise it is reported and left alone.")
    var overwrite = false

    mutating func run() throws {
        let code = self.scan(trapSignals: true)
        if code != 0 {
            throw ExitCode(code)
        }
    }
}

/**
 The work on one file: write each architecture of a universal Mach-O out beside it, named by the architecture as
 `codesign --arch` spells it, `ls_x86_64` and `ls_arm64e` for `ls`. The fat table alone decides the bytes, as it does
 for `lipo -thin`. A thin file, or one that is not Mach-O, has nothing to write.

 With `--exact`, each slice is read as a Mach-O and cut where its image ends (`MachO.logicalEnd()`), so bytes appended
 to it are dropped, as hash mode's `--exact` drops them; a thin Mach-O followed by appended bytes then becomes an
 artifact too, where one that ends where its image ends has nothing to write.

 An artifact the cut changes is named for it, `_exact` after the architecture of a universal file's slice,
 `ls_x86_64_exact`, or after the name of a thin file, which needs no architecture, `sample_exact`. It stands beside the
 plain one rather than in its way, and one the cut leaves as it is keeps its name.

 An artifact already in place, byte for byte, is left as it is and noted in the unified log alone, so a second run over
 a tree is as quiet on the terminal as the first was. A different file under an artifact's name is left alone and
 reported, with its size and SHA-256 and the slice's, unless `--overwrite` replaces it, in which case the unified log
 alone records the same. A symbolic link, or anything that is not a regular file, is never followed nor replaced: it
 is reported and left alone, a safety rule for analysis.
 */
extension Thinner {
    /**
     Scan the paths and return a process exit code: `0` success, `2` one or more paths could not be enumerated, read
     or written. `trapSignals` as `Hasher.scan(trapSignals:)`.
     */
    func scan(trapSignals: Bool = false) -> Int32 {
        logger.info("Thin\(self.scan.sort ? " sorted" : "", privacy: .public)\(self.exact ? " exact" : "", privacy: .public) with \(String(self.scan.resolvedJobs, pluralizing: "job"), privacy: .public) in \(String(self.scan.paths.count, pluralizing: "path"), privacy: .public): \(self.scan.paths.joined(separator: ", "), privacy: .public)")

        let (exact, overwrite) = (self.exact, self.overwrite)
        let run = self.scan.run(trapSignals: trapSignals, activity: "thinning") { Self.lines(for: $0, exact: exact, overwrite: overwrite, reporter: $1) }
        return run.errorCount > 0 ? 2 : 0
    }

    /**
     The lines to print for one file: the path of each artifact written or found in place, or a diagnostic for each
     that could not be written, or that a different file stands for without `overwrite`. A file that cannot be read,
     or whose Mach-O is malformed (red), is reported instead, and nothing is written.
     */
    static func lines(for path: String, exact: Bool, overwrite: Bool, reporter: Reporter) -> [Line] {
        let file: File
        let artifacts: [(suffix: String, range: Range<Int>)]
        do {
            file = try File(path: path)
            artifacts = try Self.artifacts(of: file, exact: exact)
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
                switch try Self.write(range, of: file, to: artifact, overwrite: overwrite) {
                case .written:
                    return [Line(text: OutputFormatter.formatPath(artifact))]
                case let .identical(identity):
                    logger.info("\(artifact, privacy: .public): already in place, \(identity.description, privacy: .public)")
                    return [Line(text: OutputFormatter.formatPath(artifact))]
                case let .overwritten(before, after):
                    logger.info("\(artifact, privacy: .public): overwritten, was \(before.description, privacy: .public), now \(after.description, privacy: .public)")
                    return [Line(text: OutputFormatter.formatPath(artifact))]
                case let .differs(before, after):
                    return [reporter.report(path: artifact, message: "exists and differs, \(before) where the slice is \(after); left alone without --overwrite")]
                }
            } catch {
                return [reporter.report(path: artifact, message: File.message(for: error))]
            }
        }
    }

    // MARK: - Private

    /**
     The artifacts a file yields, each with the suffix its name takes after the file's: a universal file's slice its
     architecture, then `_exact` when the `exact` cut takes appended bytes off. Every slice of a universal file, as the
     fat table places it or cut, a slice that is not Mach-O staying whole; a thin image when it was cut. Throws for a
     Mach-O that does not parse.
     */
    private static func artifacts(of file: File, exact: Bool) throws -> [(suffix: String, range: Range<Int>)] {
        switch try Universal.open(file) {
        case let .fat(archs):
            return try archs.map { arch in
                var length = arch.length
                if exact, let image = try MachO(file, offset: arch.offset, length: arch.length) {
                    length = image.logicalEnd()
                }
                return ("_\(arch.name)" + (length < arch.length ? "_exact" : ""), arch.offset ..< arch.offset + length)
            }
        case let .thin(image):
            // A thin file's artifact is named by what was done to it alone: one nothing was done to would be the file.
            let end = image.logicalEnd()
            guard exact, end < image.length else {
                return []
            }
            return [("_exact", 0 ..< end)]
        case .notMachO:
            return []
        }
    }

    /// What became of an artifact's path.
    private enum Outcome {
        /// A new file.
        case written
        /// The same bytes were there already: what they are.
        case identical(Identity)
        /// Another file was there and was replaced: what it was, and what it is now.
        case overwritten(before: Identity, after: Identity)
        /// Another file is there and stays: what it is, and what the slice is.
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
            throw ThinError.notRegularFileInTheWay
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
