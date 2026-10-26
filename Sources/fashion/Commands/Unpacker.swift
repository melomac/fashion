import ArgumentParser
import Foundation
import os

private let logger = Logger(subsystem: "fashion", category: "unpack")

/**
 `fashion unpack`: Mach-O code UPX packed written out beside it as it was before packing.
 */
struct Unpacker: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "unpack",
        abstract: "Write and restore a UPX-packed Mach-O image, unpacked without UPX.",
        helpNames: .shortAndLong,
    )

    @OptionGroup
    var scan: ScanOptions

    @Flag(help: "Write an exact Mach-O image, dropping appended bytes.")
    var exact = false

    @Flag(help: "Replace a different file found under the artifact's name; otherwise it is reported and left alone.")
    var overwrite = false

    mutating func run() throws {
        let code = self.scan(trapSignals: true)
        if code != 0 {
            throw ExitCode(code)
        }
    }
}

/**
 The work on one file: write it beside itself with what UPX packed unpacked, as `upx -d` unpacks it. `MachOEditor`
 makes the edit in memory, and the artifact is what hash mode's --unpack reads. The file is written whole: a universal
 file keeps every architecture, laid out again as `lipo` lays them out. `thin --unpack` writes each architecture as a
 file of its own instead, and every state on the way; this goes straight to the last.

 `sample` gives `sample_unpacked`. A signature added after packing hides what UPX left, so it comes out first, and the
 artifact is `sample_unsigned_unpacked`, as `thin --unpack` names its last artifact. The unpacked code keeps the
 signature it had before packing, if any: `unsign` over the artifact takes it off, into
 `sample_unsigned_unpacked_unsigned`, as `thin --unpack --unsign` would.

 A file UPX did not pack, or that is not Mach-O, has nothing to write, unless --exact cuts bytes appended to it: the
 cut alone is written then, as `_exact`. Packed data that does not hold is reported, in red.

 With --exact, an image UPX packed is cut where it ends (`MachO.logicalEnd()`) before anything else, as hash mode's
 --exact cuts it, so bytes appended after a signature do not keep it in. An image of a universal file the flags leave
 alone keeps its appended bytes, since hash mode reads the file whole. Without --exact, such a signature cannot come
 out, hides what UPX left, and the file is left as it is with nothing said, as hash mode's --unpack alone hashes it;
 --unsign refuses it there.
 */
extension Unpacker {
    /**
     Scan the paths and return a process exit code: `0` success, `2` one or more paths could not be enumerated, read
     or written. `trapSignals` as `Hasher.scan(trapSignals:)`.
     */
    func scan(trapSignals: Bool = false) -> Int32 {
        logger.info("Unpack\(self.scan.sort ? " sorted" : "", privacy: .public)\(self.exact ? " exact" : "", privacy: .public) with \(String(self.scan.resolvedJobs, pluralizing: "job"), privacy: .public) in \(String(self.scan.paths.count, pluralizing: "path"), privacy: .public): \(self.scan.paths.joined(separator: ", "), privacy: .public)")

        let (exact, overwrite) = (self.exact, self.overwrite)
        let run = self.scan.run(trapSignals: trapSignals, activity: "unpacking") { Self.lines(for: $0, exact: exact, overwrite: overwrite, reporter: $1) }
        return run.errorCount > 0 ? 2 : 0
    }

    /// The lines to print for one file, as `ArtifactWriter.lines(for:reporter:)` unpacked, whole.
    static func lines(for path: String, exact: Bool, overwrite: Bool, reporter: Reporter) -> [Line] {
        ArtifactWriter(exact: exact, unsign: false, unpack: true, split: false, overwrite: overwrite).lines(for: path, reporter: reporter)
    }
}
