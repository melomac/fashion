import ArgumentParser
import Foundation
import os

private let logger = Logger(subsystem: "fashion", category: "unsign")

/**
 `fashion unsign`: Mach-O code written out beside it without its signature, restored as it was before signing.
 */
struct Unsigner: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "unsign",
        abstract: "Write and restore a Mach-O image, removing the code signature.",
        helpNames: .shortAndLong,
        aliases: ["s"],
    )

    @OptionGroup
    var scan: ScanOptions

    @Flag(help: "Write an exact Mach-O image, dropping appended bytes.")
    var exact = false

    @Flag(help: "Replace a different file found under the artifact's name; otherwise it is reported and left alone.")
    var write = false

    mutating func run() throws {
        let code = self.scan(trapSignals: true)
        if code != 0 {
            throw ExitCode(code)
        }
    }
}

/**
 The work on one file: write it beside itself without its code signatures. `MachOEditor` makes the edit in memory,
 and the artifact is what hash mode's --unsign reads. The file is written whole: a universal file keeps every
 architecture, laid out again as `lipo` lays them out. `thinr --unsign` writes each architecture as a file of its own
 instead, the signed slice beside it; this goes straight to the artifact. `ls` gives `ls_unsigned`, and a thin file
 `sample` gives `sample_unsigned`, as `thinr --unsign` names it too.

 A file with no signature to remove, or that is not Mach-O, has nothing to write, unless --exact cuts bytes appended
 to it: the cut alone is written then, as `_exact`.

 With --exact, an image whose signature comes off is cut where it ends (`MachO.logicalEnd()`) first, as hash mode's
 --exact cuts it, so bytes appended after the signature do not keep it in; the artifact is named `_exact` for the cut
 too. An image of a universal file the flags leave alone keeps its appended bytes, laid out as the fat table places
 it, since hash mode reads the file whole; `thinr --exact` cuts each. Without --exact, a signature that does not end
 its image is reported, and nothing is written for the file.
 */
extension Unsigner {
    /**
     Scan the paths and return a process exit code: `0` success, `2` one or more paths could not be enumerated, read
     or written. `trapSignals` as `Hasher.scan(trapSignals:)`.
     */
    func scan(trapSignals: Bool = false) -> Int32 {
        logger.info("Unsign\(self.scan.sort ? " sorted" : "", privacy: .public)\(self.exact ? " exact" : "", privacy: .public) with \(String(self.scan.resolvedJobs, pluralizing: "job"), privacy: .public) in \(String(self.scan.paths.count, pluralizing: "path"), privacy: .public): \(self.scan.paths.joined(separator: ", "), privacy: .public)")

        let (exact, write) = (self.exact, self.write)
        let run = self.scan.run(trapSignals: trapSignals, activity: "unsigning") { Self.lines(for: $0, exact: exact, write: write, reporter: $1) }
        return run.errorCount > 0 ? 2 : 0
    }

    /// The lines to print for one file, as `ArtifactWriter.lines(for:reporter:)` unsigned, whole.
    static func lines(for path: String, exact: Bool, write: Bool, reporter: Reporter) -> [Line] {
        ArtifactWriter(exact: exact, unsign: true, unpack: false, split: false, write: write).lines(for: path, reporter: reporter)
    }
}
