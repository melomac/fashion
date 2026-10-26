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
        abstract: "Write Mach-O code out beside it without its signature, restored as it was before.",
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
 The work on one file: write it beside itself without its code signatures, as `MachOEditor` edits it in memory and as
 hash mode's `--unsign` reads it, whole: a universal file keeps every architecture, laid out again as `lipo` lays them
 out, where `thin --unsign` writes each as a file of its own, the signed slice beside it, where this goes straight
 to the artifact. `ls` gives `ls_unsigned`, and a thin file `sample` `sample_unsigned`, as `thin --unsign` names it
 too. A file with no signature to remove, or that is not Mach-O, has nothing to write.

 With `--exact`, each image is cut where it ends (`MachO.logicalEnd()`) before its signature comes off, so bytes
 appended to it do not keep it in, as hash mode's `--exact` drops them, and the artifact is named `_exact` for it too.
 A signature that does not end its image is reported otherwise, and nothing is written for the file.
 */
extension Unsigner {
    /**
     Scan the paths and return a process exit code: `0` success, `2` one or more paths could not be enumerated, read
     or written. `trapSignals` as `Hasher.scan(trapSignals:)`.
     */
    func scan(trapSignals: Bool = false) -> Int32 {
        logger.info("Unsign\(self.scan.sort ? " sorted" : "", privacy: .public)\(self.exact ? " exact" : "", privacy: .public) with \(String(self.scan.resolvedJobs, pluralizing: "job"), privacy: .public) in \(String(self.scan.paths.count, pluralizing: "path"), privacy: .public): \(self.scan.paths.joined(separator: ", "), privacy: .public)")

        let (exact, overwrite) = (self.exact, self.overwrite)
        let run = self.scan.run(trapSignals: trapSignals, activity: "unsigning") { Self.lines(for: $0, exact: exact, overwrite: overwrite, reporter: $1) }
        return run.errorCount > 0 ? 2 : 0
    }

    /// The lines to print for one file, as `ArtifactWriter.lines(for:reporter:)` unsigned, whole.
    static func lines(for path: String, exact: Bool, overwrite: Bool, reporter: Reporter) -> [Line] {
        ArtifactWriter(exact: exact, unsign: true, unpack: false, split: false, overwrite: overwrite).lines(for: path, reporter: reporter)
    }
}
