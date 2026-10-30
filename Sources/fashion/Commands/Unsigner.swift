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
        discussion: copyright,
        helpNames: .shortAndLong,
        aliases: ["i"],
    )

    @OptionGroup
    var scan: ScanOptions

    @OptionGroup(title: "Unsign mode")
    var unsign: UnsignerOptions

    mutating func run() throws {
        let code = self.scan(trapSignals: true)
        if code != 0 {
            throw ExitCode(code)
        }
    }
}

struct UnsignerOptions: ParsableArguments {
    @Flag(name: .shortAndLong, help: "Replace a different file found under the artifact's name; otherwise it is reported and left alone.")
    var write = false
}

/**
 The work on one file: write it beside itself without its code signatures. `MachOEditor` makes the edit in memory,
 and the artifact is what hash mode's --unsign reads. The file is written whole: a universal file keeps every
 architecture, laid out again as `lipo` lays them out. `thinr --unsign` writes each architecture as a file of its own
 instead, the signed slice beside it; this goes straight to the artifact. `ls` gives `ls_unsigned`, and a thin file
 `sample` gives `sample_unsigned`, as `thinr --unsign` names it too.

 A file with no signature to remove, or that is not Mach-O, has nothing to write.

 Bytes appended past an image's end keep its signature from coming out: hash mode's --unsign refuses such a file, as
 `codesign` does. Here the bytes are cut off first, as --exact cuts them (`MachO.logicalEnd()`), and the artifact is
 named `_exact_unsigned` for it, what hash mode's --exact --unsign reads. An image of a universal file nothing is
 done to keeps its appended bytes, laid out as the fat table places it, since the file is read whole; `thinr --exact`
 cuts each. A signature inside its image, which no cut frees, is reported, and nothing is written for the file.
 */
extension Unsigner {
    /**
     Scan the paths and return a process exit code: `0` success, `2` one or more paths could not be enumerated, read
     or written. `trapSignals` as `Hasher.scan(trapSignals:)`.
     */
    func scan(trapSignals: Bool = false) -> Int32 {
        logger.info("Unsign\(self.scan.sort ? " sorted" : "", privacy: .public) with \(String(self.scan.resolvedJobs, pluralizing: "job"), privacy: .public) in \(String(self.scan.paths.count, pluralizing: "path"), privacy: .public): \(self.scan.paths.joined(separator: ", "), privacy: .public)")

        let write = self.unsign.write
        let run = self.scan.run(trapSignals: trapSignals, activity: "unsigning") { Self.lines(for: $0, write: write, reporter: $1) }
        return run.errorCount > 0 ? 2 : 0
    }

    /// The lines to print for one file, as `ArtifactWriter.lines(for:reporter:)` unsigned, whole.
    static func lines(for path: String, write: Bool, reporter: Reporter) -> [Line] {
        ArtifactWriter(exact: false, unsign: true, unpack: false, split: false, write: write).lines(for: path, reporter: reporter)
    }
}
