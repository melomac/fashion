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
    @Flag(name: .shortAndLong, help: "Write the artifacts beside the file, rename conflicting file.")
    var write = false
}

/**
 The work on one file: write it beside itself without its code signatures. `MachOEditor` makes the edit in memory,
 and the artifact is what hash mode's --unsign reads. The file is written whole: a universal file keeps every
 architecture, laid out again as `lipo` lays them out. `thinr --unsign` takes each architecture apart instead, the
 signed slice beside the unsigned one; this goes straight to the whole. `ls` gives `ls_unsigned`, and a thin file
 `sample` gives `sample_unsigned`, as `thinr --unsign` names it too.

 A file with no signature to remove, or that is not Mach-O, has nothing to write.

 Bytes appended past an image's end keep its signature from coming out, as they keep `codesign` from removing it.
 Here the bytes are cut off first, as --exact cuts them (`MachO.logicalEnd()`), and the artifact is named
 `_exact_unsigned` for it, what hash mode's --unsign reads too, as `(exact, unsigned)`. An image of a universal file
 nothing is done to keeps its appended bytes, laid out as the fat table places it, since the file is read whole;
 `thinr --exact` cuts each. A signature inside its image, which no cut frees, is reported, and nothing is written for the file.

 With --quiet, a file that has an artifact is printed once, its own path, in place of the artifact's; what is
 reported about a file stands.
 */
extension Unsigner {
    /**
     Scan the paths and return a process exit code: `0` success, `2` one or more paths could not be enumerated, read
     or written. `trapSignals` as `Hasher.scan(trapSignals:)`.
     */
    func scan(trapSignals: Bool = false) -> Int32 {
        logger.info("Unsign\(self.scan.sort ? " sorted" : "", privacy: .public)\(self.scan.quiet ? " quiet" : "", privacy: .public) with \(String(self.scan.resolvedJobs, pluralizing: "job"), privacy: .public) in \(String(self.scan.paths.count, pluralizing: "path"), privacy: .public): \(self.scan.paths.joined(separator: ", "), privacy: .public)")

        let (write, quiet) = (self.unsign.write, self.scan.quiet)
        let run = self.scan.run(trapSignals: trapSignals, activity: "unsigning") { Self.lines(for: $0, write: write, quiet: quiet, reporter: $1) }
        return run.errorCount > 0 ? 2 : 0
    }

    /// The lines to print for one file, as `ArtifactWriter.lines(for:reporter:)` unsigned, whole; `quiet` as
    /// `Line.quiet(_:naming:)`.
    static func lines(for file: File, write: Bool, quiet: Bool = false, reporter: Reporter) -> [Line] {
        let lines = ArtifactWriter(exact: false, unsign: true, unpack: false, split: false, mode: write ? .replace : .write).lines(for: file, reporter: reporter)
        return quiet ? Line.quiet(lines, naming: file.path) : lines
    }
}
