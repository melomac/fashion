import ArgumentParser
import Foundation
import os

private let logger = Logger(subsystem: "fashion", category: "thin")

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

    @Flag(help: "Write Mach-O code without its signature, restored as it was before.")
    var unsign = false

    @Flag(help: "Write Mach-O code UPX packed as it was before packing.")
    var unpack = false

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

 With `--unsign`, the file is read without its code signatures, and with `--unpack`, with what UPX packed unpacked, as
 `MachOEditor` edits it in memory, after the `--exact` cut, and every state a slice goes through is written: the slice
 as the fat table places it, then cut, then without its signature, which comes out before an image is unpacked
 anyway, then unpacked, then the unpacked image cut and without its own signature, as far as the flags take it. So a
 thin Mach-O they change becomes an artifact too, where `unsign` and `unpack` write the file as the edits leave it,
 whole. A signature that does not end its image, appended bytes after it say, is reported and nothing is written for
 the file: `--exact` cuts those bytes off first.

 `ArtifactWriter` names and writes them, split: `ls_x86_64`, `ls_x86_64_unsigned`, `ls_x86_64_unsigned_unpacked` after
 the architecture of a universal file's slice, or `sample_unsigned` after the name of a thin file, which needs no
 architecture.
 */
extension Thinner {
    /**
     Scan the paths and return a process exit code: `0` success, `2` one or more paths could not be enumerated, read
     or written. `trapSignals` as `Hasher.scan(trapSignals:)`.
     */
    func scan(trapSignals: Bool = false) -> Int32 {
        logger.info("Thin\(self.scan.sort ? " sorted" : "", privacy: .public)\(self.exact ? " exact" : "", privacy: .public)\(self.unsign ? " unsign" : "", privacy: .public)\(self.unpack ? " unpack" : "", privacy: .public) with \(String(self.scan.resolvedJobs, pluralizing: "job"), privacy: .public) in \(String(self.scan.paths.count, pluralizing: "path"), privacy: .public): \(self.scan.paths.joined(separator: ", "), privacy: .public)")

        let (exact, unsign, unpack, overwrite) = (self.exact, self.unsign, self.unpack, self.overwrite)
        let run = self.scan.run(trapSignals: trapSignals, activity: "thinning") { Self.lines(for: $0, exact: exact, unsign: unsign, unpack: unpack, overwrite: overwrite, reporter: $1) }
        return run.errorCount > 0 ? 2 : 0
    }

    /// The lines to print for one file, as `ArtifactWriter.lines(for:reporter:)` split.
    static func lines(for path: String, exact: Bool, unsign: Bool, unpack: Bool, overwrite: Bool, reporter: Reporter) -> [Line] {
        ArtifactWriter(exact: exact, unsign: unsign, unpack: unpack, split: true, overwrite: overwrite).lines(for: path, reporter: reporter)
    }
}
