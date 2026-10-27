import ArgumentParser
import Foundation
import os

private let logger = Logger(subsystem: "fashion", category: "thinr")

/**
 `fashion thinr`: each architecture of a universal Mach-O written out beside it, as a file of its own, and every state
 the flags take it through.
 */
struct Thinner: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "thinr",
        abstract: "Write the artifacts of a Mach-O beside it: each architecture, each state the flags take it through.",
        helpNames: .shortAndLong,
        aliases: ["t", "thin"],
    )

    @OptionGroup
    var scan: ScanOptions

    @Flag(help: "Write an exact Mach-O image, dropping appended bytes.")
    var exact = false

    @Flag(help: "Write and restore a Mach-O image, removing the code signature.")
    var unsign = false

    @Flag(help: "Write and restore a UPX-packed Mach-O image, unpacked without UPX.")
    var unpack = false

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
 The work on one file: write each architecture of a universal Mach-O out beside it, named by the architecture as
 `codesign --arch` spells it, `ls_x86_64` and `ls_arm64e` for `ls`. The fat table alone decides the bytes, as it does
 for `lipo -thin`. A thin file, or one that is not Mach-O, has nothing to write.

 With --exact, each slice is read as a Mach-O and cut where its image ends (`MachO.logicalEnd()`), so bytes appended
 to it are dropped, as hash mode's --exact drops them. A thin Mach-O with appended bytes gets an artifact then, the
 cut; one that ends where its image ends has nothing to write.

 With --unsign, the file is read without its code signatures; with --unpack, with what UPX packed unpacked. Both are
 edits `MachOEditor` makes in memory, after the --exact cut. Every state a slice goes through is written: the slice
 as the fat table places it, then cut, then without its signature, then unpacked, then the unpacked image cut and
 without its own signature, as far as the flags go. A signature added after packing comes out before the image is
 unpacked, so --unpack alone writes that state too. A thin Mach-O the flags change gets its artifacts the same way,
 where `unsign` and `unpack` write the file as the edits leave it, whole.

 Bytes appended past an image's end keep its signature from coming out. They are cut off as needed, without --exact:
 for --unsign to take the signature off, and for --unpack to find UPX behind it. The cut is a state of its own, named
 `_exact` as --exact would name it; the unpacked image's own signature gets the same. A file cut short of its last
 page is padded to be read, as --exact pads it, when an edit comes of it. A signature inside its image, which no cut
 frees, is reported under --unsign and nothing is written for the file; under --unpack alone it stays, and the image
 is looked at as it is.

 `ArtifactWriter` names and writes the artifacts, split: `ls_x86_64`, `ls_x86_64_unsigned`,
 `ls_x86_64_unsigned_unpacked` after the architecture of a universal file's slice, or `sample_unsigned` after the
 name of a thin file, which needs no architecture.
 */
extension Thinner {
    /**
     Scan the paths and return a process exit code: `0` success, `2` one or more paths could not be enumerated, read
     or written. `trapSignals` as `Hasher.scan(trapSignals:)`.
     */
    func scan(trapSignals: Bool = false) -> Int32 {
        logger.info("Thin\(self.scan.sort ? " sorted" : "", privacy: .public)\(self.exact ? " exact" : "", privacy: .public)\(self.unsign ? " unsign" : "", privacy: .public)\(self.unpack ? " unpack" : "", privacy: .public) with \(String(self.scan.resolvedJobs, pluralizing: "job"), privacy: .public) in \(String(self.scan.paths.count, pluralizing: "path"), privacy: .public): \(self.scan.paths.joined(separator: ", "), privacy: .public)")

        let (exact, unsign, unpack, write) = (self.exact, self.unsign, self.unpack, self.write)
        let run = self.scan.run(trapSignals: trapSignals, activity: "thinning") { Self.lines(for: $0, exact: exact, unsign: unsign, unpack: unpack, write: write, reporter: $1) }
        return run.errorCount > 0 ? 2 : 0
    }

    /// The lines to print for one file, as `ArtifactWriter.lines(for:reporter:)` split.
    static func lines(for path: String, exact: Bool, unsign: Bool, unpack: Bool, write: Bool, reporter: Reporter) -> [Line] {
        ArtifactWriter(exact: exact, unsign: unsign, unpack: unpack, split: true, write: write).lines(for: path, reporter: reporter)
    }
}
