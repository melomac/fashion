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
        abstract: "Write Mach-O code UPX packed out beside it as it was before packing.",
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
 The work on one file: write it beside itself with what UPX packed unpacked, as `upx -d` unpacks it, as `MachOEditor`
 edits it in memory and as hash mode's `--unpack` reads it, whole: a universal file keeps every architecture, laid out
 again as `lipo` lays them out, where `thin --unpack` writes each as a file of its own. `sample` gives
 `sample_unpacked`, as `thin --unpack` names a thin file too, with the signature it had before packing, if any: `unsign`
 over the artifact takes it off, into `sample_unpacked_unsigned`, as `thin --unpack --unsign` would. A file UPX did
 not pack, or that is not Mach-O, has nothing to write; packed data that does not hold is reported (red).

 With `--exact`, an image is cut where it ends (`MachO.logicalEnd()`), so bytes appended to it do not keep a signature
 added after packing in, as hash mode's `--exact` drops them.
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
