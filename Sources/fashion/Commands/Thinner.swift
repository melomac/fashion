import ArgumentParser
import Foundation
import os

private let logger = Logger(subsystem: "fashion", category: "thinr")

/**
 `fashion thinr`: each architecture of a universal Mach-O listed, and every state the flags take it through; with
 --write, each written out beside it, as a file of its own.
 */
struct Thinner: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "thin",
        abstract: "Scan Mach-O files for artifacts, each architecture and each state the flags take it through.",
        discussion: copyright,
        helpNames: .shortAndLong,
        aliases: ["t", "thinr"],
    )

    @OptionGroup
    var scan: ScanOptions

    @OptionGroup(title: "Thin mode")
    var thin: ThinnerOptions

    mutating func run() throws {
        let code = self.scan(trapSignals: true)
        if code != 0 {
            throw ExitCode(code)
        }
    }
}

struct ThinnerOptions: ParsableArguments {
#if SECURITY_STRICT_VALIDATION
    @Flag(name: [.short, .long, .customLong("strict")], help: "Read a strict Mach-O image, dropping appended bytes.")
#else
    @Flag(name: .shortAndLong, help: "Read an exact Mach-O image, dropping appended bytes.")
#endif
    var exact = false

    @Flag(name: [.customShort("i"), .long], help: "Read and restore a Mach-O image, removing the code signature.")
    var unsign = false

    @Flag(name: [.customShort("p"), .long], help: "Read and restore a UPX-packed Mach-O image, unpacked without UPX.")
    var unpack = false

    @Flag(name: .shortAndLong, help: "Verify a Mach-O image for anomalies.")
    var verify = false

    @Flag(name: .shortAndLong, help: "Write the artifacts beside the file, rename conflicting file.")
    var write = false

    @Flag(name: .shortAndLong, help: "Keep unpacked data as _decompressed, for further investigation.")
    var keep = false
}

/**
 The work on one file: each architecture of a universal Mach-O as a file of its own beside it, named by the architecture
 as `codesign --arch` spells it, `ls_x86_64` and `ls_arm64e` for `ls`. The fat table alone decides the bytes, as it does
 for `lipo -thin`. A thin file, or one that is not Mach-O, has nothing to write.

 With --exact, each slice is read as a Mach-O and cut where its image ends (`MachO.logicalEnd()`), so bytes appended
 to it are dropped, as hash mode's --exact drops them. A thin Mach-O with appended bytes gets an artifact then, the
 cut; one that ends where its image ends has nothing to write.

 Nothing is written without --write: each artifact is listed as hash mode labels the state, `ls (x86_64, unsigned)`
 for what --write would write as `ls_x86_64_unsigned`, so a tree can be looked over before it is written beside.
 The edits are made all the same, so what cannot be read or unpacked is reported either way. With --write, the
 artifacts are written, and a different file under an artifact's name is kept beside it as the conflict backup
 (`ArtifactWriter`), its path printed after the artifact's.

 With --quiet, a file that has artifacts is printed once, its own path, in place of their lines; what is reported
 about it stands, since --quiet shortens standard output alone.

 With --unsign, the file is read without its code signatures; with --unpack, with what UPX packed unpacked. Both are
 edits `MachOEditor` makes in memory, after the --exact cut. Every state a slice goes through is an artifact: the
 slice as the fat table places it, then cut, then without its signature, then unpacked, then the unpacked image cut
 and without its own signature, as far as the flags go. A signature added after packing comes out before the image is
 unpacked, so --unpack alone has that state too. A thin Mach-O the flags change gets its artifacts the same way,
 where `unsign` and `unpack` write the file as the edits leave it, whole.

 Bytes appended past an image's end keep its signature from coming out. They are cut off as needed, without --exact:
 for --unsign to take the signature off, and for --unpack to find UPX behind it. The cut is a state of its own, named
 `_exact` as --exact would name it; the unpacked image's own signature gets the same. A file cut short of its last
 page is padded to be read, as --exact pads it, when an edit comes of it. A signature inside its image, which no cut
 frees, is reported under --unsign and nothing is written for the file; under --unpack alone it stays, and the image
 is looked at as it is.

 With --keep, what decompressed of a UPX image that fails a check after, a sum or its headers, is written as it is,
 `ls_x86_64_decompressed`, after the states before it, and the refusal is reported as without the flag.

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
        logger.info("Thin\(self.scan.sort ? " sorted" : "", privacy: .public)\(self.thin.exact ? " exact" : "", privacy: .public)\(self.thin.unsign ? " unsign" : "", privacy: .public)\(self.thin.unpack ? " unpack" : "", privacy: .public)\(self.thin.keep ? " keep" : "", privacy: .public)\(self.thin.verify ? " verifying" : "", privacy: .public)\(self.scan.quiet ? " quiet" : "", privacy: .public) with \(String(self.scan.resolvedJobs, pluralizing: "job"), privacy: .public) in \(String(self.scan.paths.count, pluralizing: "path"), privacy: .public): \(self.scan.paths.joined(separator: ", "), privacy: .public)")

        let (exact, unsign, unpack, write, keep, quiet, verify) = (self.thin.exact, self.thin.unsign, self.thin.unpack, self.thin.write, self.thin.keep, self.scan.quiet, self.thin.verify)
        let run = self.scan.run(trapSignals: trapSignals, activity: "thinning") { file, reporter in
            let lines = Self.lines(for: file, exact: exact, unsign: unsign, unpack: unpack, write: write, keep: keep, quiet: quiet, reporter: reporter)
            if verify {
                // The same descriptor, after the artifacts: what the log says is about the bytes that were thinned.
                Verify.log(file)
            }
            return lines
        }
        return run.errorCount > 0 ? 2 : 0
    }

    /// The lines to print for one file, as `ArtifactWriter.lines(for:reporter:)` split: listed without `write`, written
    /// and replaced with it. `quiet` keeps the diagnostics and puts the file's path, once, for the artifacts' paths.
    static func lines(for file: File, exact: Bool, unsign: Bool, unpack: Bool, write: Bool, keep: Bool = false, quiet: Bool = false, reporter: Reporter) -> [Line] {
        let lines = ArtifactWriter(exact: exact, unsign: unsign, unpack: unpack, split: true, mode: write ? .replace : .list, keep: keep).lines(for: file, reporter: reporter)
        return quiet ? Line.quiet(lines, naming: file.path) : lines
    }
}
