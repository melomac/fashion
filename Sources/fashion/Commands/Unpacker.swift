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
        discussion: copyright,
        helpNames: .shortAndLong,
        aliases: ["p", "upx"],
    )

    @OptionGroup
    var scan: ScanOptions

    @OptionGroup(title: "Unpack mode")
    var unpack: UnpackerOptions

    mutating func run() throws {
        let code = self.scan(trapSignals: true)
        if code != 0 {
            throw ExitCode(code)
        }
    }
}

struct UnpackerOptions: ParsableArguments {
    @Flag(name: .shortAndLong, help: "Replace a different file found under the artifact's name; otherwise it is reported and left alone.")
    var write = false

    @Flag(name: .shortAndLong, help: "Keep unpacked data as _decompressed, for further investigation.")
    var keep = false

    @Flag(name: [.customShort("i"), .long], help: "Remove the code signature the image kept from before packing too.")
    var unsign = false
}

/**
 The work on one file: write it beside itself with what UPX packed unpacked, as `upx -d` unpacks it. `MachOEditor`
 makes the edit in memory, and the artifact is what hash mode's --unpack reads. The file is written whole: a universal
 file keeps every architecture, laid out again as `lipo` lays them out. `thinr --unpack` writes each architecture as a
 file of its own instead, and every state on the way; this goes straight to the last.

 `sample` gives `sample_unpacked`. A signature added after packing hides what UPX left, so it comes out first, and the
 artifact is `sample_unsigned_unpacked`, as `thinr --unpack` names its last artifact. The unpacked code keeps the
 signature it had before packing, if any: --unsign takes it off too, into `sample_unsigned_unpacked_unsigned`, as
 `thinr --unpack --unsign` names its last artifact, and `unsign` over the artifact gives the same.

 A file UPX did not pack, or that is not Mach-O, has nothing to write. Packed data that does not hold is reported, in
 red; with --keep, what decompressed of it is written as it is all the same, `sample_decompressed`, or
 `sample_arm64_decompressed` for a slice of a universal file, since it is no image to lay out, for analysis by hand.

 Bytes appended past a signature added after packing hide what UPX left: hash mode's --unpack hashes such a file as it
 is, with nothing said, and its --unsign refuses it. Here the bytes are cut off first, as --exact cuts them
 (`MachO.logicalEnd()`), the signature comes out, and the artifact is named `_exact_unsigned_unpacked` for it, what
 hash mode's --exact --unpack reads. An image of a universal file nothing is done to keeps its appended bytes, since
 the file is read whole. A file cut short of its last page, as a file UPX 3.91 packed and that lost it, is padded to
 be read, as --exact pads it, and named `_exact` for that too. The unpacked image keeps the bytes appended to it
 before packing, as `upx -d` gives them back; `thinr --exact --unpack` cuts them.
 */
extension Unpacker {
    /**
     Scan the paths and return a process exit code: `0` success, `2` one or more paths could not be enumerated, read
     or written. `trapSignals` as `Hasher.scan(trapSignals:)`.
     */
    func scan(trapSignals: Bool = false) -> Int32 {
        logger.info("Unpack\(self.scan.sort ? " sorted" : "", privacy: .public) with \(String(self.scan.resolvedJobs, pluralizing: "job"), privacy: .public) in \(String(self.scan.paths.count, pluralizing: "path"), privacy: .public): \(self.scan.paths.joined(separator: ", "), privacy: .public)")

        let (write, keep, unsign) = (self.unpack.write, self.unpack.keep, self.unpack.unsign)
        let run = self.scan.run(trapSignals: trapSignals, activity: "unpacking") { Self.lines(for: $0, write: write, keep: keep, unsign: unsign, reporter: $1) }
        return run.errorCount > 0 ? 2 : 0
    }

    /// The lines to print for one file, as `ArtifactWriter.lines(for:reporter:)` unpacked, whole, and with `unsign` the
    /// signature the unpacked image kept out too.
    static func lines(for path: String, write: Bool, keep: Bool = false, unsign: Bool = false, reporter: Reporter) -> [Line] {
        ArtifactWriter(exact: false, unsign: unsign, unpack: true, split: false, write: write, keep: keep).lines(for: path, reporter: reporter)
    }
}
