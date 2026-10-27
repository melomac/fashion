import ArgumentParser
import Foundation
import MachO
import os

private let logger = Logger(subsystem: "fashion", category: "verify")

/**
 `fashion verify`: what is odd about each Mach-O, one line each.
 */
struct Verifier: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "verify",
        abstract: "Verify Mach-O files for anomalies.",
        helpNames: .shortAndLong,
        aliases: ["v"],
    )

    @OptionGroup
    var scan: ScanOptions

    mutating func run() throws {
        let code = self.scan(trapSignals: true)
        if code != 0 {
            throw ExitCode(code)
        }
    }
}

/**
 The work on one file: one line for each thing `MachO.anomalies(in:)` finds odd about each image, after the file's
 path, and for a universal file itself: a Mach-O slice not page aligned, slices that overlap, bytes past the last
 slice. A file with nothing to say, or that is not Mach-O, prints nothing; nor does an archive among a universal
 file's slices, which `lipo` aligns for its members' symbols alone.

 What the parser refuses, by the loader's own rules, is reported in red and counted, as hash mode reports it. In a
 universal file the slice is named by its architecture, and the other slices' lines are kept.
 */
extension Verifier {
    /**
     Scan the paths and return a process exit code: `0` success, `2` one or more paths could not be enumerated or
     parsed. `trapSignals` as `Hasher.scan(trapSignals:)`.
     */
    func scan(trapSignals: Bool = false) -> Int32 {
        logger.info("Verify\(self.scan.sort ? " sorted" : "", privacy: .public)")

        let run = self.scan.run(trapSignals: trapSignals, activity: "verifying") { Self.lines(for: $0, reporter: $1) }
        return run.errorCount > 0 ? 2 : 0
    }

    /// The lines to print for one file.
    static func lines(for path: String, reporter: Reporter) -> [Line] {
        func line(_ finding: String, arch: String? = nil) -> Line {
            Line(text: "\(OutputFormatter.formatPath(path))\(arch.map { " (\($0))" } ?? ""): \(finding)")
        }
        do {
            let file = try File(path: path)
            switch try Universal.open(file) {
            case let .thin(image):
                return image.anomalies(in: file).map { line($0) }
            case let .fat(archs):
                var lines: [Line] = []
                let placed = archs.sorted { $0.offset < $1.offset }
                for (before, after) in zip(placed, placed.dropFirst()) where after.offset < before.offset + before.length {
                    lines.append(line("slices \(before.name) and \(after.name) overlap"))
                }
                if let last = placed.last, last.offset + last.length < file.size {
                    lines.append(line("\((file.size - last.offset - last.length).hex) bytes past the last slice, \(last.name)'s end at \((last.offset + last.length).hex)"))
                }
                for arch in archs {
                    do {
                        // An archive, which lipo aligns for its members' symbols, and a dSYM, which no loader maps, say nothing.
                        guard let image = try MachO(file, offset: arch.offset, length: arch.length) else {
                            continue
                        }
                        if image.filetype != UInt32(MH_DSYM), arch.offset % 0x1000 != 0 {
                            lines.append(line("slice \(arch.name) at \(arch.offset.hex) is not page aligned"))
                        }
                        lines += image.anomalies(in: file).map { line($0, arch: arch.name) }
                    } catch {
                        lines.append(reporter.report(path: "\(path) (\(arch.name))", message: File.message(for: error), tint: Digester.tint(for: error)))
                    }
                }
                return lines
            case .notMachO:
                return []
            }
        } catch {
            return [reporter.report(path: path, message: File.message(for: error), tint: Digester.tint(for: error))]
        }
    }
}
