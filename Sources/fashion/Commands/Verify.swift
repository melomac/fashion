import ArgumentParser
import Foundation
import MachO
import os

private let logger = Logger(subsystem: "fashion", category: "verify")

/**
 `fashion verify`: what is odd about each Mach-O, one line each.
 */
struct Verify: ParsableCommand {
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
 The work on one file: one line for each thing `MachOVerifier` finds odd about each image, after the file's path, and
 for a universal file itself and each slice against its entry in the table. A file with nothing to say, or that is
 not Mach-O, prints nothing; nor does an archive among a universal file's slices, which `lipo` aligns for its members'
 symbols alone.

 What the parser refuses, by the kernel's own rules, is reported in red and counted, as hash mode reports it, and so
 is a signature Security cannot read, after the lines of its image. In a universal file the slice is named by its
 architecture, and the other slices' lines are kept.
 */
extension Verify {
    /**
     Scan the paths and return a process exit code: `0` success, `2` one or more paths could not be enumerated or
     parsed. `trapSignals` as `Hasher.scan(trapSignals:)`.
     */
    func scan(trapSignals: Bool = false) -> Int32 {
        logger.info("\(self.scan.sort ? "Verify sorted" : "Verify", privacy: .public) with \(String(self.scan.resolvedJobs, pluralizing: "job"), privacy: .public) in \(String(self.scan.paths.count, pluralizing: "path"), privacy: .public): \(self.scan.paths.joined(separator: ", "), privacy: .public)")

        let run = self.scan.run(trapSignals: trapSignals, activity: "verifying") { Self.lines(for: $0, reporter: $1) }
        return run.errorCount > 0 ? 2 : 0
    }

    /// The lines to print for one file.
    static func lines(for path: String, reporter: Reporter) -> [Line] {
        func line(_ finding: String, arch: String? = nil) -> Line {
            Line(text: "\(OutputFormatter.formatPath(path))\(arch.map { " (\($0))" } ?? ""): \(finding)")
        }
        func refused(_ error: Error, arch: String? = nil) -> Line {
            reporter.report(path: "\(path)\(arch.map { " (\($0))" } ?? "")", message: File.message(for: error), tint: Digester.tint(for: error))
        }
        do {
            let file = try File(path: path)
            switch try Universal.open(file) {
            case let .thin(image):
                let (found, error) = MachOVerifier(image, in: file).anomalies()
                return found.map { line($0) } + (error.map { [refused($0)] } ?? [])
            case let .fat(archs):
                var lines = MachOVerifier.anomalies(universal: file, archs).map { line($0) }
                for arch in archs {
                    do {
                        guard let image = try MachO(file, offset: arch.offset, length: arch.length) else {
                            if let odd = try MachOVerifier.anomaly(slice: arch, in: file) {
                                lines.append(line(odd))
                            }
                            continue
                        }
                        let verifier = MachOVerifier(image, in: file)
                        lines += verifier.anomalies(slice: arch).map { line($0) }
                        let (found, error) = verifier.anomalies()
                        lines += found.map { line($0, arch: arch.name) }
                        if let error {
                            lines.append(refused(error, arch: arch.name))
                        }
                    } catch {
                        lines.append(refused(error, arch: arch.name))
                    }
                }
                return lines
            case .notMachO:
                return []
            }
        } catch {
            return [refused(error)]
        }
    }
}
