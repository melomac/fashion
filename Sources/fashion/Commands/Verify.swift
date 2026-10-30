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
        discussion: copyright,
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

    /**
     The lines to print for one file: each finding, which the unified log gets as a notice too, as `log(_:)` leaves it,
     and each refusal, which the reporter logs as an error.
     */
    static func lines(for path: String, reporter: Reporter) -> [Line] {
        var lines: [Line] = []
        self.verify(path) { finding, arch in
            logger.notice("\(arch.map { "\(path) (\($0))" } ?? path, privacy: .public): \(finding, privacy: .public)")
            lines.append(Line(text: "\(OutputFormatter.formatPath(path))\(arch.map { " (\($0))" } ?? ""): \(finding)"))
        } refused: { error, arch in
            lines.append(reporter.report(path: "\(path)\(arch.map { " (\($0))" } ?? "")", message: File.message(for: error), tint: Digester.tint(for: error)))
        }
        return lines
    }

    /**
     What `verify` would print of one file, in the unified log alone: each finding as a notice, each refusal as an
     error, under the `verify` category, as `lines(for:reporter:)` logs them beside its lines. `hash --verify` and
     `thinr --verify` call it for each file they work on, so that a scan for another purpose leaves what is odd about
     its files in the log, and prints nothing more.
     */
    static func log(_ path: String) {
        self.verify(path) { finding, arch in
            let subject = arch.map { "\(path) (\($0))" } ?? path
            logger.notice("\(subject, privacy: .public): \(finding, privacy: .public)")
        } refused: { error, arch in
            let subject = arch.map { "\(path) (\($0))" } ?? path
            logger.error("\(subject, privacy: .public): \(File.message(for: error), privacy: .public)")
        }
    }

    /**
     What `MachOVerifier` finds about one file, as it is found: `found` gets each finding with the architecture of the
     slice it is about, nil for the file or a universal file's table; `refused` gets what the parser refuses of a file
     or a slice, and a signature Security cannot read, the same way.
     */
    static func verify(_ path: String, found: (_ finding: String, _ arch: String?) -> Void, refused: (_ error: Error, _ arch: String?) -> Void) {
        do {
            try self.verify(File(path: path), found: found, refused: refused)
        } catch {
            refused(error, nil)
        }
    }

    /// The same over a file already open, which throws what it refuses of the file as a whole: the fuzzer's `verify`
    /// harness runs it with closures that keep nothing.
    static func verify(_ file: File, found: (_ finding: String, _ arch: String?) -> Void, refused: (_ error: Error, _ arch: String?) -> Void) throws {
        // The slice hidden past the table's count that does not lie in the file: no slice to hash mode, which takes
        // the file as the table counts it, a refusal here, as dyld refuses the file for it.
        var hiddenRefused: (name: String, error: ParserError)?
        switch try Universal.open(file, hiddenRefused: { hiddenRefused = ($0, $1) }) {
        case let .thin(image):
            let (findings, error) = MachOVerifier(image, in: file).anomalies()
            findings.forEach { found($0, nil) }
            if let error {
                refused(error, nil)
            }
        case let .fat(archs):
            MachOVerifier.anomalies(universal: file, archs).forEach { found($0, nil) }
            if let hiddenRefused {
                refused(hiddenRefused.error, "\(hiddenRefused.name) hidden past the table")
            }
            for arch in archs {
                do {
                    guard let image = try MachO(file, offset: arch.offset, length: arch.length) else {
                        if let odd = try MachOVerifier.anomaly(slice: arch, in: file) {
                            found(odd, nil)
                        }
                        continue
                    }
                    let verifier = MachOVerifier(image, in: file)
                    verifier.anomalies(slice: arch).forEach { found($0, nil) }
                    let (findings, error) = verifier.anomalies()
                    findings.forEach { found($0, arch.name) }
                    if let error {
                        refused(error, arch.name)
                    }
                } catch {
                    refused(error, arch.name)
                }
            }
        case .notMachO:
            if let archs = try Universal.oversized(file) {
                found(MachOVerifier.anomaly(oversized: archs), nil)
            }
        }
    }
}
