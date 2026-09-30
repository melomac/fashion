@testable import fashion
import XCTest

/**
 The signal contract: a trap takes over only the signals not inherited as ignored and puts them back afterwards,
 and the command line still ends the way a shell expects when its output goes away.
 */
final class SignalTrapTests: XCTestCase {
    private static let signals = [SIGINT, SIGTERM, SIGINFO, SIGPIPE]

    private func handler(_ signo: Int32) -> Int {
        var action = sigaction()
        sigaction(signo, nil, &action)
        return unsafeBitCast(action.__sigaction_u.__sa_handler, to: Int.self)
    }

    private var ignored: Int {
        unsafeBitCast(SIG_IGN, to: Int.self)
    }

    func testTrapIgnoresWhileActiveAndRestores() {
        let before = Self.signals.map(self.handler)
        let trap = SignalTrap(reporter: Reporter())
        for signo in Self.signals {
            XCTAssertEqual(self.handler(signo), self.ignored, "signal \(signo)")
        }
        trap.restore()
        XCTAssertEqual(Self.signals.map(self.handler), before)
    }

    func testTrapLeavesInheritedIgnoredSignal() {
        let previous = signal(SIGINT, SIG_IGN)
        defer { signal(SIGINT, previous) }

        let trap = SignalTrap(reporter: Reporter())
        trap.restore()
        XCTAssertEqual(self.handler(SIGINT), self.ignored)
    }

    // MARK: - Command Line

    /**
     Run the built `fashion` on a small tree with stdout a pipe whose reader is gone, like a `| head` that already exited.
     */
    private func runWithClosedStdout(shell: String? = nil) throws -> (reason: Process.TerminationReason, status: Int32, stderr: String) {
        let binary = Bundle(for: Self.self).bundleURL.deletingLastPathComponent() / "fashion"
        try XCTSkipUnless(FileManager.default.isExecutableFile(atPath: binary.path), "fashion binary unavailable")

        let directory = FileManager.default.temporaryDirectory / UUID().uuidString
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        for index in 0 ..< 3 {
            try Data("\(index)".utf8).write(to: directory / "\(index)")
        }

        let stdout = Pipe()
        try stdout.fileHandleForReading.close()
        let stderr = Pipe()
        let process = Process()
        if let shell {
            process.executableURL = URL(fileURLWithPath: "/bin/sh")
            process.arguments = ["-c", "\(shell); exec \"$0\" \"$@\"", binary.path, directory.path]
        } else {
            process.executableURL = binary
            process.arguments = [directory.path]
        }
        process.standardOutput = stdout
        process.standardError = stderr

        try process.run()
        let output = stderr.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return (process.terminationReason, process.terminationStatus, String(decoding: output, as: UTF8.self))
    }

    func testClosedStdoutDiesOfSIGPIPE() throws {
        let result = try self.runWithClosedStdout()
        XCTAssertEqual(result.reason, .uncaughtSignal)
        XCTAssertEqual(result.status, SIGPIPE)
        XCTAssertEqual(result.stderr, "")
    }

    func testClosedStdoutWithInheritedIgnoredSIGPIPEExitsWithWriteError() throws {
        let result = try self.runWithClosedStdout(shell: "trap '' PIPE")
        XCTAssertEqual(result.reason, .exit)
        XCTAssertEqual(result.status, 2)
        XCTAssertTrue(result.stderr.hasPrefix("fashion: write error:"), result.stderr)
    }
}
