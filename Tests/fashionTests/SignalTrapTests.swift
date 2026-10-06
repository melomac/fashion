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

    /**
     Whether every signal is ignored within a second: a trap ignores each one once its source is registered, asynchronously.
     */
    private func eventuallyAllIgnored() -> Bool {
        let deadline = Date().addingTimeInterval(1)
        while Date() < deadline {
            if Self.signals.allSatisfy({ self.handler($0) == self.ignored }) {
                return true
            }
            usleep(1000)
        }
        return false
    }

    func testTrapIgnoresWhileActiveAndRestores() {
        let before = Self.signals.map(self.handler)
        let trap = SignalTrap(reporter: Reporter())
        XCTAssertTrue(self.eventuallyAllIgnored())
        trap.restore()
        XCTAssertEqual(Self.signals.map(self.handler), before)
    }

    func testRestoreBeforeRegistrationLeavesSignalsRestored() {
        let before = Self.signals.map(self.handler)
        let trap = SignalTrap(reporter: Reporter())
        trap.restore()
        // A registration handler running late must not ignore a signal the trap already gave back.
        usleep(100_000)
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
        let binary = try fashionExecutable()

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
        process.environment = fashionEnvironment
        process.standardOutput = stdout
        process.standardError = stderr

        try process.run()
        let output = stderr.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return (process.terminationReason, process.terminationStatus, String(decoding: output, as: UTF8.self))
    }

    func testSigTermEndsTheRunWhileStdOutIsBlocked() throws {
        // A reader that stops reading blocks the stdout write: SIGTERM must still end the run, as without the trap.
        let binary = try fashionExecutable()
        let directory = FileManager.default.temporaryDirectory / UUID().uuidString
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        // Lines of about 150 bytes: 2000 files overflow a 64 KiB pipe.
        for index in 0 ..< 2000 {
            try Data("\(index)".utf8).write(to: directory / "\(index)")
        }

        let stdout = Pipe() // never read
        let process = Process()
        process.executableURL = binary
        process.arguments = [directory.path]
        process.standardOutput = stdout
        process.standardError = FileHandle.nullDevice
        try self.assertSigTermEnds(process, blocking: stdout, "stdout")
    }

    func testSigTermEndsTheRunWhileStdErrIsBlocked() throws {
        // A reader that stops reading blocks the stderr write of a diagnostic: SIGTERM must still end the run.
        let binary = try fashionExecutable()
        // Lines of about 150 bytes: 2000 missing paths overflow a 64 KiB pipe.
        let missing = (0 ..< 2000).map { "/nonexistent-\(String(repeating: "x", count: 100))/\($0)" }

        let stderr = Pipe() // never read
        let process = Process()
        process.executableURL = binary
        process.arguments = missing
        process.standardOutput = FileHandle.nullDevice
        process.standardError = stderr
        try self.assertSigTermEnds(process, blocking: stderr, "stderr")
    }

    /**
     Run `process`, send it SIGTERM once its output has had time to fill `pipe`, which nobody reads, and require that it
     dies of the signal within five seconds.
     */
    private func assertSigTermEnds(_ process: Process, blocking pipe: Pipe, _ stream: String) throws {
        process.environment = fashionEnvironment
        try process.run()
        // Output means the run, and with it the signal trap, is under way: a signal sent before that would only meet the
        // default action. Then give the writer time to fill the pipe and block.
        _ = pipe.fileHandleForReading.readData(ofLength: 1)
        usleep(500_000)
        process.terminate()

        let deadline = Date().addingTimeInterval(5)
        while process.isRunning, Date() < deadline {
            usleep(10000)
        }
        guard !process.isRunning else {
            kill(process.processIdentifier, SIGKILL)
            process.waitUntilExit()
            return XCTFail("SIGTERM did not end the run while \(stream) was blocked")
        }
        XCTAssertEqual(process.terminationReason, .uncaughtSignal)
        XCTAssertEqual(process.terminationStatus, SIGTERM)
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
