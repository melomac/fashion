import Foundation
import os
import System

/*
 The scan, end to end. `Fashion.scan()` builds the parts below once per run, then the calling (main) thread walks the
 paths and hands each file to `jobs` hash threads, which print through `Output` and `Console`.

 fashion [options] <paths>
   |
   v
 Fashion.run() -> scan()        built once per scan:
                                  Digester    per-file options, read once
                                  Console     owns stdout and stderr, and the status line
                                  Reporter    counts, diagnostics, unified log, end of run
                                  SignalTrap  INT/TERM/PIPE: log the end, die of the signal
                                              INFO (^T): progress on stderr
                                  Output      prints each file's lines

 MAIN THREAD: WALKER                HANDOFF           HASH THREADS (x jobs)
 QoS userInitiated                  64 paths          QoS userInitiated
 +--------------------------+       +---------+       +--------------------------------+
 | FileWalker (fts)         |  put  |         |  take | output.started(index, path)    |
 | unsorted: as found       |------>| (index, |------>| digester.lines(for: path)      |
 | --sort: roots in natural |       |  path)  |       |   digests(path), by mode:      |
 | order, each directory    |       |         |       |     symhash | xar-toc |        |
 | by fashion_fts_compare   |       +---------+       |     cdhash | slices | file     |
 | walk errors -> Reporter  |                         |   -> [DigestResult]            |
 +--------------------------+                         |   -> match / quiet -> lines    |
                                                      |   diagnostics: Reporter, lines |
                                                      | reporter.fileProcessed()       |
                                                      | output.finished(index, lines)  |
                                                      +--------------------------------+
              | handoff.close() when the walk ends                     |
              v                                                        v
        hashing.wait()                                +--------------------------------+
              |                                       | Output (condition)             |
              v                                       |  unsorted: queue now           |
        reporter.end("done")                          |  --sort: hold by index until   |
        exit 0, 1 (no match), 2 (errors)              |  every earlier file queued     |
                                                      |  one thread prints the queue,  |
                                                      |  the others hash on            |
                                                      |  write error -> trap / exit 2  |
                                                      +--------------------------------+
                                                                       |
 status timer (foreground terminal only)                               v
 after 0.5 s, every 100 ms:                           +--------------------------------+
   output.showStatus() ------------------------------>| Console                        |
   "N files · M waiting ·                             |  pipe or file: write as is     |
    hashing …<path>"                                  |  terminal: erase the status    |
                                                      |  line, controls shown as ?,    |
                                                      |  each line in its tint         |
                                                      +--------------------------------+
                                                                       |
                                                                       v
                                                                stdout / stderr

 Signals (command line only):
   SIGINT, SIGTERM  -> reporter.end -> console.close() (never waits) -> die of the signal
   SIGPIPE          -> held back: EPIPE in Console.out -> trap.brokenPipe() -> die of SIGPIPE
   SIGINFO (^T)     -> reporter.progress() -> "fashion: N files with M errors in T, P peak memory"
 */

private let logger = Logger(subsystem: "fashion", category: "runner")

// MARK: Pipeline Types

/**
 One digest of a file: of the whole file, or of one of its slices, named by `label` (`arm64`, `x86_64, ADHOC, sha256`).
 */
struct DigestResult {
    let digest: String
    var label: String?
    var tint = Tint.none

    /**
     The path as printed: `path (label)`, or the bare path for the whole file.
     */
    func display(_ path: String) -> String {
        self.label.map { "\(path) (\($0))" } ?? path
    }
}

/**
 A line to print, and how it shows on a terminal.

 A file's diagnostics are lines of its own, for stderr. Where both streams show on one terminal they print with the
 file's lines rather than as they come (see `Output`), so the terminal shows them together.
 */
struct Line {
    let text: String
    var tint = Tint.none
    var diagnostic = false
}

/**
 How a line shows on a terminal, by what it tells.
 */
enum Tint: Equatable {
    case none
    /// Green: a match by its distance, 0 when identical, as any exact match is, to 1 at the threshold (see `Digester.matchTint(_:)`).
    case match(distance: Double)
    /// Gray: a fuzzy match too distant to mean much, whatever the threshold.
    case weak
    /// Red: a file whose own bytes are malformed, on stderr.
    case malformed
    /// Yellow: any other diagnostic on stderr.
    case error
    /// Dimmed: a synthesized ad-hoc cdhash.
    case adhoc

    /// The SGR parameters that set it: with 256 colors, greens by shade and a gray; with 16, the terminal's own green,
    /// dimmed past identical, and bright black for gray.
    func sgr(colors256: Bool = true) -> String? {
        switch self {
        case .none: nil
        case .malformed: "31"
        case .error: "33"
        case .adhoc: "2"
        case let .match(distance):
            // Full green only when identical, then darker greens by quarters of the way to the threshold.
            switch distance {
            case ...0: colors256 ? "38;5;46" : "32" // #00ff00
            case ...0.25: colors256 ? "38;5;40" : "2;32" // #00d700
            case ...0.5: colors256 ? "38;5;34" : "2;32" // #00af00
            case ...0.75: colors256 ? "38;5;28" : "2;32" // #008700
            default: colors256 ? "38;5;22" : "2;32" // #005f00
            }
        case .weak: colors256 ? "38;5;245" : "90"
        }
    }
}

// MARK: - Console

/**
 The terminal side of a run: lines to stdout and stderr. When stdout is a terminal, a status line under the output.
 The status line is erased before any other write and when the run ends, so it never ends up in a pipe, a file or the
 terminal's scrollback.

 On a terminal, control characters in a line show as "?" (see `printable(_:)`), and a line shows in its tint unless
 `TERM=dumb` or `NO_COLOR` is set (https://no-color.org): in 256 colors when `TERM` (xterm-256color, xterm-direct) or
 `COLORTERM` claims them, in 16 otherwise.

 Off a terminal there is no status line, and lines go straight out: the callers' own locks keep them whole, and nothing
 here makes a signal handler or a diagnostic wait for a stdout write blocked by a reader that stopped reading.
 */
final class Console: @unchecked Sendable {
    /// Whether stdout is a terminal that can show the status line (not Emacs-style `TERM=dumb`).
    private static let environment = ProcessInfo.processInfo.environment
    private static let dumb = Console.environment["TERM"] == "dumb"
    let isLive = isatty(STDOUT_FILENO) == 1 && !Console.dumb
    private let stdoutIsTerminal = isatty(STDOUT_FILENO) == 1
    private let stderrIsTerminal = isatty(STDERR_FILENO) == 1
    /// Whether stdout and stderr both show on a terminal, where a file's diagnostics print with its lines (see `Output`).
    let streamsMeet = isatty(STDOUT_FILENO) == 1 && isatty(STDERR_FILENO) == 1
    private let tints = !Console.dumb && Console.environment["NO_COLOR", default: ""].isEmpty
    private let colors256 = ["256color", "direct"].contains { Console.environment["TERM", default: ""].contains($0) } || Console.environment["COLORTERM"] != nil
    private let lock = NSLock()
    private var shown = false
    private var closed = false

    /**
     Write lines to stdout, in one write, none for no lines; throws on a write error.
     */
    func out(_ lines: some Sequence<Line>) throws {
        var bytes: [UInt8] = []
        for line in lines {
            bytes.append(contentsOf: self.rendered(line.text, tint: line.tint, terminal: self.stdoutIsTerminal).utf8)
            bytes.append(UInt8(ascii: "\n"))
        }
        guard !bytes.isEmpty else {
            return
        }
        try self.write(bytes, to: .standardOutput)
    }

    /**
     Write a line to stderr. A write error must not abort the scan; a closed stderr pipe still ends it through the
     trapped SIGPIPE.
     */
    func err(_ line: String, tint: Tint = .none) {
        try? self.write((self.rendered(line, tint: tint, terminal: self.stderrIsTerminal) + "\n").utf8, to: .standardError)
    }

    /**
     Show `head` followed by as much of the end of `path` as fits the terminal, until the run is over.
     */
    func status(_ head: String, path: String) {
        // Not from a background job, which would draw over the shell's prompt and what is being typed.
        guard
            self.isLive,
            tcgetpgrp(STDOUT_FILENO) == getpgrp()
        else {
            return
        }
        self.lock.withLock {
            guard !self.closed else {
                return
            }

            var size = winsize()
            let width = ioctl(STDOUT_FILENO, TIOCGWINSZ, &size) == 0 && size.ws_col > 0 ? Int(size.ws_col) : 80

            let path = Self.printable(path)
            let room = max(width - 1 - head.count, 1)
            let tail = path.count <= room ? path : "…" + path.suffix(room - 1)

            // Dim, and without auto-wrap so a line too wide for the terminal is clipped: one carriage return erases it.
            _ = try? FileDescriptor.standardOutput.writeAll("\r\u{1B}[2m\u{1B}[?7l\(head)\(tail)\u{1B}[?7h\u{1B}[22m\u{1B}[K".utf8)
            self.shown = true
        }
    }

    /**
     Take the status line off the terminal for good: the run is over. Signal handlers call this, so it never waits: whoever
     holds the lock is writing a line, which erased the status line first.
     */
    func close() {
        guard
            self.isLive,
            self.lock.try()
        else {
            return
        }
        defer {
            self.lock.unlock()
        }
        self.erase()
        self.closed = true
    }

    /**
     A line as a terminal may show it: a control character from a file name, such as ESC, would move the cursor,
     restyle the terminal or rewrite earlier output, so it shows as "?", as `ls` does. Pipes and files get every byte.
     */
    static func printable(_ line: String) -> String {
        // C0 controls, DEL and C1 controls: Unicode's general category Cc.
        let isControl = { (scalar: Unicode.Scalar) in scalar.value < 0x20 || (0x7f ... 0x9f).contains(scalar.value) }
        guard line.unicodeScalars.contains(where: isControl) else {
            return line
        }
        return String(String.UnicodeScalarView(line.unicodeScalars.map { isControl($0) ? "?" : $0 }))
    }

    /**
     A printable line in its tint, which ends with the line.
     */
    static func tinted(_ line: String, _ tint: Tint, colors256: Bool = true) -> String {
        tint.sgr(colors256: colors256).map { "\u{1B}[\($0)m\(line)\u{1B}[0m" } ?? line
    }

    /**
     A line as a terminal shows it, printable and in its tint; as is anywhere else.
     */
    private func rendered(_ line: String, tint: Tint, terminal: Bool) -> String {
        terminal ? Self.tinted(Self.printable(line), self.tints ? tint : .none, colors256: self.colors256) : line
    }

    /**
     On a terminal, erase the status line first, under the lock so it cannot be redrawn in the middle of the lines.
     */
    private func write(_ bytes: some Sequence<UInt8>, to fd: FileDescriptor) throws {
        guard self.isLive else {
            _ = try fd.writeAll(bytes)
            return
        }
        try self.lock.withLock {
            self.erase()
            _ = try fd.writeAll(bytes)
        }
    }

    /**
     Caller holds the lock.
     */
    private func erase() {
        if self.shown {
            _ = try? FileDescriptor.standardOutput.writeAll("\r\u{1B}[K".utf8)
            self.shown = false
        }
    }
}

// MARK: - Output

/**
 Thread-safe stdout writer: each file's lines print once it is hashed, right away or, with `--sort`, in the sorted
 order the paths were handed out, holding a file's lines until every file before it has printed. On a terminal, the
 status line shows the count of hashed files, the files held back and the file hashed for the longest.

 Lines ready to print queue up, and the first hash thread to find nobody printing prints them: all that have queued
 up each time a write returns, until none are left. The others hash on rather than wait, each for a write of its own,
 on a terminal that takes lines slower than they are hashed. Hashing then runs ahead of the terminal, by up to
 `backlog` lines before the hash threads wait for it, rather than in step with it.

 Where stdout and stderr both show on a terminal, a file's diagnostics queue with its lines, so the terminal shows
 them together; anywhere else they go out as they come, since nothing shows the two streams side by side and a line
 that waits in the queue is lost should the run end first.
 */
final class Output: @unchecked Sendable {
    /**
     How many lines may queue up for a slow terminal before the hash threads wait for it: a fraction of a second of
     small files, which carries them through a terminal's longer stalls, a few MB at most when full.
     */
    static let backlog = 1 << 13

    private let condition = NSCondition()
    private let sorted: Bool
    private let console: Console
    private let reporter: Reporter
    private let trap: SignalTrap?
    private var held: [Int: [Line]] = [:]
    private var hashing: [Int: String] = [:]
    private var queued: [Line] = []
    private var printing = false
    private var next = 0
    private var printed = false

    init(sorted: Bool, console: Console, reporter: Reporter, trap: SignalTrap?) {
        self.sorted = sorted
        self.console = console
        self.reporter = reporter
        self.trap = trap
    }

    /**
     Whether any line was printed on stdout, which in match mode means a file matched; diagnostics do not count.
     */
    var printedAny: Bool {
        self.condition.withLock { self.printed }
    }

    /**
     Note the file handed out at `index` as being hashed, for the status line.
     */
    func started(_ index: Int, path: String) {
        // Off a terminal nothing reads it: don't make every hash thread wait for the lock.
        guard self.console.isLive else {
            return
        }
        self.condition.withLock {
            self.hashing[index] = path
        }
    }

    /**
     Queue the lines of the file handed out at `index`, and print the queue unless another thread is printing it.
     */
    func finished(_ index: Int, lines: [Line]) {
        var lines = lines
        if !self.console.streamsMeet {
            for line in lines where line.diagnostic {
                self.reporter.emit(line)
            }
            lines.removeAll(where: \.diagnostic)
        }

        self.condition.lock()
        defer {
            self.condition.unlock()
        }
        self.hashing[index] = nil

        // Unsorted, a finished file is simply the next to print.
        self.held[self.sorted ? index : self.next] = lines
        while let ready = self.held.removeValue(forKey: self.next) {
            self.queued += ready
            self.next += 1
            if ready.contains(where: { !$0.diagnostic }) {
                self.printed = true
            }
        }

        // Another thread is printing: leave the lines to it, and wait only once it is far behind.
        while self.printing, self.queued.count > Self.backlog {
            self.condition.wait()
        }
        guard !self.printing else {
            return
        }
        self.printing = true
        while !self.queued.isEmpty {
            let lines = self.queued
            self.queued = []
            // Room for the threads waiting on the backlog; the write itself waits for nobody but the reader.
            self.condition.broadcast()
            self.condition.unlock()
            self.write(lines)
            self.condition.lock()
        }
        self.printing = false
    }

    /**
     Redraw the status line: the count of hashed files, the lines held back and the file hashed for the longest.
     */
    func showStatus() {
        let status: (path: String, waiting: Int)? = self.condition.withLock {
            guard let path = self.hashing.min(by: { $0.key < $1.key })?.value else {
                return nil
            }
            return (path, self.held.count)
        }
        guard let status else {
            return
        }
        // Off the lock: the write waits for the terminal, and the hash threads must not wait for that.
        self.console.status("\(String(self.reporter.fileCount, pluralizing: "file")) · \(status.waiting > 0 ? "\(status.waiting) waiting · " : "")hashing ", path: status.path)
    }

    /**
     One thread prints at a time, so lines from concurrent hash threads never interleave.

     A file's diagnostics go to stderr as they come among its lines, where the terminal shows them together.
     */
    private func write(_ lines: [Line]) {
        var start = lines.startIndex
        for index in lines.indices where lines[index].diagnostic {
            self.write(lines[start ..< index])
            self.reporter.emit(lines[index])
            start = index + 1
        }
        self.write(lines[start...])
    }

    private func write(_ lines: ArraySlice<Line>) {
        do {
            try self.console.out(lines)
        } catch {
            if error as? Errno == .brokenPipe {
                // The reader went away (`| head`): if the trap holds SIGPIPE, this logs the end and dies of it
                // silently, as the process would have without the trap.
                self.trap?.brokenPipe()
            }

            // Otherwise nothing more can be delivered (SIGPIPE inherited as ignored, or stdout closed): report
            // and exit like coreutils, rather than crash on the uncaught error.
            let description = OutputFormatter.formatDiagnostic(File.message(for: error))
            self.reporter.end("Stopped by write error: \(description)")
            self.console.err("fashion: write error: \(description)", tint: .error)

            exit(2)
        }
    }
}

// MARK: - Reporter

/**
 Thread-safe bookkeeping for one run, callable from the walking and hash threads as well as signal handlers:
 - diagnostics go to both stderr (for the user and scripts) and the unified log (for a persistent, queryable record),
   and failures are counted so the process can exit non-zero when any path could not be enumerated or hashed; a
   file's are logged and counted as they come, and printed with its lines where a terminal shows them together;
 - files are counted as hash threads finish them, for the status line, the progress report on SIGINFO and the end of
   the run, which is logged exactly once whether the run completes or is interrupted;
 - the progress report and the end of the run carry the peak memory footprint, which the kernel tracks on its own.
 */
final class Reporter: @unchecked Sendable {
    /// The counts, which ending the run on a signal reads.
    private let lock = NSLock()
    /// Keeps stderr lines whole; never held with `lock`, so a stderr write blocked by a reader that stopped reading
    /// cannot keep a signal from ending the run.
    private let lineLock = NSLock()
    private let console: Console
    private let clock = ContinuousClock()
    private let start: ContinuousClock.Instant
    private var files = 0
    private var errors = 0
    private var ended = false

    init(console: Console = Console()) {
        self.console = console
        self.start = self.clock.now
    }

    var fileCount: Int {
        self.lock.withLock { self.files }
    }

    var errorCount: Int {
        self.lock.withLock { self.errors }
    }

    /**
     A path that could not be enumerated or hashed, logged and counted now.

     The line is printed with the file's lines, or on its own (see `emit(_:)`).
     */
    func report(path: String, message: String, tint: Tint = .error) -> Line {
        logger.error("\(path, privacy: .public): \(message, privacy: .public)")

        self.lock.withLock {
            self.errors += 1
        }
        return Self.line(path: path, message: message, tint: tint)
    }

    /**
     A file that was hashed but deserves a second look, like a failure but uncounted: it leaves the exit status alone.
     */
    func warn(path: String, message: String) -> Line {
        logger.notice("\(path, privacy: .public): \(message, privacy: .public)")

        return Self.line(path: path, message: message, tint: .error)
    }

    /**
     What an algorithm left out of a file's digest, or why it made none: the input TLSH defines no digest of, or what
     lies past its length limit.

     Not a failure but the algorithm's definition: uncounted, though yellow like any other diagnostic.
     */
    func inform(path: String, message: String) -> Line {
        logger.info("\(path, privacy: .public): \(message, privacy: .public)")

        return Self.line(path: path, message: message, tint: .error)
    }

    /**
     Write a diagnostic line now: a walk error, which has no file lines to go out with, or a file's where no terminal
     shows both streams; otherwise the thread printing the file's lines emits its diagnostics among them (see `Output`).
     */
    func emit(_ line: Line) {
        self.lineLock.withLock {
            self.console.err(line.text, tint: line.tint)
        }
    }

    private static func line(path: String, message: String, tint: Tint) -> Line {
        Line(text: "fashion: \(OutputFormatter.formatPath(path)): \(OutputFormatter.formatDiagnostic(message))", tint: tint, diagnostic: true)
    }

    func fileProcessed() {
        self.lock.withLock { self.files += 1 }
    }

    /**
     Report the counts, elapsed time and peak memory so far to the log and to stderr, like `dd` on `SIGINFO` (⌃T).
     */
    func progress() {
        let summary = self.summary(self.lock.withLock { (self.files, self.errors) })
        logger.info("Progress: \(summary, privacy: .public)")

        self.lineLock.withLock {
            self.console.err("fashion: \(summary)")
        }
    }

    /**
     Take the status line off the terminal and log the counts, elapsed time and peak memory; calls after the first are
     ignored.
     */
    func end(_ reason: String) {
        self.console.close()
        let counts: (files: Int, errors: Int)? = self.lock.withLock {
            guard !self.ended else {
                return nil
            }
            self.ended = true
            return (self.files, self.errors)
        }
        guard let counts else {
            return
        }
        logger.info("\(reason, privacy: .public): \(self.summary(counts), privacy: .public)")
    }

    /**
     Call without holding the lock: the first format loads ICU, which would stall every hash thread's `fileProcessed()`.
     */
    private func summary(_ counts: (files: Int, errors: Int)) -> String {
        let duration = (self.clock.now - self.start).formatted(.units(allowed: [.hours, .minutes, .seconds, .milliseconds], width: .narrow))
        // Not `.byteCount(style:)`: its formatter adds about 1 ms to every run, and its decimal separator follows the locale.
        let peak = Self.peakFootprint().map { String(format: ", %.1f MB peak memory", Double($0) / 1_000_000) } ?? ""

        return "\(String(counts.files, pluralizing: "file")) with \(String(counts.errors, pluralizing: "error")) in \(duration)\(peak)"
    }

    /**
     The highest physical footprint of the process so far, the "peak memory footprint" of `/usr/bin/time -l`. The kernel
     keeps this high-water mark, so a spike between two reports counts even after its memory is freed.
     */
    static func peakFootprint() -> Int64? {
        var info = rusage_info_v4()
        let status = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: rusage_info_t?.self, capacity: 1) {
                proc_pid_rusage(getpid(), RUSAGE_INFO_V4, $0)
            }
        }
        return status == 0 ? Int64(info.ri_lifetime_max_phys_footprint) : nil
    }
}

// MARK: - SignalTrap

/**
 Signal handling for the duration of a run:
 - `SIGINT` / `SIGTERM` log the end of the run, then the process dies of that signal so the parent sees the usual status;
 - `SIGINFO` reports progress on ⌃T;
 - `SIGPIPE` is held back so a write to a closed pipe fails with `EPIPE` instead of killing the process mid-write;
   the end of the run is then logged before dying of it, by the stdout writer or, for a closed stderr, when the
   signal reaches its source.

 A signal inherited as ignored (a background job in a script, `nohup`) stays ignored, and `restore()` puts back
 the inherited dispositions once the run is over. Dispositions are process-wide, so only the command line installs
 a trap (see `Fashion.scan(trapSignals:)`).
 */
final class SignalTrap: @unchecked Sendable {
    private let reporter: Reporter
    private let lock = NSLock()
    private var active = true
    private var sources: [DispatchSourceSignal] = []
    private var inherited: [(signo: Int32, action: sigaction)] = []
    private var holdsBrokenPipe = false

    init(reporter: Reporter) {
        self.reporter = reporter
        self.watch(SIGINT) { $0.stop("Interrupted", dyingOf: SIGINT) }
        self.watch(SIGTERM) { $0.stop("Terminated", dyingOf: SIGTERM) }
        self.watch(SIGINFO) { $0.reporter.progress() }
        self.holdsBrokenPipe = self.watch(SIGPIPE) { $0.stop("Broken pipe", dyingOf: SIGPIPE) }
    }

    /**
     Die of the `SIGPIPE` held back by the trap, as the process would have without it.
     Returns when `SIGPIPE` was inherited as ignored, or once the run is over.
     */
    func brokenPipe() {
        if self.holdsBrokenPipe {
            self.stop("Broken pipe", dyingOf: SIGPIPE)
        }
    }

    func restore() {
        self.lock.withLock {
            // A signal handled from now on came in as the run finished: let the run complete rather than die after "done".
            self.active = false
            for var entry in self.inherited {
                sigaction(entry.signo, &entry.action, nil)
            }
        }
        for source in self.sources {
            source.cancel()
        }
    }

    /**
     Watch `signo` unless it was inherited as ignored; returns whether it is watched.
     */
    @discardableResult
    private func watch(_ signo: Int32, handler: @escaping @Sendable (SignalTrap) -> Void) -> Bool {
        var action = sigaction()
        sigaction(signo, nil, &action)

        // Compare as addresses: C function pointers are not Equatable.
        if unsafeBitCast(action.__sigaction_u.__sa_handler, to: Int.self) == unsafeBitCast(SIG_IGN, to: Int.self) {
            return false
        }

        let source = DispatchSource.makeSignalSource(signal: signo, queue: .global())
        source.setEventHandler { [weak self] in
            if let self {
                handler(self)
            }
        }

        // Ignore the signal only once the source is registered, which happens asynchronously: until then it keeps its
        // default action rather than being lost. Not once the run is over, when restore() has already put it back.
        source.setRegistrationHandler { [weak self] in
            guard let self else {
                return
            }
            self.lock.withLock {
                if self.active {
                    signal(signo, SIG_IGN)
                }
            }
        }

        self.inherited.append((signo, action))
        self.sources.append(source)
        source.resume()

        return true
    }

    /**
     Log the end of the run and die of `signo`, unless the run is already over.
     */
    private func stop(_ reason: String, dyingOf signo: Int32) {
        // The lock is held until the process dies, so restore() cannot interleave.
        self.lock.withLock {
            guard self.active else {
                return
            }
            self.reporter.end(reason)

            signal(signo, SIG_DFL)
            raise(signo)
        }
    }
}

// MARK: - Handoff

/**
 Hands the walked paths to the hash threads through a short queue: the walker waits for room before adding a path,
 so it stays at most `capacity` paths ahead of hashing, and a hash thread waits for a path, or for the walk to end.

 One condition variable serves both waits: hash threads wait while the queue is empty, the walker while it is full,
 never both at once. Not semaphores: a semaphore has no owner, and Xcode's Thread Performance Checker reports hash
 threads waiting on one as waiting on "a thread without a QoS class", which nobody is; it leaves a condition alone.
 */
final class Handoff: @unchecked Sendable {
    private let condition = NSCondition()
    private let capacity: Int
    private var queue: [(index: Int, path: String)] = []
    private var closed = false

    init(capacity: Int) {
        self.capacity = capacity
    }

    /**
     Wait for room, then queue the path and wake a hash thread.
     */
    func put(index: Int, path: String) {
        self.condition.lock()
        defer {
            self.condition.unlock()
        }
        while self.queue.count == self.capacity {
            self.condition.wait()
        }
        self.queue.append((index, path))
        self.condition.signal()
    }

    /**
     Wait for the next path; nil once the walk is over and the queue is empty.
     */
    func take() -> (index: Int, path: String)? {
        self.condition.lock()
        defer {
            self.condition.unlock()
        }
        while self.queue.isEmpty, !self.closed {
            self.condition.wait()
        }
        guard !self.queue.isEmpty else {
            return nil
        }
        let wasFull = self.queue.count == self.capacity
        let item = self.queue.removeFirst()
        if wasFull {
            // The walker waits for this room, and so may hash threads a signal has not reached yet: wake them all.
            self.condition.broadcast()
        }
        return item
    }

    /**
     End the walk: every hash thread wakes, empties the queue and stops.
     */
    func close() {
        self.condition.lock()
        self.closed = true
        self.condition.broadcast()
        self.condition.unlock()
    }
}

// MARK: - Scan

/**
 The scan: this thread walks the paths and hands each file to `jobs` hash threads, which print through `Output`.
 With `--sort`, the walk sorts each directory as it reads it, so files are handed out in order as they are found.
 */
extension Fashion {
    /**
     Scan the paths and return a process exit code:
     - `0` success,
     - `1` match mode found nothing,
     - `2` one or more paths could not be enumerated or hashed.

     `trapSignals` logs the end of the run on `SIGINT`, `SIGTERM` and `SIGPIPE`, and progress on `SIGINFO`.
     Signal dispositions are process-wide, so only the command line sets it.
     */
    func scan(trapSignals: Bool = false) -> Int32 {
        let jobs = self.resolvedJobs
        let digester = Digester(self)

        let algorithm = digester.algorithm.defaultValueDescription
        logger.info("\(self.sort ? "Run sorted" : "Run", privacy: .public) with \(String(jobs, pluralizing: "job"), privacy: .public) and \(algorithm, privacy: .public) algorithm in \(String(self.paths.count, pluralizing: "path"), privacy: .public): \(self.paths.joined(separator: ", "), privacy: .public)")

        if !digester.targets.isEmpty {
            logger.info("Match mode with \(String(digester.targets.count, pluralizing: "digest"), privacy: .public): \(digester.targets.joined(separator: ", "), privacy: .public)")
        }

        let console = Console()
        let reporter = Reporter(console: console)
        let trap = trapSignals ? SignalTrap(reporter: reporter) : nil
        let output = Output(sorted: self.sort, console: console, reporter: reporter, trap: trap)

        // The walking thread runs at the hash threads' QoS, so it keeps up with them when every core is busy.
        _ = pthread_set_qos_class_self_np(QOS_CLASS_USER_INITIATED, 0)

        // A few dozen paths of lookahead keep every hash thread busy while the walker reads a large directory.
        let handoff = Handoff(capacity: 64)
        let hashing = DispatchGroup()
        for _ in 0 ..< jobs {
            hashing.enter()
            let thread = Thread {
                while let (index, path) = handoff.take() {
                    output.started(index, path: path)
                    let lines = digester.lines(for: path, reporter: reporter)
                    reporter.fileProcessed()
                    output.finished(index, lines: lines)
                }
                hashing.leave()
            }
            thread.qualityOfService = .userInitiated
            thread.start()
        }

        // On a terminal, a scan running for more than half a second shows its status line, redrawn ten times a second.
        let ticks = DispatchQueue(label: "status")
        let ticker = console.isLive ? DispatchSource.makeTimerSource(queue: ticks) : nil
        ticker?.setEventHandler { output.showStatus() }
        ticker?.schedule(deadline: .now() + .milliseconds(500), repeating: .milliseconds(100))
        ticker?.resume()

        let files = FileWalker(paths: self.paths, follow: self.follow, reporter: reporter, sorted: self.sort)
        for (index, path) in files.enumerated() {
            handoff.put(index: index, path: path)
        }
        handoff.close()
        hashing.wait()

        // Let a redraw in flight finish, so the end of the run erases the status line for good.
        ticker?.cancel()
        ticks.sync {}

        reporter.end("Done")
        trap?.restore()

        if reporter.errorCount > 0 {
            return 2
        }
        if !digester.targets.isEmpty, !output.printedAny {
            return 1
        }
        return 0
    }
}

// MARK: - Digester

/**
 The work on one file: its digests in the selected mode and the lines to print for them. Built once per scan from the
 command line, so hash threads read plain values instead of resolving every option for every file.
 */
struct Digester {
    /**
     What a scan digests in each file. Every mode but cdhash streams bytes through a `ByteHash`.
     */
    enum Mode {
        /// The whole file, or its Mach-O image with `--exact`.
        case file(ByteHash)
        /// The whole file, then each architecture of a universal binary.
        case slices(ByteHash)
        /// The external symbol names of each Mach-O slice.
        case symhash(ByteHash, separator: String, sortSymbols: Bool)
        /// The table of contents of a XAR archive.
        case xarToc(ByteHash, decompress: Bool)
        /// The code directory hashes of each Mach-O slice.
        case cdhash
    }

    let algorithm: Algorithm
    let mode: Mode
    let targets: [String]
    let score: Int
    let quiet: Bool
    let exact: Bool
    /// Whether TLSH digests are compared without the file length they record.
    let xlen: Bool

    init(_ command: Fashion) {
        self.algorithm = command.resolvedAlgorithm
        self.targets = command.matchOptions.match
        self.score = command.resolvedScore
        self.quiet = command.quiet
        self.exact = command.exact
        self.xlen = command.matchOptions.xlen

        // `--algo cdhash` is a mode of its own: validate() refuses it with --symhash, --xar-toc or --slices.
        guard let hash = ByteHash(self.algorithm) else {
            self.mode = .cdhash
            return
        }
        self.mode = if command.symbolOptions.symhash {
            .symhash(hash, separator: command.resolvedSeparator, sortSymbols: command.symbolOptions.sortSymbols)
        } else if command.xarOptions.xarToc {
            .xarToc(hash, decompress: command.xarOptions.decompress)
        } else if command.slices {
            .slices(hash)
        } else {
            .file(hash)
        }
    }

    // MARK: - Output Lines

    /**
     The lines to print for one file: every digest or, in match mode, every matching one. A quiet match names the file
     once, and so does a symhash search, which reports files rather than slices (the slices of one binary usually share
     a symhash). A match is green, a fuzzy one by its distance. The file's diagnostics come first: a file that cannot
     be hashed is reported, in red when it is malformed, and prints nothing else.
     */
    func lines(for path: String, reporter: Reporter) -> [Line] {
        var diagnostics: [Line] = []
        let results: [DigestResult]
        do {
            results = try self.digests(path, reporter: reporter) { diagnostics.append($0) }
        } catch {
            return diagnostics + [reporter.report(path: path, message: File.message(for: error), tint: Self.tint(for: error))]
        }

        var lines: [Line] = []
        if self.targets.isEmpty {
            lines = results.map { result in
                Line(text: self.quiet ? result.digest : OutputFormatter.formatLine(digest: result.digest, path: result.display(path), algorithm: self.algorithm), tint: result.tint)
            }
        } else {
            for result in results {
                guard let match = Matching.check(digest: result.digest, against: self.targets, algorithm: self.algorithm, threshold: self.score, xlen: self.xlen) else {
                    continue
                }
                let tint = self.matchTint(match.score)
                if self.quiet {
                    lines = [Line(text: OutputFormatter.formatPath(path), tint: tint)]
                    break
                }
                if case .symhash = self.mode {
                    lines = [Line(text: OutputFormatter.formatLine(digest: result.digest, score: match.score, path: path, algorithm: self.algorithm), tint: tint)]
                    break
                }
                lines.append(Line(text: OutputFormatter.formatLine(digest: result.digest, score: match.score, path: result.display(path), algorithm: self.algorithm), tint: tint))
            }
        }
        return diagnostics + lines
    }

    /**
     A match's green: full for an exact one, whose score is nil, or a fuzzy one by its distance from identical toward
     the `--score` threshold: an ssdeep similarity falls from 100, a TLSH distance rises from 0.

     A TLSH distance has no upper bound, so from 300, where the TLSH paper's false positives pass 79% (Table II), a
     match is gray whatever the threshold, and the greens stop there. Those rates count the length, so with `--xlen` the
     greens run to the threshold.

     An ssdeep match is never gray: the same paper keeps its false positives under 0.1% at any score (Table I).
     */
    func matchTint(_ score: Int?) -> Tint {
        guard let score else {
            return .match(distance: 0)
        }
        if self.algorithm == .ssdeep {
            return .match(distance: Double(100 - score) / Double(max(100 - self.score, 1)))
        }
        if self.xlen {
            return .match(distance: Double(score) / Double(max(self.score, 1)))
        }
        guard score < 300 else {
            return .weak
        }
        return .match(distance: Double(score) / Double(max(min(self.score, 300), 1)))
    }

    /**
     Red for a file whose own bytes are malformed: its Mach-O, signature or XAR does not parse, or goes past a limit only
     a crafted file reaches. Yellow for any other failure: the file could not be read, or changed while it was hashed.
     */
    static func tint(for error: Error) -> Tint {
        error is ParserError || error is CDHashError || error is XARParser.XARError ? .malformed : .error
    }

    // MARK: - Digests

    /**
     The digests of one file in the selected mode; `note` hears each of its diagnostics as it comes.
     */
    private func digests(_ path: String, reporter: Reporter, note: @escaping (Line) -> Void) throws -> [DigestResult] {
        // One descriptor for everything read from the file, whose size when it is opened is the size hashed.
        let file = try File(path: path)
        // What TLSH leaves out of a digest, or why it made none, named after the architecture it is about, unless
        // --quiet keeps the lines alone.
        let caveat = { (arch: String?, message: String) in
            guard !self.quiet else {
                return
            }
            note(reporter.inform(path: arch.map { "\(path) (\($0))" } ?? path, message: message))
        }
        return switch self.mode {
        case let .file(hash):
            try self.fileDigest(file, hash: hash, caveat: { caveat(nil, $0) }).map { [DigestResult(digest: $0)] } ?? []
        case let .slices(hash):
            try self.sliceDigests(file, hash: hash, caveat: caveat)
        case let .symhash(hash, separator, sortSymbols):
            try SymHash.compute(file, algorithm: hash, separator: separator, sortSymbols: sortSymbols, caveat: caveat)
        case let .xarToc(hash, decompress):
            try XARParser.hashToc(file, algorithm: hash, decompress: decompress, caveat: { caveat(nil, $0) }).map { [DigestResult(digest: $0)] } ?? []
        case .cdhash:
            try self.cdHashDigests(file, path: path, reporter: reporter, note: note)
        }
    }

    /**
     One digest per code directory of each slice, `--exact` trimming an unsigned slice to its logical extent before
     synthesizing its ad-hoc cdhash, dimmed. A slice whose signature does not hold is labeled INVALID, and warned about
     once, however many of its directories fail.
     */
    private func cdHashDigests(_ file: File, path: String, reporter: Reporter, note: (Line) -> Void) throws -> [DigestResult] {
        let results = try CDHash.hash(file, path: path, exact: self.exact)
        var warned: Set<String> = []
        for result in results where result.invalid && warned.insert(result.arch ?? "").inserted {
            // Security rejects the signature, so the slice is hashed as unsigned, or its code changed since signing.
            let reason = result.adhoc ? "signature rejected, hashed as unsigned" : "invalid signature (code or signature have been modified)"
            note(reporter.warn(path: result.arch.map { "\(path) (\($0))" } ?? path, message: reason))
        }

        return results.map { result in
            // An unsigned slice is labeled ADHOC; its hash type (sha256 / sha1) is appended to tell the two
            // synthesized cdhashes apart. A signed slice shows its hash type only when ambiguous. A signature that does
            // not hold is labeled INVALID, so the line tells what stderr does.
            let tag: String? = if result.adhoc {
                result.type.map { "ADHOC, \($0)" } ?? "ADHOC"
            } else {
                result.type
            }
            let label = [result.arch, result.invalid ? "INVALID" : nil, tag].compactMap(\.self).joined(separator: ", ")
            return DigestResult(digest: result.hash, label: label.isEmpty ? nil : label, tint: result.adhoc ? .adhoc : .none)
        }
    }

    /**
     The whole-file digest, then one per architecture of a universal binary, each trimmed when `--exact` is set.
     */
    private func sliceDigests(_ file: File, hash: ByteHash, caveat: (_ arch: String?, _ message: String) -> Void) throws -> [DigestResult] {
        // Read the container first, so a malformed one fails before any hashing.
        let slices = try self.sliceRanges(file)

        var results = try self.fileDigest(file, hash: hash, caveat: { caveat(nil, $0) }).map { [DigestResult(digest: $0)] } ?? []
        for slice in slices {
            if let digest = try hash.digest(file, range: slice.range, caveat: { caveat(slice.arch, $0) }) {
                results.append(DigestResult(digest: digest, label: slice.arch))
            }
        }
        return results
    }

    /**
     Where each architecture of a universal binary lies in the file, as Security's `Universal` places a `MachO` at its
     offset; none for any other file. Each slice is validated as a thin Mach-O, so a malformed slice is rejected like a
     malformed thin file, and trimmed to its logical end when `--exact` is set. Only the headers are read.
     */
    private func sliceRanges(_ file: File) throws -> [(range: Range<Int>, arch: String)] {
        guard case let .fat(archs) = try Universal.open(file) else {
            return []
        }

        return try archs.map { arch in
            // Parse even without --exact: a malformed slice is an error either way. A slice that is not Mach-O at
            // all is hashed whole.
            let image = try MachO(file, offset: arch.offset, length: arch.length)
            let length = image.map { self.exact ? $0.logicalEnd() : arch.length } ?? arch.length
            return (arch.offset ..< arch.offset + length, arch.name)
        }
    }

    /**
     The digest of the whole file or, with `--exact`, of a Mach-O's logical content only: `fileEnd` reads just the
     headers.
     */
    private func fileDigest(_ file: File, hash: ByteHash, caveat: (String) -> Void) throws -> String? {
        guard self.exact else {
            return try hash.digest(file, caveat: caveat)
        }
        return try hash.digest(file, range: 0 ..< Universal.fileEnd(file), caveat: caveat)
    }
}
