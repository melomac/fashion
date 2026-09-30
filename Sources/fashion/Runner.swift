import Foundation
import os
import System

private let logger = Logger(subsystem: "fashion", category: "runner")

// MARK: Pipeline Types

struct WorkItem {
    let index: Int
    let path: String
}

struct DigestResult {
    let digest: String
    let path: String
    let filePath: String?
}

struct Batch {
    let index: Int
    let results: [DigestResult]
}

// MARK: - OutputWriter

/**
 Thread-safe stdout writer.
 */
actor OutputWriter {
    private let handle = FileHandle.standardOutput
    private let reporter: Reporter
    private let trap: SignalTrap?

    init(reporter: Reporter, trap: SignalTrap?) {
        self.reporter = reporter
        self.trap = trap
    }

    func write(_ string: String) {
        do {
            try self.handle.write(contentsOf: Data((string + "\n").utf8))
        } catch {
            let error = FileReader.posixError(error)
            if error as? Errno == .brokenPipe {
                // The reader went away (`| head`): if the trap holds SIGPIPE, this logs the end and dies of it
                // silently, as the process would have without the trap.
                self.trap?.brokenPipe()
            }

            // Otherwise nothing more can be delivered (SIGPIPE inherited as ignored, or stdout closed): report
            // and exit like coreutils, rather than crash on the uncaught error.
            let description = OutputFormatter.formatDiagnostic(error.localizedDescription)
            self.reporter.end("stopped by write error: \(description)")
            try? FileHandle.standardError.write(contentsOf: Data("fashion: write error: \(description)\n".utf8))

            exit(2)
        }
    }
}

// MARK: - Reporter

/**
 Thread-safe bookkeeping for one run, callable from the synchronous worker code as well as the async pipeline:
 - diagnostics go to both stderr (for the user and scripts) and the unified log (for a persistent, queryable record),
   and are counted so the process can exit non-zero when any path could not be enumerated or hashed;
 - files are counted as workers finish them, for the progress report on SIGINFO and the end of the run,
   which is logged exactly once whether the run completes or is interrupted.
 */
final class Reporter: @unchecked Sendable {
    private let lock = NSLock()
    private let handle = FileHandle.standardError
    private let clock = ContinuousClock()
    private let start: ContinuousClock.Instant
    private var fileCount = 0
    private var errors = 0
    private var ended = false

    init() {
        self.start = self.clock.now
    }

    var errorCount: Int {
        self.lock.withLock { self.errors }
    }

    func report(path: String, message: String) {
        logger.error("\(path, privacy: .public): \(message, privacy: .public)")

        let displayPath = OutputFormatter.formatPath(path)
        let displayMessage = OutputFormatter.formatDiagnostic(message)
        self.lock.withLock {
            self.errors += 1
            self.write("fashion: \(displayPath): \(displayMessage)")
        }
    }

    func fileProcessed() {
        self.lock.withLock { self.fileCount += 1 }
    }

    /**
     Report the counts and elapsed time so far to the log and to stderr, like `dd` on `SIGINFO` (⌃T).
     */
    func progress() {
        let summary = self.summary(self.lock.withLock { (self.fileCount, self.errors) })
        logger.info("progress: \(summary, privacy: .public)")

        self.lock.withLock {
            self.write("fashion: \(summary)")
        }
    }

    /**
     Log the counts and elapsed time; calls after the first are ignored.
     */
    func end(_ reason: String) {
        let counts: (files: Int, errors: Int)? = self.lock.withLock {
            guard !self.ended else {
                return nil
            }
            self.ended = true
            return (self.fileCount, self.errors)
        }
        guard let counts else {
            return
        }
        logger.info("\(reason, privacy: .public): \(self.summary(counts), privacy: .public)")
    }

    /**
     Call without holding the lock: the first format loads ICU, which would stall every worker's `fileProcessed()`.
     */
    private func summary(_ counts: (files: Int, errors: Int)) -> String {
        let duration = (self.clock.now - self.start).formatted(.units(allowed: [.hours, .minutes, .seconds, .milliseconds], width: .narrow))

        return "\(counts.files) file(s) with \(counts.errors) error(s) in \(duration)"
    }

    /**
     Caller holds the lock, so lines from concurrent workers never interleave.
     */
    private func write(_ line: String) {
        // A write error must not abort the scan; a closed stderr pipe still ends it through the trapped SIGPIPE.
        try? self.handle.write(contentsOf: Data((line + "\n").utf8))
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
 a trap (see `Runner.trapSignals`).
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
        self.watch(SIGINT) { $0.stop("interrupted", dyingOf: SIGINT) }
        self.watch(SIGTERM) { $0.stop("terminated", dyingOf: SIGTERM) }
        self.watch(SIGINFO) { $0.reporter.progress() }
        self.holdsBrokenPipe = self.watch(SIGPIPE) { $0.stop("broken pipe", dyingOf: SIGPIPE) }
    }

    /**
     Die of the `SIGPIPE` held back by the trap, as the process would have without it.
     Returns when `SIGPIPE` was inherited as ignored, or once the run is over.
     */
    func brokenPipe() {
        if self.holdsBrokenPipe {
            self.stop("broken pipe", dyingOf: SIGPIPE)
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

        // Ignore the signal only once the source is registered: one arriving in between would otherwise be lost.
        let registered = DispatchSemaphore(value: 0)
        source.setRegistrationHandler {
            registered.signal()
        }

        source.resume()
        registered.wait()
        signal(signo, SIG_IGN)

        self.inherited.append((signo, action))
        self.sources.append(source)

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

// MARK: - Runner

/**
 Concurrent processing pipeline: enumerator → worker pool → printer.
 */
struct Runner {
    let paths: [String]
    let algorithm: Algorithm
    let quiet: Bool
    let slices: Bool
    let exact: Bool
    let sortFiles: Bool
    let jobs: Int
    let follow: Bool
    let matchDigests: [String]
    let score: Int
    let symhash: Bool
    let separator: String
    let sortSymbols: Bool
    let xarToc: Bool
    let decompress: Bool
    /// Log the end of the run on `SIGINT`, `SIGTERM` and `SIGPIPE`, and progress on `SIGINFO`.
    /// Signal dispositions are process-wide, so only the command line sets this.
    var trapSignals = false

    /**
     Run the pipeline and return a process exit code:
     - `0` success,
     - `1` match mode found nothing,
     - `2` one or more paths could not be enumerated or hashed.
     */
    func run() async -> Int32 {
        logger.info("run with \(self.jobs, privacy: .public) job(s) and \(self.algorithm.rawValue, privacy: .public) algorithm in path(s): \(self.paths.joined(separator: ", "), privacy: .public)")
        if !self.matchDigests.isEmpty {
            logger.info("match digest(s): \(self.matchDigests.joined(separator: ", "), privacy: .public)")
        }
        let reporter = Reporter()
        let trap = self.trapSignals ? SignalTrap(reporter: reporter) : nil
        let writer = OutputWriter(reporter: reporter, trap: trap)

        let matchFound: Bool
        if self.sortFiles {
            let allPaths = FileEnumerator.collectSorted(paths: self.paths, follow: self.follow, reporter: reporter)
            matchFound = await self.runSorted(paths: allPaths, reporter: reporter, writer: writer)
        } else {
            let pathStream = FileEnumerator.walk(paths: self.paths, follow: self.follow, reporter: reporter)
            matchFound = await self.runStreaming(pathStream: pathStream, reporter: reporter, writer: writer)
        }

        reporter.end("done")
        trap?.restore()

        if reporter.errorCount > 0 {
            return 2
        }
        if !self.matchDigests.isEmpty, !matchFound {
            return 1
        }
        return 0
    }

    // MARK: - Sorted Mode

    private func runSorted(paths: [String], reporter: Reporter, writer: OutputWriter) async -> Bool {
        guard !paths.isEmpty else {
            return false
        }

        var matchFound = false
        await withTaskGroup(of: Batch.self) { group in
            var pending = paths.enumerated().makeIterator()
            var buffer: [Int: Batch] = [:]
            var nextToEmit = 0

            // Seed initial tasks
            for _ in 0 ..< self.jobs {
                guard let (index, path) = pending.next() else {
                    break
                }
                let item = WorkItem(index: index, path: path)
                group.addTask {
                    self.processItem(item, reporter: reporter)
                }
            }

            // Process results, emit in order, feed more work
            while let batch = await group.next() {
                buffer[batch.index] = batch

                // Feed next item
                if let (index, path) = pending.next() {
                    let item = WorkItem(index: index, path: path)
                    group.addTask {
                        self.processItem(item, reporter: reporter)
                    }
                }

                // Flush consecutive completed results from the front
                while let ready = buffer.removeValue(forKey: nextToEmit) {
                    for result in ready.results {
                        if let line = formatResult(result) {
                            matchFound = true
                            await writer.write(line)
                        }
                    }
                    nextToEmit += 1
                }
            }
        }
        return matchFound
    }

    // MARK: - Streaming Mode

    private func runStreaming(pathStream: AsyncStream<String>, reporter: Reporter, writer: OutputWriter) async -> Bool {
        var index = 0
        var matchFound = false

        await withTaskGroup(of: Batch.self) { group in
            var activeCount = 0

            for await path in pathStream {
                let item = WorkItem(index: index, path: path)
                index += 1

                if activeCount < self.jobs {
                    group.addTask {
                        self.processItem(item, reporter: reporter)
                    }
                    activeCount += 1
                } else {
                    // Wait for one to finish before adding more
                    if let batch = await group.next() {
                        activeCount -= 1
                        for result in batch.results {
                            if let line = formatResult(result) {
                                matchFound = true
                                await writer.write(line)
                            }
                        }
                    }
                    group.addTask {
                        self.processItem(item, reporter: reporter)
                    }
                    activeCount += 1
                }
            }

            // Drain remaining
            while let batch = await group.next() {
                for result in batch.results {
                    if let line = formatResult(result) {
                        matchFound = true
                        await writer.write(line)
                    }
                }
            }
        }
        return matchFound
    }

    // MARK: - Processing

    private func processItem(_ item: WorkItem, reporter: Reporter) -> Batch {
        let results: [DigestResult] = if self.symhash {
            self.processSymHash(item, reporter: reporter)
        } else if self.xarToc {
            self.processXarToc(item, reporter: reporter)
        } else if self.algorithm == .cdhash {
            self.processCDHash(item, reporter: reporter)
        } else if self.slices {
            self.processSlices(item, reporter: reporter)
        } else {
            self.processRegular(item, reporter: reporter)
        }

        reporter.fileProcessed()
        return Batch(index: item.index, results: results)
    }

    private func processRegular(_ item: WorkItem, reporter: Reporter) -> [DigestResult] {
        do {
            let digest: String?
            let trimMachO = self.exact ? try MachOParser.isMachO(path: item.path) : false
            if trimMachO {
                // Mach-O: hash only the logical content. The map is lazy, so fileEnd faults just the
                // header; crypto and git algorithms then stream the trimmed extent (no full map, no copy),
                // failing closed if the file shrank in between.
                let data = try FileReader.map(path: item.path)
                let end = try MachOParser.fileEnd(data: data)
                switch self.algorithm {
                case .md5, .sha1, .sha256, .sha384, .sha512:
                    digest = try CryptoDigest.hash(path: item.path, algorithm: self.algorithm, limit: end, exactLength: end)
                case .git, .git256:
                    digest = try GitBlobDigest.hash(path: item.path, useSHA256: self.algorithm == .git256, limit: end)
                default:
                    digest = try self.hashData(end < data.count ? data.prefix(end) : data)
                }
            } else {
                digest = switch self.algorithm {
                case .md5, .sha1, .sha256, .sha384, .sha512:
                    try CryptoDigest.hash(path: item.path, algorithm: self.algorithm)
                case .git:
                    try GitBlobDigest.hash(path: item.path, useSHA256: false)
                case .git256:
                    try GitBlobDigest.hash(path: item.path, useSHA256: true)
                case .ssdeep:
                    try SSDeepBridge.hash(path: item.path)
                case .tlsh:
                    try TLSHBridge.hash(path: item.path)
                case .cdhash:
                    try CDHash.hash(path: item.path).first?.hash
                }
            }

            guard let digest else {
                return []
            }
            return [DigestResult(digest: digest, path: item.path, filePath: item.path)]
        } catch {
            reporter.report(path: item.path, message: error.localizedDescription)
            return []
        }
    }

    private func processCDHash(_ item: WorkItem, reporter: Reporter) -> [DigestResult] {
        // --exact trims an unsigned slice to its logical extent before synthesizing its ad-hoc cdhash.
        let sliceResults: [CDHash.SliceResult]
        do {
            sliceResults = try CDHash.hash(path: item.path, exact: self.exact)
        } catch {
            reporter.report(path: item.path, message: error.localizedDescription)
            return []
        }

        let results = sliceResults.map { result in
            // An unsigned slice is labeled ADHOC; its hash type (sha256 / sha1) is appended to tell the two
            // synthesized cdhashes apart. A signed slice shows its hash type only when ambiguous.
            let tag: String? = if result.adhoc {
                result.type.map { "ADHOC, \($0)" } ?? "ADHOC"
            } else {
                result.type
            }
            let suffix = [result.arch, tag].compactMap(\.self).joined(separator: ", ")
            let displayPath = suffix.isEmpty ? item.path : "\(item.path) (\(suffix))"
            return DigestResult(digest: result.hash, path: displayPath, filePath: item.path)
        }

        if self.quiet, !self.matchDigests.isEmpty {
            return self.firstMatch(in: results, for: item)
        }
        return results
    }

    /**
     The first result whose digest matches, reduced to the bare file path, or nothing.
     A quiet match listing names each file once, whichever of its slices matched.
     */
    private func firstMatch(in results: [DigestResult], for item: WorkItem) -> [DigestResult] {
        for result in results where Matching.check(digest: result.digest, against: self.matchDigests, algorithm: self.algorithm, threshold: self.score) != nil {
            return [DigestResult(digest: result.digest, path: item.path, filePath: item.path)]
        }
        return []
    }

    private func processSlices(_ item: WorkItem, reporter: Reporter) -> [DigestResult] {
        do {
            // Read the container before hashing anything, so a malformed one yields an error, not a partial listing.
            var fatBinary: (data: Data, archs: [MachOParser.FatArch])?
            if try MachOParser.isMachO(path: item.path) {
                let data = try FileReader.map(path: item.path)
                if case let .fat(archs) = try MachOParser.open(data: data) {
                    fatBinary = (data, archs)
                }
            }

            // Whole-file hash first (trimmed to the Mach-O logical end when --exact is set).
            var results = self.processRegular(item, reporter: reporter)

            // If fat Mach-O, hash each architecture slice (each trimmed when --exact is set).
            if let fatBinary {
                for arch in fatBinary.archs {
                    let sliceData = MachOParser.sliceData(fileData: fatBinary.data, arch: arch)
                    let archName = MachOParser.archName(cpuType: arch.cpuType, cpuSubtype: arch.cpuSubtype)
                    if let digest = try self.hashData(self.validatedSlice(sliceData)) {
                        results.append(DigestResult(digest: digest, path: "\(item.path) (\(archName))", filePath: item.path))
                    }
                }
            }

            if self.quiet, !self.matchDigests.isEmpty {
                return self.firstMatch(in: results, for: item)
            }
            return results
        } catch {
            reporter.report(path: item.path, message: error.localizedDescription)
            return []
        }
    }

    /**
     Validate a fat slice as a thin Mach-O, so a malformed slice is rejected like a malformed thin file,
     and trim it to its logical end when --exact is set. A slice that is not Mach-O at all is returned unchanged.
     */
    private func validatedSlice(_ slice: Data) throws -> Data {
        guard let machO = try MachOSlice(slice), self.exact else {
            return slice
        }
        return slice.prefix(machO.logicalEnd())
    }

    /**
     Hash raw bytes with the configured algorithm (shared by the regular and slice paths).
     */
    private func hashData(_ data: Data) throws -> String? {
        switch self.algorithm {
        case .md5, .sha1, .sha256, .sha384, .sha512:
            try CryptoDigest.hash(data: data, algorithm: self.algorithm)
        case .git:
            try GitBlobDigest.hashData(data, useSHA256: false)
        case .git256:
            try GitBlobDigest.hashData(data, useSHA256: true)
        case .ssdeep:
            SSDeepBridge.hash(data: data)
        case .tlsh:
            TLSHBridge.hash(data: data)
        case .cdhash:
            try CDHash.hash(data: data)
        }
    }

    private func processSymHash(_ item: WorkItem, reporter: Reporter) -> [DigestResult] {
        do {
            let results = try SymHash.compute(path: item.path, algorithm: self.algorithm, separator: self.separator, sortSymbols: self.sortSymbols)

            let labelled = results.map { result in
                let displayPath = result.arch.map { "\(item.path) (\($0))" } ?? item.path
                return DigestResult(digest: result.digest, path: displayPath, filePath: item.path)
            }

            // Match mode: a symhash search reports files, not slices, so name the file once on its first
            // matching slice (the slices of one binary usually share a symhash).
            if !self.matchDigests.isEmpty {
                return self.firstMatch(in: labelled, for: item)
            }
            return labelled
        } catch {
            reporter.report(path: item.path, message: error.localizedDescription)
            return []
        }
    }

    private func processXarToc(_ item: WorkItem, reporter: Reporter) -> [DigestResult] {
        do {
            if let digest = try XARParser.hashToc(path: item.path, algorithm: algorithm, decompress: decompress) {
                return [DigestResult(digest: digest, path: item.path, filePath: item.path)]
            }
            return []
        } catch {
            reporter.report(path: item.path, message: error.localizedDescription)
            return []
        }
    }

    // MARK: - Formatting

    private func formatResult(_ result: DigestResult) -> String? {
        if !self.matchDigests.isEmpty {
            guard let matchResult = Matching.check(digest: result.digest, against: matchDigests, algorithm: algorithm, threshold: score) else {
                return nil
            }

            if self.quiet {
                return OutputFormatter.formatQuietMatch(path: result.filePath ?? result.path)
            }

            if let score = matchResult.score {
                return OutputFormatter.formatMatchLine(digest: result.digest, score: score, path: result.path, algorithm: self.algorithm)
            }

            return OutputFormatter.formatLine(digest: result.digest, path: result.path, algorithm: self.algorithm)
        }

        if self.quiet {
            return OutputFormatter.formatQuiet(digest: result.digest, algorithm: self.algorithm)
        }

        return OutputFormatter.formatLine(digest: result.digest, path: result.path, algorithm: self.algorithm)
    }
}
