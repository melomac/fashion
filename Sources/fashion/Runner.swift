import Foundation
import os

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

    func write(_ string: String) {
        do {
            try self.handle.write(contentsOf: Data((string + "\n").utf8))
        } catch {
            // A consumer that went away (EPIPE with SIGPIPE ignored) or a closed stdout: nothing more can be
            // delivered, so stop like coreutils does rather than die on an uncaught Foundation exception.
            let description = OutputFormatter.formatDiagnostic(FileReader.posixError(error).localizedDescription)
            try? FileHandle.standardError.write(contentsOf: Data("fashion: write error: \(description)\n".utf8))
            exit(2)
        }
    }
}

// MARK: - ErrorReporter

/**
 Thread-safe diagnostics sink: writes messages to both stderr (for the user and scripts) and the
 unified log (for a persistent, queryable record), and counts them so the process can exit non-zero
 when any path could not be enumerated or hashed. Lock-based so it is callable from the synchronous
 worker code as well as the async pipeline.
 */
final class ErrorReporter: @unchecked Sendable {
    private let lock = NSLock()
    private let handle = FileHandle.standardError
    private let logger = Logger(subsystem: "fashion", category: "runner")
    private var errorCount = 0

    var count: Int {
        self.lock.withLock { self.errorCount }
    }

    func report(path: String, message: String) {
        self.logger.error("\(path, privacy: .public): \(message, privacy: .public)")
        let displayPath = OutputFormatter.formatPath(path)
        let displayMessage = OutputFormatter.formatDiagnostic(message)
        self.lock.withLock {
            self.errorCount += 1
            // A failing stderr must never abort the scan.
            try? self.handle.write(contentsOf: Data("fashion: \(displayPath): \(displayMessage)\n".utf8))
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

    private let reporter = ErrorReporter()

    /**
     Run the pipeline and return a process exit code:
     - `0` success,
     - `1` match mode found nothing,
     - `2` one or more paths could not be enumerated or hashed.
     */
    func run() async -> Int32 {
        let writer = OutputWriter()

        let matchFound: Bool
        if self.sortFiles {
            let allPaths = FileEnumerator.collectSorted(paths: self.paths, follow: self.follow, reporter: self.reporter)
            matchFound = await self.runSorted(paths: allPaths, writer: writer)
        } else {
            let pathStream = FileEnumerator.walk(paths: self.paths, follow: self.follow, reporter: self.reporter)
            matchFound = await self.runStreaming(pathStream: pathStream, writer: writer)
        }

        if self.reporter.count > 0 {
            return 2
        }
        if !self.matchDigests.isEmpty, !matchFound {
            return 1
        }
        return 0
    }

    // MARK: - Sorted Mode

    private func runSorted(paths: [String], writer: OutputWriter) async -> Bool {
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
                    self.processItem(item)
                }
            }

            // Process results, emit in order, feed more work
            while let batch = await group.next() {
                buffer[batch.index] = batch

                // Feed next item
                if let (index, path) = pending.next() {
                    let item = WorkItem(index: index, path: path)
                    group.addTask {
                        self.processItem(item)
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

    private func runStreaming(pathStream: AsyncStream<String>, writer: OutputWriter) async -> Bool {
        var index = 0
        var matchFound = false

        await withTaskGroup(of: Batch.self) { group in
            var activeCount = 0

            for await path in pathStream {
                let item = WorkItem(index: index, path: path)
                index += 1

                if activeCount < self.jobs {
                    group.addTask {
                        self.processItem(item)
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
                        self.processItem(item)
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

    private func processItem(_ item: WorkItem) -> Batch {
        let results: [DigestResult] = if self.symhash {
            self.processSymHash(item)
        } else if self.xarToc {
            self.processXarToc(item)
        } else if self.algorithm == .cdhash {
            self.processCDHash(item)
        } else if self.slices {
            self.processSlices(item)
        } else {
            self.processRegular(item)
        }

        return Batch(index: item.index, results: results)
    }

    private func processRegular(_ item: WorkItem) -> [DigestResult] {
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
            self.reporter.report(path: item.path, message: error.localizedDescription)
            return []
        }
    }

    private func processCDHash(_ item: WorkItem) -> [DigestResult] {
        // --exact trims an unsigned slice to its logical extent before synthesizing its ad-hoc cdhash.
        let sliceResults: [CDHash.SliceResult]
        do {
            sliceResults = try CDHash.hash(path: item.path, exact: self.exact)
        } catch {
            self.reporter.report(path: item.path, message: error.localizedDescription)
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

    private func processSlices(_ item: WorkItem) -> [DigestResult] {
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
            var results = self.processRegular(item)

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
            self.reporter.report(path: item.path, message: error.localizedDescription)
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

    private func processSymHash(_ item: WorkItem) -> [DigestResult] {
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
            self.reporter.report(path: item.path, message: error.localizedDescription)
            return []
        }
    }

    private func processXarToc(_ item: WorkItem) -> [DigestResult] {
        do {
            if let digest = try XARParser.hashToc(path: item.path, algorithm: algorithm, decompress: decompress) {
                return [DigestResult(digest: digest, path: item.path, filePath: item.path)]
            }
            return []
        } catch {
            self.reporter.report(path: item.path, message: error.localizedDescription)
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
