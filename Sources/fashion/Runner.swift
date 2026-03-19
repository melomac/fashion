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
        guard let data = (string + "\n").data(using: .utf8) else {
            return
        }
        self.handle.write(data)
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

    private let logger = Logger(subsystem: "fashion", category: "runner")

    func run() async throws {
        let writer = OutputWriter()

        if self.sortFiles {
            let allPaths = FileEnumerator.collectSorted(paths: self.paths, follow: self.follow)
            try await self.runSorted(paths: allPaths, writer: writer)
        } else {
            let pathStream = FileEnumerator.walk(paths: self.paths, follow: self.follow)
            try await self.runStreaming(pathStream: pathStream, writer: writer)
        }
    }

    // MARK: - Sorted Mode

    private func runSorted(paths: [String], writer: OutputWriter) async throws {
        guard !paths.isEmpty else {
            return
        }

        try await withThrowingTaskGroup(of: Batch.self) { group in
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
                    try self.processItem(item)
                }
            }

            // Process results, emit in order, feed more work
            while let batch = try await group.next() {
                buffer[batch.index] = batch

                // Feed next item
                if let (index, path) = pending.next() {
                    let item = WorkItem(index: index, path: path)
                    group.addTask {
                        try self.processItem(item)
                    }
                }

                // Flush consecutive completed results from the front
                while let ready = buffer.removeValue(forKey: nextToEmit) {
                    for result in ready.results {
                        if let line = formatResult(result) {
                            await writer.write(line)
                        }
                    }
                    nextToEmit += 1
                }
            }
        }
    }

    // MARK: - Streaming Mode

    private func runStreaming(pathStream: AsyncStream<String>, writer: OutputWriter) async throws {
        var index = 0

        try await withThrowingTaskGroup(of: Batch.self) { group in
            var activeCount = 0

            for await path in pathStream {
                let item = WorkItem(index: index, path: path)
                index += 1

                if activeCount < self.jobs {
                    group.addTask {
                        try self.processItem(item)
                    }
                    activeCount += 1
                } else {
                    // Wait for one to finish before adding more
                    if let batch = try await group.next() {
                        activeCount -= 1
                        for result in batch.results {
                            if let line = formatResult(result) {
                                await writer.write(line)
                            }
                        }
                    }
                    group.addTask {
                        try self.processItem(item)
                    }
                    activeCount += 1
                }
            }

            // Drain remaining
            while let batch = try await group.next() {
                for result in batch.results {
                    if let line = formatResult(result) {
                        await writer.write(line)
                    }
                }
            }
        }
    }

    // MARK: - Processing

    private func processItem(_ item: WorkItem) throws -> Batch {
        let results: [DigestResult] = if self.symhash {
            self.processSymhash(item)
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
            let digest: String? = switch self.algorithm {
            case .md5, .sha1, .sha224, .sha256, .sha384, .sha512:
                try CryptoDigest.hash(path: item.path, algorithm: self.algorithm)
            case .git:
                try GitBlobDigest.hash(path: item.path, useSHA256: false)
            case .git256:
                try GitBlobDigest.hash(path: item.path, useSHA256: true)
            case .ssdeep:
                SSDeepBridge.hash(path: item.path)
            case .tlsh:
                try TLSHBridge.hash(path: item.path)
            case .cdhash:
                CDHash.hash(path: item.path).first?.hash
            }

            guard let d = digest else {
                return []
            }
            return [DigestResult(digest: d, path: item.path, filePath: item.path)]
        } catch {
            self.logger.info("Error processing \(item.path, privacy: .public): \(error.localizedDescription, privacy: .public)")
            return []
        }
    }

    private func processCDHash(_ item: WorkItem) -> [DigestResult] {
        let sliceResults = CDHash.hash(path: item.path)
        guard !sliceResults.isEmpty else { return [] }

        // Quiet match mode: return first matching slice and move on
        if self.quiet, !self.matchDigests.isEmpty {
            for sr in sliceResults {
                if Matching.check(digest: sr.hash, against: self.matchDigests, algorithm: self.algorithm, threshold: self.score) != nil {
                    return [DigestResult(digest: sr.hash, path: item.path, filePath: item.path)]
                }
            }
            return []
        }

        return sliceResults.map { sr in
            let displayPath = sr.arch != nil ? "\(item.path) (\(sr.arch!))" : item.path
            return DigestResult(digest: sr.hash, path: displayPath, filePath: item.path)
        }
    }

    private func processSlices(_ item: WorkItem) -> [DigestResult] {
        var results: [DigestResult] = []

        // Hash the whole file first
        let wholeFile = self.processRegular(item)
        results.append(contentsOf: wholeFile)

        // If fat Mach-O, hash each slice
        do {
            let data = try Data(contentsOf: URL(fileURLWithPath: item.path), options: .mappedIfSafe)
            if case let .fat(archs) = MachOParser.open(data: data) {
                for arch in archs {
                    let sliceData = MachOParser.sliceData(fileData: data, arch: arch)
                    let archName = MachOParser.archName(cpuType: arch.cpuType, cpuSubtype: arch.cpuSubtype)
                    let displayPath = "\(item.path) (\(archName))"

                    let digest: String? = switch self.algorithm {
                    case .md5, .sha1, .sha224, .sha256, .sha384, .sha512:
                        try CryptoDigest.hash(data: sliceData, algorithm: self.algorithm)
                    case .git:
                        try GitBlobDigest.hashData(sliceData, useSHA256: false)
                    case .git256:
                        try GitBlobDigest.hashData(sliceData, useSHA256: true)
                    case .ssdeep:
                        SSDeepBridge.hash(data: sliceData)
                    case .tlsh:
                        TLSHBridge.hash(data: sliceData)
                    case .cdhash:
                        CDHash.hash(data: sliceData)
                    }

                    if let d = digest {
                        results.append(DigestResult(digest: d, path: displayPath, filePath: item.path))
                    }
                }
            }
        } catch {
            self.logger.info("Error reading slices for \(item.path, privacy: .public): \(error.localizedDescription, privacy: .public)")
        }

        return results
    }

    private func processSymhash(_ item: WorkItem) -> [DigestResult] {
        do {
            let results = try SymHash.compute(path: item.path, algorithm: self.algorithm, separator: self.separator, sortSymbols: self.sortSymbols)

            // In match mode, when slices flag is off or when quiet flag is on, emit file path on first matching slice.
            if !self.slices || self.quiet, !self.matchDigests.isEmpty {
                for r in results {
                    if Matching.check(digest: r.digest, against: self.matchDigests, algorithm: self.algorithm, threshold: self.score) != nil {
                        return [DigestResult(digest: r.digest, path: item.path, filePath: item.path)]
                    }
                }
                return []
            }

            return results.map { r in
                let displayPath = r.arch != nil ? "\(item.path) (\(r.arch!))" : item.path
                return DigestResult(digest: r.digest, path: displayPath, filePath: item.path)
            }
        } catch {
            self.logger.info("Error computing symhash for \(item.path, privacy: .public): \(error.localizedDescription, privacy: .public)")
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
            self.logger.info("Error processing XAR \(item.path, privacy: .public): \(error.localizedDescription, privacy: .public)")
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
