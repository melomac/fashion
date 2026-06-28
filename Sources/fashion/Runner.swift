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
                // header; crypto algorithms then stream the trimmed extent (no full map, no copy).
                let data = try Data(contentsOf: URL(fileURLWithPath: item.path), options: .mappedIfSafe)
                let end = MachOParser.fileEnd(data: data)
                switch self.algorithm {
                case .md5, .sha1, .sha256, .sha384, .sha512:
                    digest = try CryptoDigest.hash(path: item.path, algorithm: self.algorithm, limit: end)
                default:
                    digest = self.hashData(end < data.count ? data.prefix(end) : data)
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
                    SSDeepBridge.hash(path: item.path)
                case .tlsh:
                    try TLSHBridge.hash(path: item.path)
                case .cdhash:
                    CDHash.hash(path: item.path).first?.hash
                }
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
            for result in sliceResults {
                if Matching.check(digest: result.hash, against: self.matchDigests, algorithm: self.algorithm, threshold: self.score) != nil {
                    return [DigestResult(digest: result.hash, path: item.path, filePath: item.path)]
                }
            }
            return []
        }

        return sliceResults.map { result in
            let suffix = [result.arch, result.type].compactMap(\.self).joined(separator: ", ")
            let displayPath = suffix.isEmpty ? item.path : "\(item.path) (\(suffix))"
            return DigestResult(digest: result.hash, path: displayPath, filePath: item.path)
        }
    }

    private func processSlices(_ item: WorkItem) -> [DigestResult] {
        var results: [DigestResult] = []

        // Whole-file hash first (trimmed to the Mach-O logical end when --exact is set).
        results.append(contentsOf: self.processRegular(item))

        // If fat Mach-O, hash each architecture slice (each trimmed when --exact is set).
        // Skip the map entirely for non-Mach-O input so a large unrelated file is never brought in just to check.
        do {
            if try MachOParser.isMachO(path: item.path) {
                let data = try Data(contentsOf: URL(fileURLWithPath: item.path), options: .mappedIfSafe)
                if case let .fat(archs) = MachOParser.open(data: data) {
                    for arch in archs {
                        let sliceData = MachOParser.sliceData(fileData: data, arch: arch)
                        let archName = MachOParser.archName(cpuType: arch.cpuType, cpuSubtype: arch.cpuSubtype)
                        if let d = self.hashData(self.trimmedIfExact(sliceData)) {
                            results.append(DigestResult(digest: d, path: "\(item.path) (\(archName))", filePath: item.path))
                        }
                    }
                }
            }
        } catch {
            self.logger.info("Error reading slices for \(item.path, privacy: .public): \(error.localizedDescription, privacy: .public)")
        }

        // Quiet match mode: emit the file once on the first matching line (mirrors processCDHash).
        if self.quiet, !self.matchDigests.isEmpty {
            for r in results where Matching.check(digest: r.digest, against: self.matchDigests, algorithm: self.algorithm, threshold: self.score) != nil {
                return [DigestResult(digest: r.digest, path: item.path, filePath: item.path)]
            }
            return []
        }

        return results
    }

    /**
     Trim a Mach-O slice to its logical end when --exact is set; otherwise return it unchanged.
     */
    private func trimmedIfExact(_ slice: Data) -> Data {
        guard self.exact else {
            return slice
        }
        let end = MachOParser.machOEnd(data: slice)
        return end < slice.count ? Data(slice.prefix(end)) : slice
    }

    /**
     Hash raw bytes with the configured algorithm (shared by the regular and slice paths).
     */
    private func hashData(_ data: Data) -> String? {
        do {
            switch self.algorithm {
            case .md5, .sha1, .sha256, .sha384, .sha512:
                return try CryptoDigest.hash(data: data, algorithm: self.algorithm)
            case .git:
                return try GitBlobDigest.hashData(data, useSHA256: false)
            case .git256:
                return try GitBlobDigest.hashData(data, useSHA256: true)
            case .ssdeep:
                return SSDeepBridge.hash(data: data)
            case .tlsh:
                return TLSHBridge.hash(data: data)
            case .cdhash:
                return CDHash.hash(data: data)
            }
        } catch {
            return nil
        }
    }

    private func processSymHash(_ item: WorkItem) -> [DigestResult] {
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
