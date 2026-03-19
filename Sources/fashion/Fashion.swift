import ArgumentParser
import Foundation

@main
struct Fashion: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "fashion",
        abstract: "Compute and match file digests for threat hunting and binary analysis.",
        version: "1.0.0",
    )

    @Argument(help: "Paths to scan (default: current directory).", completion: .file())
    var paths: [String] = ["."]

    // MARK: - Options

    @Option(name: .shortAndLong, help: "Hash algorithm: \(Algorithm.allCases.map(\.rawValue).joined(separator:", ")).", completion: .list(Algorithm.allCases.map(\.rawValue)))
    var algo: String?

    @Option(name: .shortAndLong, help: "Number of concurrent workers (0 = all CPUs).")
    var jobs: Int = 1

    @Flag(name: [.customShort("L"), .long], help: "Follow symlinks.")
    var follow = false

    @Flag(name: .shortAndLong, help: "Quiet output.")
    var quiet = false

    @Flag(help: "Hash individual Mach-O architecture slices.")
    var slices = false

    @Flag(inversion: .prefixedNo, help: "Sort file paths before processing.")
    var sort = false

    // MARK: - Grouped Options

    @OptionGroup(title: "Match mode")
    var matchOptions: MatchOptions

    @OptionGroup(title: "Symbol mode")
    var symbolOptions: SymbolOptions

    @OptionGroup(title: "XAR mode")
    var xarOptions: XAROptions

    // MARK: - Resolved Properties

    var resolvedAlgorithm: Algorithm {
        if let explicit = algo {
            Algorithm.parse(explicit) ?? .sha256
        } else if self.symbolOptions.symhash {
            .md5
        } else if self.xarOptions.xarToc {
            .sha1
        } else {
            .sha256
        }
    }

    var resolvedJobs: Int {
        self.jobs == 0 ? ProcessInfo.processInfo.activeProcessorCount : max(1, self.jobs)
    }

    var resolvedSeparator: String {
        var sep = self.symbolOptions.separator
        sep = sep.replacingOccurrences(of: "\\n", with: "\n")
        sep = sep.replacingOccurrences(of: "\\0", with: "\0")
        sep = sep.replacingOccurrences(of: "\\t", with: "\t")
        return sep
    }

    var resolvedScore: Int {
        if !self.matchOptions.match.isEmpty, self.matchOptions.score == 0, self.resolvedAlgorithm.isFuzzy {
            return 40
        }
        return self.matchOptions.score
    }

    // MARK: - Run

    mutating func run() async throws {
        let runner = Runner(
            paths: paths,
            algorithm: resolvedAlgorithm,
            quiet: quiet,
            slices: slices,
            sortFiles: sort,
            jobs: resolvedJobs,
            follow: follow,
            matchDigests: matchOptions.match,
            score: self.resolvedScore,
            symhash: self.symbolOptions.symhash,
            separator: self.resolvedSeparator,
            sortSymbols: self.symbolOptions.sortSymbols,
            xarToc: self.xarOptions.xarToc,
            decompress: self.xarOptions.decompress,
        )
        try await runner.run()
    }
}

// MARK: - Option Groups

struct MatchOptions: ParsableArguments {
    @Option(name: .shortAndLong, help: "Digests to match against.")
    var match: [String] = []

    @Option(name: .shortAndLong, help: "Minimum similarity (ssdeep) or maximum distance (TLSH) threshold.")
    var score: Int = 40
}

struct SymbolOptions: ParsableArguments {
    @Flag(help: "Compute symhash (external symbol hash) for Mach-O files.")
    var symhash = false

    @Option(help: ArgumentHelp("Symbol separator for symhash.", valueName: "char"))
    var separator: String = ","

    @Flag(inversion: .prefixedNo, help: "Sort symbols before hashing.")
    var sortSymbols = true
}

struct XAROptions: ParsableArguments {
    @Flag(name: .customLong("xar-toc"), help: "Hash XAR table of contents.")
    var xarToc = false

    @Flag(help: "Decompress XAR TOC before hashing.")
    var decompress = false
}
