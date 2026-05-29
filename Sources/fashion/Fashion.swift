import ArgumentParser
import Foundation

extension Algorithm: ExpressibleByArgument {
    var defaultValueDescription: String {
        switch self {
        case .md5: "MD5"
        case .sha1: "SHA-1"
        case .sha256: "SHA-256"
        case .sha384: "SHA-384"
        case .sha512: "SHA-512"
        case .git: "Git blob (SHA-1)"
        case .git256: "Git blob (SHA-256)"
        case .ssdeep: "ssdeep fuzzy hash"
        case .tlsh: "Trend Micro Locality Sensitive Hash"
        case .cdhash: "CodeDirectory hash"
        }
    }
}

// MARK: -

@main
struct Fashion: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "fashion",
        abstract: "Compute and match file digests for threat hunting and binary analysis.",
        version: "1.0.1",
    )

    @Argument(help: "Paths to scan (default: current directory).", completion: .file())
    var paths: [String] = ["."]

    // MARK: - Options

    @Option(name: .shortAndLong, help: "Hash algorithm")
    var algo: Algorithm?

    @Option(name: .shortAndLong, help: "Number of concurrent workers (0 = all CPUs).")
    var jobs: Int = 1

    @Flag(name: [.customShort("L"), .long], help: "Follow symlinks.")
    var follow = false

    @Flag(name: .shortAndLong, help: "Quiet output.")
    var quiet = false

    @Flag(help: "Hash individual Mach-O architectures.")
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
        if let algo = self.algo {
            algo
        } else if self.symbolOptions.symhash {
            .md5
        } else if self.xarOptions.xarToc {
            .sha1
        } else {
            .sha256
        }
    }

    var resolvedJobs: Int {
        if self.jobs == 0 || self.jobs > ProcessInfo.processInfo.activeProcessorCount {
            return ProcessInfo.processInfo.activeProcessorCount
        }
        return max(1, self.jobs)
    }

    var resolvedSeparator: String {
        var sep = self.symbolOptions.separator
        sep = sep.replacingOccurrences(of: "\\n", with: "\n")
        sep = sep.replacingOccurrences(of: "\\0", with: "\0")
        sep = sep.replacingOccurrences(of: "\\t", with: "\t")
        return sep
    }

    var resolvedScore: Int {
        max(0, self.matchOptions.score)
    }

    // MARK: - Run

    mutating func run() async throws {
        let runner = Runner(
            paths: self.paths,
            algorithm: self.resolvedAlgorithm,
            quiet: self.quiet,
            slices: self.slices,
            sortFiles: self.sort,
            jobs: self.resolvedJobs,
            follow: self.follow,
            matchDigests: self.matchOptions.match,
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
    @Flag(help: "Compute SymHash (external symbol hash) for Mach-O files.")
    var symhash = false

    @Option(help: ArgumentHelp("Symbol separator.", valueName: "char"))
    var separator: String = ","

    @Flag(inversion: .prefixedNo, help: "Sort symbols before hashing.")
    var sortSymbols = true
}

struct XAROptions: ParsableArguments {
    @Flag(help: "Hash XAR table of contents.")
    var xarToc = false

    @Flag(help: "Decompress table of contents before hashing.")
    var decompress = false
}
