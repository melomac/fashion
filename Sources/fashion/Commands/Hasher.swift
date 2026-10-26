import ArgumentParser
import Foundation
import os

private let logger = Logger(subsystem: "fashion", category: "hash")

/// What `Hasher` refuses: a mode, an algorithm or a target that cannot go together.
private enum HashOptionError: Error, Equatable {
    case conflictingModes
    case unsupportedSymHashAlgorithm(Algorithm)
    case unsupportedXarCDHash
    case unsupportedSlicesCDHash
    case exactWithIncompatibleMode
    case unsignWithIncompatibleMode
    case unpackWithXarToc
    case decompressWithoutXarToc
    case negativeScore
    case targetOfNoShape(String)
    case targetNotOfAlgorithm(String, Algorithm)
    case xlenWithoutTLSHTarget
}

extension HashOptionError: LocalizedError {
    var errorDescription: String? {
        switch self {
        case .conflictingModes:
            "--symhash, --xar-toc, and --slices are mutually exclusive."
        case let .unsupportedSymHashAlgorithm(algorithm):
            "--symhash does not support the \(algorithm.rawValue) algorithm."
        case .unsupportedXarCDHash:
            "--xar-toc does not support the cdhash algorithm."
        case .unsupportedSlicesCDHash:
            "--slices does not support the cdhash algorithm; use --algo cdhash on its own."
        case .exactWithIncompatibleMode:
            "--exact does not apply to --symhash or --xar-toc."
        case .unsignWithIncompatibleMode:
            "--unsign does not apply to --symhash or --xar-toc."
        case .unpackWithXarToc:
            "--unpack does not apply to --xar-toc."
        case .decompressWithoutXarToc:
            "--decompress requires --xar-toc."
        case .negativeScore:
            "--score must be zero or greater."
        case let .targetOfNoShape(target):
            "--match '\(target)' is not shaped like MD5, SHA-1, SHA-2, ssdeep or TLSH digests; git, git256 and cdhash take --algo."
        case let .targetNotOfAlgorithm(target, algorithm):
            "--match '\(target)' is not shaped like \(algorithm.rawValue) digests."
        case .xlenWithoutTLSHTarget:
            "--xlen requires a TLSH digest to --match."
        }
    }
}

extension Algorithm: ExpressibleByArgument {
    init?(argument: String) {
        guard let algorithm = Algorithm.parse(argument) else {
            return nil
        }
        self = algorithm
    }

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
        case .cdhash: "CodeDirectory hash (ADHOC for unsigned slices)"
        }
    }
}

/**
 Default mode: the digests of every file walked, or the files that match the targets given.
 */
struct Hasher: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "hash",
        abstract: "Compute and match file cryptographic or fuzzy hash digests for threat hunting and binary triage.",
        usage: "fashion [hash] [<options>] [<paths> ...]",
        discussion: "Other subcommands are listed by 'fashion help'.",
        helpNames: .shortAndLong,
    )

    // MARK: - Options

    @Option(name: .shortAndLong, help: "Hash algorithm")
    var algo: Algorithm?

    @OptionGroup
    var scan: ScanOptions

    @Flag(name: .shortAndLong, help: "Quiet output: digests alone, or matched paths.")
    var quiet = false

    @Flag(help: "Hash individual Mach-O architectures.")
    var slices = false

    @Flag(help: "Hash an exact Mach-O image, dropping appended bytes.")
    var exact = false

    @Flag(help: "Hash a Mach-O image, removing the code signature.")
    var unsign = false

    @Flag(help: "Hash a UPX-packed Mach-O image, unpacked without UPX.")
    var unpack = false

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

    var resolvedSeparator: String {
        var sep = self.symbolOptions.separator
        sep = sep.replacingOccurrences(of: "\\n", with: "\n")
        sep = sep.replacingOccurrences(of: "\\0", with: "\0")
        sep = sep.replacingOccurrences(of: "\\t", with: "\t")
        return sep
    }

    var resolvedScore: Int {
        self.matchOptions.score
    }

    // MARK: - Validation

    mutating func validate() throws {
        // The pipeline routes each item to exactly one of these modes, so combining them silently
        // discards all but the highest-priority one. Reject the ambiguity up front.
        let modeCount = [self.symbolOptions.symhash, self.xarOptions.xarToc, self.slices].count(where: { $0 })
        if modeCount > 1 {
            throw ValidationError(HashOptionError.conflictingModes)
        }

        // Reject algorithms a mode cannot compute; otherwise the mode silently emits nothing.
        if let algo = self.algo {
            if self.symbolOptions.symhash, [.git, .git256, .cdhash].contains(algo) {
                throw ValidationError(HashOptionError.unsupportedSymHashAlgorithm(algo))
            }
            if self.xarOptions.xarToc, algo == .cdhash {
                throw ValidationError(HashOptionError.unsupportedXarCDHash)
            }
            if self.slices, algo == .cdhash {
                throw ValidationError(HashOptionError.unsupportedSlicesCDHash)
            }
        }

        // Flags that are silently ignored outside the mode they belong to.
        if self.exact, self.symbolOptions.symhash || self.xarOptions.xarToc {
            throw ValidationError(HashOptionError.exactWithIncompatibleMode)
        }
        if self.unsign, self.symbolOptions.symhash || self.xarOptions.xarToc {
            throw ValidationError(HashOptionError.unsignWithIncompatibleMode)
        }
        if self.unpack, self.xarOptions.xarToc {
            throw ValidationError(HashOptionError.unpackWithXarToc)
        }
        if self.xarOptions.decompress, !self.xarOptions.xarToc {
            throw ValidationError(HashOptionError.decompressWithoutXarToc)
        }
        // A target is compared with --algo, whose digests it must be shaped like, or without --algo with the algorithm
        // its shape names: one shaped like none would scan everything and match nothing.
        for target in self.matchOptions.match where !Targets.fits(target, self.algo) {
            throw ValidationError(self.algo.map { HashOptionError.targetNotOfAlgorithm(target, $0) } ?? .targetOfNoShape(target))
        }
        if self.matchOptions.xlen, !Targets(self.matchOptions.match, algorithm: self.algo).algorithms.contains(.tlsh) {
            throw ValidationError(HashOptionError.xlenWithoutTLSHTarget)
        }
        if self.matchOptions.score < 0 {
            throw ValidationError(HashOptionError.negativeScore)
        }
    }

    // MARK: - Run

    mutating func run() throws {
        let code = self.scan(trapSignals: true)
        if code != 0 {
            throw ExitCode(code)
        }
    }
}

// MARK: - Scan

extension Hasher {
    /**
     Scan the paths and return a process exit code:
     - `0` success,
     - `1` match mode found nothing,
     - `2` one or more paths could not be enumerated or hashed.

     `trapSignals` logs the end of the run on `SIGINT`, `SIGTERM` and `SIGPIPE`, and progress on `SIGINFO`.
     Signal dispositions are process-wide, so only the command line sets it.
     */
    func scan(trapSignals: Bool = false) -> Int32 {
        let digester = Digester(self)

        let algorithms = digester.algorithms.map(\.defaultValueDescription).joined(separator: ", ")
        logger.info("\(self.scan.sort ? "Run sorted" : "Run", privacy: .public) with \(String(self.scan.resolvedJobs, pluralizing: "job"), privacy: .public) and \(algorithms, privacy: .public) \(digester.algorithms.count == 1 ? "algorithm" : "algorithms", privacy: .public) in \(String(self.scan.paths.count, pluralizing: "path"), privacy: .public): \(self.scan.paths.joined(separator: ", "), privacy: .public)")

        if !digester.targets.isEmpty {
            logger.info("Match mode with \(String(digester.targets.count, pluralizing: "digest"), privacy: .public): \(self.matchOptions.match.joined(separator: ", "), privacy: .public)")
        }

        let run = self.scan.run(trapSignals: trapSignals, activity: "hashing") { digester.lines(for: $0, reporter: $1) }
        if run.errorCount > 0 {
            return 2
        }
        if !digester.targets.isEmpty, !run.printedAny {
            return 1
        }
        return 0
    }
}

// MARK: - Option Groups

struct MatchOptions: ParsableArguments {
    @Option(name: .shortAndLong, help: "Digests to match against.")
    var match: [String] = []

    @Option(name: .shortAndLong, help: "Minimum similarity (ssdeep) or maximum distance (TLSH) threshold.")
    var score: Int = 40

    @Flag(help: "Compare TLSH digests without the file length they record, like the tlsh tool's -xlen.")
    var xlen = false
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
