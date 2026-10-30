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
    case scoreAboveSSDeep
    case targetOfNoShape(String)
    case targetNotOfAlgorithm(String, Algorithm)
    case xlenWithoutTLSHTarget
    case negateWithoutMatch
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
        case .scoreAboveSSDeep:
            "--score above 100 matches no ssdeep digest, whose similarity is 100 at most."
        case let .targetOfNoShape(target):
            "--match '\(target)' is not shaped like MD5, SHA-1, SHA-2, ssdeep or TLSH digests; git, git256 and cdhash take --algo."
        case let .targetNotOfAlgorithm(target, algorithm):
            "--match '\(target)' is not shaped like \(algorithm.rawValue) digests."
        case .xlenWithoutTLSHTarget:
            "--xlen requires a TLSH digest to --match."
        case .negateWithoutMatch:
            "--negate requires --match."
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
        case .md5: "MD5 insecure hash"
        case .sha1: "SHA-1 insecure hash"
        case .sha256: "SHA-256 hash"
        case .sha384: "SHA-384 hash"
        case .sha512: "SHA-512 hash"
        case .git: "Git blob SHA-1 hash"
        case .git256: "Git blob SHA-256 hash"
        case .ssdeep: "Spam Sum Deep fuzzy hash"
        case .tlsh: "Trend Micro Locality Sensitive Hash"
        case .cdhash: "CodeDirectory hash"
        }
    }

    /**
     Complete each algorithm with its own description rather than the option's.

     The generated completion scripts run `fashion ---completion` and read one
     candidate per line: fish takes a description after a tab, zsh after a
     colon, and bash takes the bare value.
     */
    static var defaultCompletionKind: CompletionKind {
        .custom { _, _, _ in
            let separator: String? = switch ProcessInfo.processInfo.environment["SAP_SHELL"] {
            case "fish": "\t"
            case "zsh": ":"
            default: nil
            }
            return allCases.map { algorithm in
                guard let separator else {
                    return algorithm.rawValue
                }
                return algorithm.rawValue + separator + algorithm.defaultValueDescription
            }
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
        aliases: ["h"],
    )

    // MARK: - Options

    @OptionGroup
    var scan: ScanOptions

    @OptionGroup(title: "Hash mode")
    var hash: HasherOptions

    @OptionGroup(title: "Match mode")
    var matchOptions: MatchOptions

    @OptionGroup(title: "Symbol mode")
    var symbolOptions: SymbolOptions

    @OptionGroup(title: "XAR mode")
    var xarOptions: XAROptions

    // MARK: - Resolved Properties

    var resolvedAlgorithm: Algorithm {
        if let algo = self.hash.algo {
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
        let modeCount = [self.symbolOptions.symhash, self.xarOptions.xarToc, self.hash.slices].count(where: { $0 })
        if modeCount > 1 {
            throw ValidationError(HashOptionError.conflictingModes)
        }

        // Reject algorithms a mode cannot compute; otherwise the mode silently emits nothing.
        if let algo = self.hash.algo {
            if self.symbolOptions.symhash, [.git, .git256, .cdhash].contains(algo) {
                throw ValidationError(HashOptionError.unsupportedSymHashAlgorithm(algo))
            }
            if self.xarOptions.xarToc, algo == .cdhash {
                throw ValidationError(HashOptionError.unsupportedXarCDHash)
            }
            if self.hash.slices, algo == .cdhash {
                throw ValidationError(HashOptionError.unsupportedSlicesCDHash)
            }
        }

        // Flags that are silently ignored outside the mode they belong to.
        if self.hash.exact, self.symbolOptions.symhash || self.xarOptions.xarToc {
            throw ValidationError(HashOptionError.exactWithIncompatibleMode)
        }
        if self.hash.unsign, self.symbolOptions.symhash || self.xarOptions.xarToc {
            throw ValidationError(HashOptionError.unsignWithIncompatibleMode)
        }
        if self.hash.unpack, self.xarOptions.xarToc {
            throw ValidationError(HashOptionError.unpackWithXarToc)
        }
        if self.xarOptions.decompress, !self.xarOptions.xarToc {
            throw ValidationError(HashOptionError.decompressWithoutXarToc)
        }
        // A target is compared with --algo, whose digests it must be shaped like, or without --algo with the algorithm
        // its shape names: one shaped like none would scan everything and match nothing.
        for target in self.matchOptions.match where !Targets.fits(target, self.hash.algo) {
            throw ValidationError(self.hash.algo.map { HashOptionError.targetNotOfAlgorithm(target, $0) } ?? .targetOfNoShape(target))
        }
        if self.matchOptions.xlen, !Targets(self.matchOptions.match, algorithm: self.hash.algo).algorithms.contains(.tlsh) {
            throw ValidationError(HashOptionError.xlenWithoutTLSHTarget)
        }
        if self.matchOptions.score < 0 {
            throw ValidationError(HashOptionError.negativeScore)
        }
        if self.matchOptions.score > 100, Targets(self.matchOptions.match, algorithm: self.hash.algo).algorithms.contains(.ssdeep) {
            throw ValidationError(HashOptionError.scoreAboveSSDeep)
        }
        if self.matchOptions.negate, self.matchOptions.match.isEmpty {
            throw ValidationError(HashOptionError.negateWithoutMatch)
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
     - `1` match mode printed nothing: no file matched, or with --negate every file did,
     - `2` one or more paths could not be enumerated or hashed.

     `trapSignals` logs the end of the run on `SIGINT`, `SIGTERM` and `SIGPIPE`, and progress on `SIGINFO`.
     Signal dispositions are process-wide, so only the command line sets it.
     */
    func scan(trapSignals: Bool = false) -> Int32 {
        let digester = Digester(self)

        let algorithms = digester.algorithms.map(\.defaultValueDescription).joined(separator: ", ")
        logger.info("\(self.scan.sort ? "Run sorted" : "Run", privacy: .public)\(self.hash.verify ? " verifying" : "", privacy: .public) with \(String(self.scan.resolvedJobs, pluralizing: "job"), privacy: .public) and \(algorithms, privacy: .public) \(digester.algorithms.count == 1 ? "algorithm" : "algorithms", privacy: .public) in \(String(self.scan.paths.count, pluralizing: "path"), privacy: .public): \(self.scan.paths.joined(separator: ", "), privacy: .public)")

        if !digester.targets.isEmpty {
            logger.info("Match mode\(self.matchOptions.negate ? ", negated," : "", privacy: .public) with \(String(digester.targets.count, pluralizing: "digest"), privacy: .public): \(self.matchOptions.match.joined(separator: ", "), privacy: .public)")
        }

        let verify = self.hash.verify
        let run = self.scan.run(trapSignals: trapSignals, activity: "hashing") { path, reporter in
            let lines = digester.lines(for: path, reporter: reporter)
            if verify {
                Verify.log(path)
            }
            return lines
        }
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

struct HasherOptions: ParsableArguments {
    @Option(name: .shortAndLong, help: "Hash algorithm")
    var algo: Algorithm?

    @Flag(name: .shortAndLong, help: "Quiet mode: digest(s) or matched path(s) only.")
    var quiet = false

    @Flag(help: "Hash individual Mach-O architectures.")
    var slices = false

    @Flag(name: .shortAndLong, help: "Hash an exact Mach-O image, dropping appended bytes.")
    var exact = false

    @Flag(name: [.customShort("i"), .long], help: "Hash a Mach-O image, removing the code signature.")
    var unsign = false

    @Flag(name: [.customShort("p"), .long], help: "Hash a UPX-packed Mach-O image, unpacked without UPX.")
    var unpack = false

    @Flag(name: .shortAndLong, help: "Verify Mach-O files for anomalies")
    var verify = false
}

struct MatchOptions: ParsableArguments {
    @Option(name: .shortAndLong, help: "Digests to match.")
    var match: [String] = []

    @Option(name: .shortAndLong, help: "Minimum similarity (ssdeep) or maximum distance (TLSH) threshold.")
    var score: Int = 40

    @Flag(name: .shortAndLong, help: "Compare TLSH digests without the recorded file length.")
    var xlen = false

    @Flag(name: .shortAndLong, help: "Print only not matched files.")
    var negate = false
}

struct SymbolOptions: ParsableArguments {
    @Flag(name: [.long, .customLong("sym")], help: "Compute SymHash (external symbol hash) for Mach-O slices.")
    var symhash = false

    @Option(name: [.long, .customLong("sep")], help: ArgumentHelp("Symbol separator.", valueName: "char"))
    var separator: String = ","

    @Flag(name: .shortAndLong, inversion: .prefixedNo, help: "Sort symbols before hashing.")
    var order = true
}

struct XAROptions: ParsableArguments {
    @Flag(name: [.long, .customLong("xar")], help: "Hash XAR table of contents.")
    var xarToc = false

    @Flag(name: [.short, .customLong("dec"), .long], help: "Decompress table of contents before hashing.")
    var decompress = false
}
