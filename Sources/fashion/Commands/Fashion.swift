import ArgumentParser
import Foundation

/// What `ScanOptions` refuses, for every subcommand.
private enum ScanOptionError: Error, Equatable {
    case negativeJobs
    case jobsWithAllJobs
    case argumentNotUTF8(Int)
}

extension ScanOptionError: LocalizedError {
    var errorDescription: String? {
        switch self {
        case .negativeJobs:
            "--jobs must be zero or greater."
        case .jobsWithAllJobs:
            "-J and --jobs are mutually exclusive."
        case let .argumentNotUTF8(index):
            "Argument \(index) is not valid UTF-8."
        }
    }
}

extension ValidationError {
    /// A usage error that says what `error` says.
    init(_ error: some LocalizedError) {
        self.init(error.localizedDescription)
    }
}

// MARK: -

/**
 The command line. `fashion` runs the `hash` subcommand unless another is named, so `fashion [options] <paths>` reads as
 it always has; the subcommands share `ScanOptions`, which say what to walk and how.

 The root answers to no help flag of its own, so `fashion --help` falls through to the default subcommand and shows its
 options, as it did before there were subcommands; `fashion help` lists the subcommands.
 */
@main
struct Fashion: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "fashion",
        abstract: "Compute and match file cryptographic or fuzzy hash digests for threat hunting and binary triage.",
        version: "1.5.3",
        subcommands: [
            Hasher.self,
            Thinner.self,
        ],
        defaultSubcommand: Hasher.self,
        helpNames: [],
    )
}

// MARK: - Scan Options

/**
 What every subcommand takes: the paths to walk and how, the workers that take the files, and the order they come out in.
 */
struct ScanOptions: ParsableArguments {
    @Argument(help: "Paths to scan (default: current directory).", completion: .file())
    var paths: [String] = ["."]

    @Option(name: .shortAndLong, help: "Number of concurrent workers (default: 1, 0 = all CPUs).")
    var jobs: Int?

    @Flag(name: .customShort("J"), help: "All CPUs, as --jobs 0.")
    var allJobs = false

    @Flag(name: [.customShort("L"), .long], help: "Follow symlinks.")
    var follow = false

    @Flag(inversion: .prefixedNo, help: "Sort file paths, numbers by value.")
    var sort = false

    var resolvedJobs: Int {
        let processors = ProcessInfo.processInfo.activeProcessorCount
        let jobs = self.allJobs ? 0 : self.jobs ?? 1
        return jobs == 0 ? processors : min(jobs, processors)
    }

    mutating func validate() throws {
        // A negative count only gets past the parser as `--jobs=-7`: `--jobs -7` reads `-7` as an option.
        if let jobs = self.jobs, jobs < 0 {
            throw ValidationError(ScanOptionError.negativeJobs)
        }
        if self.allJobs, self.jobs != nil {
            throw ValidationError(ScanOptionError.jobsWithAllJobs)
        }
        // CommandLine.arguments repairs bytes that are not UTF-8 to U+FFFD, which names another path (a name copied
        // raw from an NFS or FAT volume, say): refuse to hash something else.
        for index in 1 ..< Int(CommandLine.argc) where String(validatingCString: CommandLine.unsafeArgv[index]!) == nil {
            throw ValidationError(ScanOptionError.argumentNotUTF8(index))
        }
    }
}
