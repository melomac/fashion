import CryptoKit
@testable import fashion
import Foundation
import MachO
import XCTest

/**
 A fixture as a file: written to a temporary file, opened and unlinked at once, so the descriptor holds the only
 reference to it.
 */
extension File {
    convenience init(data: Data) throws {
        saveFixture(data)
        let url = FileManager.default.temporaryDirectory / "fashion-fixture-\(UUID())"
        try data.write(to: url)
        defer {
            try? FileManager.default.removeItem(at: url)
        }
        try self.init(path: url.path())
    }
}

/**
 The directory `FASHION_FIXTURES` names, where every fixture the tests open is kept, named by its SHA-256, to seed the
 fuzzer's corpora (`Fuzz/fuzz.sh seed`). Nil, and nothing is kept, unless the environment sets it.
 */
private let fixtureDirectory = ProcessInfo.processInfo.environment["FASHION_FIXTURES"].map { URL(fileURLWithPath: $0) }

/// The largest fixture kept (1 MiB): the fuzzer takes no longer input, and a sparse one of gigabytes would be read whole.
private let maxFixtureSize = 1 << 20

func saveFixture(_ data: Data) {
    guard let fixtureDirectory, data.count <= maxFixtureSize else {
        return
    }
    try? data.write(to: fixtureDirectory / SHA256.hash(data: data).hexString)
}

/// `saveFixture` for a file at `path`: a binary the test compiled or signed, or one of the OS's.
func saveFixture(path: String) {
    guard
        fixtureDirectory != nil,
        let size = try? FileManager.default.attributesOfItem(atPath: path)[.size] as? Int,
        size <= maxFixtureSize,
        let data = try? Data(contentsOf: URL(fileURLWithPath: path))
    else {
        return
    }
    saveFixture(data)
}

/**
 Test conveniences over the parsers: open a fixture or a path, and best-effort views of a fixture that read as far
 as a damaged load-command table parses instead of throwing (production only uses the throwing initializer).
 */
extension Universal {
    static func open(path: String) throws -> Universal {
        saveFixture(path: path)
        return try self.open(File(path: path))
    }

    static func open(data: Data) throws -> Universal {
        try self.open(File(data: data))
    }

    /// Whether `open` reads the file as a Mach-O, thin or universal.
    static func isMachO(path: String) throws -> Bool {
        saveFixture(path: path)
        return try self.isMachO(File(path: path))
    }

    static func isMachO(data: Data) throws -> Bool {
        try self.isMachO(File(data: data))
    }

    private static func isMachO(_ file: File) throws -> Bool {
        if case .notMachO = try self.open(file) {
            return false
        }
        return true
    }

    /// One architecture of a universal fixture, copied out as if extracted.
    static func sliceData(fileData: Data, arch: Architecture) -> Data {
        Data(fileData.bytes(in: arch.offset ..< arch.offset + arch.length))
    }

    static func fileEnd(data: Data) throws -> Int {
        try self.fileEnd(File(data: data))
    }
}

extension MachO {
    /// A fixture read as a thin file.
    init?(_ data: Data) throws {
        try self.init(File(data: data))
    }

    static func loadCommands(data: Data) -> [LoadCommand] {
        (try? MachO(lenient: File(data: data)))?.loadCommands ?? []
    }

    static func logicalEnd(data: Data) -> Int {
        (try? MachO(lenient: File(data: data)))?.logicalEnd() ?? data.count
    }
}

extension SymHash {
    /// The external symbol names of raw tables, `symtab` counting from the start of `data`.
    static func externalSymbolNames(data: Data, symtab: symtab_command, is64: Bool, swap: Bool) throws -> [Data] {
        try self.externalSymbolNames(file: File(data: data), offset: 0, length: data.count, symtab: symtab, is64: is64, swap: swap)
    }
}

extension CDHash {
    static func hash(path: String, exact: Bool = false) throws -> [SliceResult] {
        saveFixture(path: path)
        return try self.hash(File(path: path), path: path, exact: exact)
    }

    /// Every slice's cdhashes, as `hash(path:)` reports a file's; the name only appears in the log.
    static func hash(fixture: Data) throws -> [SliceResult] {
        try self.hash(File(data: fixture), path: "fixture")
    }

    /// The strongest cdhash of a thin fixture, embedded or ad-hoc; nil for anything else.
    static func hash(data: Data, exact: Bool = false) throws -> String? {
        try MachO(data)?.codeDirectoryHashes(exact: exact).hashes.first?.hash
    }
}

/**
 Byte builders for synthetic Mach-O fixtures: native-endian for thin headers and load commands,
 big-endian for fat headers and embedded code signatures.
 */
extension Data {
    mutating func appendUInt32(_ value: UInt32) {
        self.appendRaw(value)
    }

    mutating func appendInt32(_ value: Int32) {
        self.appendRaw(value)
    }

    mutating func appendUInt64(_ value: UInt64) {
        self.appendRaw(value)
    }

    mutating func appendUInt32BE(_ value: UInt32) {
        self.appendRaw(value.bigEndian)
    }

    mutating func appendInt32BE(_ value: Int32) {
        self.appendRaw(value.bigEndian)
    }

    mutating func appendUInt64BE(_ value: UInt64) {
        self.appendRaw(value.bigEndian)
    }

    private mutating func appendRaw(_ value: some FixedWidthInteger) {
        Swift.withUnsafeBytes(of: value) { self.append(contentsOf: $0) }
    }
}

/**
 The `fashion` executable built next to the test bundle; skips the calling test when it is missing.
 */
func fashionExecutable() throws -> URL {
    let binary = Bundle(for: BundleMarker.self).bundleURL.deletingLastPathComponent() / "fashion"
    try XCTSkipUnless(FileManager.default.isExecutableFile(atPath: binary.path), "fashion binary unavailable")
    return binary
}

private final class BundleMarker {}

/**
 The environment of a `fashion` child. Xcode's test runner sets `OS_ACTIVITY_DT_MODE`, which copies the child's `os_log`
 lines to its stderr: into what a test reads there, or into a pipe nobody reads, where logging the end of the run on
 SIGTERM would block.
 */
let fashionEnvironment = ProcessInfo.processInfo.environment.filter { $0.key != "OS_ACTIVITY_DT_MODE" }

/**
 Run the built `fashion` on `arguments`, its output discarded: the exit status and the lines it wrote to stderr. Through
 `sh`, which runs `script` with `$0` the binary and `$1`… the arguments, it can be handed bytes a Swift string cannot
 hold.
 */
func runFashion(_ arguments: [String], sh script: String? = nil) throws -> (status: Int32, errors: [String]) {
    let process = Process()
    if let script {
        process.executableURL = URL(fileURLWithPath: "/bin/sh")
        process.arguments = try ["-c", script, fashionExecutable().path] + arguments
    } else {
        process.executableURL = try fashionExecutable()
        process.arguments = arguments
    }
    process.environment = fashionEnvironment
    process.standardOutput = FileHandle.nullDevice
    let stderr = Pipe()
    process.standardError = stderr
    try process.run()
    let output = stderr.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    return (process.terminationStatus, String(decoding: output, as: UTF8.self).split(separator: "\n").map(String.init))
}

/**
 `paths` in the natural order `--sort` lists files in, written apart from `fashion_fts_compare`: each path is cut into
 runs of ASCII digits and single other bytes, and two paths compare at the first run they differ in, two numbers by
 value, then the one with more leading zeros first, and anything else by its first byte.
 */
func naturallySorted(_ paths: [String]) -> [String] {
    func isDigit(_ byte: UInt8) -> Bool {
        (UInt8(ascii: "0") ... UInt8(ascii: "9")).contains(byte)
    }

    func runs(_ path: String) -> [[UInt8]] {
        var runs: [[UInt8]] = []
        for byte in path.utf8 {
            if isDigit(byte), let last = runs.last?.last, isDigit(last) {
                runs[runs.count - 1].append(byte)
            } else {
                runs.append([byte])
            }
        }
        return runs
    }

    func precedes(_ lhs: [[UInt8]], _ rhs: [[UInt8]]) -> Bool {
        for (left, right) in zip(lhs, rhs) where left != right {
            guard isDigit(left[0]), isDigit(right[0]) else {
                return left[0] < right[0]
            }
            let leftDigits = left.drop { $0 == UInt8(ascii: "0") }
            let rightDigits = right.drop { $0 == UInt8(ascii: "0") }
            if leftDigits.count != rightDigits.count {
                return leftDigits.count < rightDigits.count
            }
            if leftDigits != rightDigits {
                return leftDigits.lexicographicallyPrecedes(rightDigits)
            }
            return left.count > right.count
        }
        return lhs.count < rhs.count
    }

    return paths.map { ($0, runs($0)) }.sorted { precedes($0.1, $1.1) }.map(\.0)
}

extension URL {
    /**
     Appends a path component using the `/` operator. Test convenience.
     */
    static func / (url: URL, component: String) -> URL {
        url.appending(path: component)
    }
}

/**
 A codesign invocation that exited non-zero; the description carries its output so the failure explains itself.
 */
struct CodesignFailure: Error, CustomStringConvertible {
    let arguments: [String]
    let status: Int32
    let output: String

    var description: String {
        "codesign \(self.arguments.joined(separator: " ")) exited \(self.status): \(self.output)"
    }
}

/**
 Run `/usr/bin/codesign` and return its combined stdout+stderr (codesign `-d` prints to stderr).

 Skips the calling test when codesign is unavailable, and throws `CodesignFailure` when it exits non-zero, so a
 failed signing or inspection reports codesign's own message rather than a downstream symptom.
 */
func codesign(_ arguments: [String]) throws -> String {
    let path = "/usr/bin/codesign"
    try XCTSkipUnless(FileManager.default.isExecutableFile(atPath: path), "codesign unavailable")

    let pipe = Pipe()
    let process = Process()
    process.executableURL = URL(fileURLWithPath: path)
    process.arguments = arguments
    process.standardOutput = pipe
    process.standardError = pipe

    try process.run()
    process.waitUntilExit()

    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    let output = String(decoding: data, as: UTF8.self)

    guard process.terminationStatus == 0 else {
        throw CodesignFailure(arguments: arguments, status: process.terminationStatus, output: output)
    }
    return output
}

/**
 The architecture names codesign reports for a signed `path`, spelled as `codesign --arch` expects them: the list
 in `Format=Mach-O universal (x86_64 arm64e arm64e.x1)`, or the single name of a thin binary.

 codesign ships with the OS, so unlike Xcode's `lipo` — which may predate the OS and print `unknown(16777228,12)` —
 it names every slice the OS does.

 Nil when the output carries no parseable Format line.
 */
func codesignArchs(_ path: String) throws -> Set<String>? {
    for line in try codesign(["-dv", path]).split(separator: "\n") where line.hasPrefix("Format=") {
        // The list is the outermost parenthesis: a slice codesign cannot name appears inside it as `(cputype:subtype)`.
        guard
            let open = line.firstIndex(of: "("),
            let close = line.lastIndex(of: ")"),
            open < close
        else {
            return nil
        }
        return Set(line[line.index(after: open) ..< close].split(separator: " ").map(String.init))
    }
    return nil
}
