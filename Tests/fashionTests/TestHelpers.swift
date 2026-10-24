import CryptoKit
@testable import fashion
import Foundation
import MachO
import XCTest
import zlib

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

extension SymHash {
    /// The symhashes by one algorithm, as the tests ask for them.
    static func compute(_ file: File, algorithm: ByteHash, separator: String, sortSymbols: Bool) throws -> [DigestResult] {
        try self.compute(file, algorithms: [algorithm], separator: separator, sortSymbols: sortSymbols)
    }
}

extension XARParser {
    /// The table of contents' digest by one algorithm, as the tests ask for it; nil for a file that is not a XAR archive.
    static func hashToc(_ file: File, algorithm: ByteHash, decompress: Bool) throws -> String? {
        try self.hashToc(file, algorithms: [algorithm], decompress: decompress).first?.digest
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
 A XAR archive holding `toc` as its table of contents, declared `size` bytes uncompressed, then `trailer`.
 */
func xarArchive(toc: Data, size: Int, trailer: Data = Data()) -> Data {
    var data = Data("xar!".utf8)
    data.append(contentsOf: [0x00, 0x1c, 0x00, 0x01]) // header size 28, version 1
    data.appendUInt64BE(UInt64(toc.count))
    data.appendUInt64BE(UInt64(size))
    data.appendUInt32BE(1) // checksum algorithm
    return data + toc + trailer
}

/**
 `data` compressed by zlib, as a XAR archive stores its table of contents.
 */
func deflate(_ data: Data, level: Int32 = Z_DEFAULT_COMPRESSION) -> Data {
    var length = compressBound(uLong(data.count))
    var compressed = Data(count: Int(length))
    let status = data.withUnsafeBytes { source in
        compressed.withUnsafeMutableBytes { destination in
            compress2(destination.baseAddress!.assumingMemoryBound(to: Bytef.self), &length, source.baseAddress?.assumingMemoryBound(to: Bytef.self), uLong(data.count), level)
        }
    }
    XCTAssertEqual(status, Z_OK)
    return compressed.prefix(Int(length))
}

extension Data {
    /// The bytes `hex` spells, two digits each; nil for anything else.
    init?(hex: String) {
        let digits = Array(hex.utf8)
        guard digits.count.isMultiple(of: 2) else {
            return nil
        }
        var bytes: [UInt8] = []
        for index in stride(from: 0, to: digits.count, by: 2) {
            guard let byte = UInt8(String(decoding: digits[index ..< index + 2], as: UTF8.self), radix: 16) else {
                return nil
            }
            bytes.append(byte)
        }
        self.init(bytes)
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
 The smallest big-endian executable codesign signs (ppc, or ppc64 when `is64`): `__TEXT` at file offset
 `textOffset`, a `__DATA` segment filling any gap before it, a final `__LINKEDIT` of `linkeditSize` bytes that ends the
 file, and `LC_VERSION_MIN_MACOSX` 10.4 so codesign records the execSeg fields. Given `infoPlist`, `__TEXT` holds it in
 an `__info_plist` section.
 */
func makeBigEndianMachO(is64: Bool, textOffset: UInt32 = 0, linkeditSize: UInt32 = 8, infoPlist: Data? = nil) -> Data {
    let page: UInt32 = 0x1000
    func name(_ name: String) -> Data { // a NUL-padded segname / sectname
        Data(name.utf8) + Data(count: 16 - name.utf8.count)
    }
    func field(_ value: UInt32) -> Data { // an address or size, 64-bit in a 64-bit image
        var field = Data()
        is64 ? field.appendUInt64BE(UInt64(value)) : field.appendUInt32BE(value)
        return field
    }
    func segment(_ segname: String, offset: UInt32, size: UInt32, maxprot: Int32, initprot: Int32, sections: [Data] = []) -> Data {
        var command = Data()
        command.appendUInt32BE(UInt32(is64 ? LC_SEGMENT_64 : LC_SEGMENT))
        command.appendUInt32BE(UInt32((is64 ? 72 : 56) + sections.reduce(0) { $0 + $1.count })) // cmdsize
        command.append(name(segname))
        [offset, (size + page - 1) / page * page, offset, size].forEach { command.append(field($0)) } // vmaddr, vmsize, fileoff, filesize
        command.appendInt32BE(maxprot)
        command.appendInt32BE(initprot)
        command.appendUInt32BE(UInt32(sections.count)) // nsects
        command.appendUInt32BE(0) // flags
        sections.forEach { command.append($0) }
        return command
    }

    let plistOffset = textOffset + page / 2
    var sections: [Data] = []
    if let infoPlist {
        var section = name("__info_plist") + name("__TEXT") + field(plistOffset) + field(UInt32(infoPlist.count)) // sectname, segname, addr, size
        [plistOffset, 0, 0, 0, 0, 0, 0].forEach { section.appendUInt32BE($0) } // offset, align, reloff, nreloc, flags, reserved1, reserved2
        if is64 {
            section.appendUInt32BE(0) // reserved3
        }
        sections.append(section)
    }

    var commands: [Data] = textOffset > 0 ? [segment("__DATA", offset: 0, size: textOffset, maxprot: 3, initprot: 3)] : []
    commands.append(segment("__TEXT", offset: textOffset, size: page, maxprot: 7, initprot: 5, sections: sections))
    commands.append(segment("__LINKEDIT", offset: textOffset + page, size: linkeditSize, maxprot: 7, initprot: 1))
    var versionMin = Data()
    [UInt32(LC_VERSION_MIN_MACOSX), 16, 0x000a_0400, 0x000a_0400].forEach { versionMin.appendUInt32BE($0) } // 10.4, SDK 10.4
    commands.append(versionMin)

    var data = Data()
    data.appendUInt32BE(is64 ? MH_MAGIC_64 : MH_MAGIC)
    data.appendInt32BE(is64 ? CPU_TYPE_POWERPC64 : CPU_TYPE_POWERPC)
    data.appendInt32BE(CPU_SUBTYPE_POWERPC_ALL)
    data.appendUInt32BE(UInt32(MH_EXECUTE))
    data.appendUInt32BE(UInt32(commands.count)) // ncmds
    data.appendUInt32BE(UInt32(commands.reduce(0) { $0 + $1.count })) // sizeofcmds
    data.appendUInt32BE(0) // flags
    if is64 {
        data.appendUInt32BE(0) // reserved
    }
    commands.forEach { data.append($0) }
    data.append(Data((data.count ..< Int(textOffset + page)).map { UInt8(truncatingIfNeeded: $0 * 7) })) // segment content
    if let infoPlist {
        data.replaceSubrange(Int(plistOffset) ..< Int(plistOffset) + infoPlist.count, with: infoPlist)
    }
    data.append(Data(count: Int(linkeditSize)))
    return data
}

/// `int main` built by `clang arguments` against the `sdk` SDK into `dir/name`, unsigned; skips the test when it cannot be built.
func compile(_ name: String, in dir: URL, sdk: String = "macosx", _ arguments: [String]) throws -> URL {
    let source = dir / "main.c"
    try "int main(void) { return 0; }\n".write(to: source, atomically: true, encoding: .utf8)
    let output = dir / name
    let built = try execute("/usr/bin/xcrun", ["-sdk", sdk, "clang"] + arguments + ["-Wl,-no_adhoc_codesign", source.path(), "-o", output.path()])
    try XCTSkipUnless(built, "cannot build \(name) with the \(sdk) SDK")
    return output
}

/// Run `executable` with its output discarded; true when it exits zero.
func execute(_ executable: String, _ arguments: [String]) throws -> Bool {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: executable)
    process.arguments = arguments
    process.standardOutput = FileHandle.nullDevice
    process.standardError = FileHandle.nullDevice

    try process.run()
    process.waitUntilExit()
    return process.terminationStatus == 0
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
 The message the command line prints for the hash subcommand's `arguments`, or nil when they are valid.
 */
func usageError(_ arguments: [String]) -> String? {
    do {
        _ = try Hasher.parse(arguments)
        return nil
    } catch {
        return Hasher.message(for: error)
    }
}

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
