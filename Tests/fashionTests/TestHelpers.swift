import Foundation
import XCTest

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
        guard let open = line.firstIndex(of: "("), let close = line.lastIndex(of: ")"), open < close else {
            return nil
        }
        return Set(line[line.index(after: open) ..< close].split(separator: " ").map(String.init))
    }
    return nil
}
