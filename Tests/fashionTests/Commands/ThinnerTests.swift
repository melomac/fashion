import CryptoKit
@testable import fashion
import MachO
import XCTest

/**
 `fashion thin`: each architecture of a universal Mach-O written out beside it, byte for byte; a second run leaves it
 alone, another file in its place is overwritten and said so, a symlink in its place is left alone.
 */
final class ThinnerTests: XCTestCase {
    private func directory(_ name: String) throws -> URL {
        let url = FileManager.default.temporaryDirectory / "fashion-thin-\(name)-\(UUID())"
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    /**
     A copy of `/bin/ls` in `directory`, with its architectures as the fat table places them; skips when the OS's
     `ls` is not universal.
     */
    private func universalLs(in directory: URL) throws -> (url: URL, data: Data, slices: [Universal.Architecture]) {
        let url = directory / "ls"
        try FileManager.default.copyItem(at: URL(fileURLWithPath: "/bin/ls"), to: url)
        let data = try Data(contentsOf: url)
        guard case let .fat(slices) = try Universal.open(path: url.path) else {
            throw XCTSkip("/bin/ls is not universal")
        }
        return (url, data, slices)
    }

    private func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private func mode(_ url: URL) throws -> Int {
        try XCTUnwrap(FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as? Int)
    }

    func testSlicesAreWrittenBesideTheFile() throws {
        let directory = try self.directory("ls")
        defer {
            try? FileManager.default.removeItem(at: directory)
        }
        let (ls, data, slices) = try self.universalLs(in: directory)

        // One line per artifact, its path, and the artifacts beside the file: the bytes of each slice as the fat
        // table places them, named as codesign spells the architecture, which reads each as the thin Mach-O it is.
        let lines = Thinner.lines(for: ls.path, reporter: Reporter(console: Console()))
        XCTAssertEqual(lines.map(\.text), slices.map { "\(ls.path)_\($0.name)" })
        XCTAssertTrue(lines.allSatisfy { !$0.diagnostic && $0.tint == .none })
        XCTAssertEqual(try codesignArchs("/bin/ls"), Set(slices.map(\.name)))
        for slice in slices {
            let artifact = directory / "ls_\(slice.name)"
            XCTAssertEqual(try Data(contentsOf: artifact), data[slice.offset ..< slice.offset + slice.length])
            XCTAssertEqual(try codesignArchs(artifact.path), [slice.name])
            // Not executable: an artifact is for analysis, not to run.
            XCTAssertEqual(try self.mode(artifact) & 0o111, 0)
            XCTAssertEqual(try self.mode(artifact) & 0o444, 0o444)
        }
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path).count, 1 + slices.count)
    }

    func testIdenticalArtifactsAreLeftInPlace() throws {
        // A second run finds every artifact in place, byte for byte: the same lines, nothing rewritten, nothing said.
        let directory = try self.directory("twice")
        defer {
            try? FileManager.default.removeItem(at: directory)
        }
        let (ls, _, slices) = try self.universalLs(in: directory)
        XCTAssertEqual(try Thinner.parse([directory.path]).scan(), 0)
        let artifacts = slices.map { directory / "ls_\($0.name)" }
        let before = try artifacts.map { try FileManager.default.attributesOfItem(atPath: $0.path)[.modificationDate] as? Date }

        let (status, errors) = try runFashion(["thin", ls.path])
        XCTAssertEqual(status, 0)
        XCTAssertEqual(errors, [])
        XCTAssertEqual(Thinner.lines(for: ls.path, reporter: Reporter(console: Console())).map(\.text), artifacts.map(\.path))
        XCTAssertEqual(try artifacts.map { try FileManager.default.attributesOfItem(atPath: $0.path)[.modificationDate] as? Date }, before)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path).count, 1 + slices.count)
    }

    func testOtherFilesInTheWayAreOverwrittenAndSaidSo() throws {
        // Another file under an artifact's name is replaced by the slice, without the execute bit it had, and
        // standard error says what was there and what is there now, by size and SHA-256; the run succeeds.
        let directory = try self.directory("overwrite")
        defer {
            try? FileManager.default.removeItem(at: directory)
        }
        let (ls, data, slices) = try self.universalLs(in: directory)
        let other = Data("in the way".utf8)
        for slice in slices {
            try other.write(to: directory / "ls_\(slice.name)")
            try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: (directory / "ls_\(slice.name)").path)
        }

        let (status, errors) = try runFashion(["thin", ls.path])
        XCTAssertEqual(status, 0)
        XCTAssertEqual(errors, slices.map { slice in
            let bytes = data[slice.offset ..< slice.offset + slice.length]
            return "fashion: \(ls.path)_\(slice.name): overwritten: was 10 bytes, sha256 \(self.sha256(other)), now \(bytes.count) bytes, sha256 \(self.sha256(bytes))"
        })
        for slice in slices {
            let artifact = directory / "ls_\(slice.name)"
            XCTAssertEqual(try Data(contentsOf: artifact), data[slice.offset ..< slice.offset + slice.length])
            XCTAssertEqual(try self.mode(artifact) & 0o111, 0)
        }
        // The lines of such a run: the overwrite line first, then the artifact, as for any file's diagnostics.
        try other.write(to: directory / "ls_\(slices[0].name)")
        let lines = Thinner.lines(for: ls.path, reporter: Reporter(console: Console()))
        XCTAssertEqual(lines.count, slices.count + 1)
        XCTAssertEqual(lines[0].diagnostic, true)
        XCTAssertEqual(lines[0].tint, .error)
        XCTAssertEqual(lines[1].text, (directory / "ls_\(slices[0].name)").path)
    }

    func testSymlinkInTheWayIsLeftAlone() throws {
        // A symlink under an artifact's name is neither followed nor replaced: reported, counted, its target untouched.
        let directory = try self.directory("symlink")
        defer {
            try? FileManager.default.removeItem(at: directory)
        }
        let (ls, data, slices) = try self.universalLs(in: directory)
        let target = directory / "elsewhere"
        try Data("elsewhere".utf8).write(to: target)
        let link = directory / "ls_\(slices[0].name)"
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)

        let (status, errors) = try runFashion(["thin", ls.path])
        XCTAssertEqual(status, 2)
        XCTAssertEqual(errors, ["fashion: \(link.path): exists and is not a regular file, left alone"])
        XCTAssertEqual(try Data(contentsOf: target), Data("elsewhere".utf8))
        XCTAssertEqual(try FileManager.default.destinationOfSymbolicLink(atPath: link.path), target.path)
        // The other slices were written.
        for slice in slices.dropFirst() {
            XCTAssertEqual(try Data(contentsOf: directory / "ls_\(slice.name)"), data[slice.offset ..< slice.offset + slice.length])
        }
    }

    func testThinAndOtherFilesAreLeftAlone() throws {
        // A thin Mach-O has nothing to extract, nor has any other file: no artifact, no line, exit 0.
        let directory = try self.directory("thin")
        defer {
            try? FileManager.default.removeItem(at: directory)
        }
        let data = try Data(contentsOf: URL(fileURLWithPath: "/bin/ls"))
        guard case let .fat(slices) = try Universal.open(data: data) else {
            throw XCTSkip("/bin/ls is not universal")
        }
        try Universal.sliceData(fileData: data, arch: slices[0]).write(to: directory / "thin")
        try Data("not a Mach-O".utf8).write(to: directory / "text")

        for name in ["thin", "text"] {
            XCTAssertEqual(Thinner.lines(for: (directory / name).path, reporter: Reporter(console: Console())).count, 0)
        }
        XCTAssertEqual(try Thinner.parse([directory.path]).scan(), 0)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path).count, 2)
    }

    func testMalformedFatIsReported() throws {
        // A fat table pointing past the end of the file is a malformed Mach-O: red, counted, nothing written.
        let directory = try self.directory("malformed")
        defer {
            try? FileManager.default.removeItem(at: directory)
        }
        var data = Data()
        data.appendUInt32BE(FAT_MAGIC)
        data.appendUInt32BE(1)
        data.appendInt32BE(CPU_TYPE_X86_64)
        data.appendInt32BE(CPU_SUBTYPE_X86_64_ALL)
        data.appendUInt32BE(4096) // offset
        data.appendUInt32BE(4096) // size
        data.appendUInt32BE(12) // align
        let fat = directory / "fat"
        try data.write(to: fat)

        let reporter = Reporter(console: Console())
        let lines = Thinner.lines(for: fat.path, reporter: reporter)
        XCTAssertEqual(lines.count, 1)
        XCTAssertEqual(lines.first?.tint, .malformed)
        XCTAssertEqual(lines.first?.diagnostic, true)
        XCTAssertEqual(reporter.errorCount, 1)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path), ["fat"])
        XCTAssertEqual(try Thinner.parse([fat.path]).scan(), 2)
    }
}
