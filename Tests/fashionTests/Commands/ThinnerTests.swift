import CryptoKit
@testable import fashion
import MachO
import os
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
        let lines = Thinner.lines(for: ls.path, exact: false, overwrite: false, reporter: Reporter(console: Console()))
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
        XCTAssertEqual(Thinner.lines(for: ls.path, exact: false, overwrite: false, reporter: Reporter(console: Console())).map(\.text), artifacts.map(\.path))
        XCTAssertEqual(try artifacts.map { try FileManager.default.attributesOfItem(atPath: $0.path)[.modificationDate] as? Date }, before)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path).count, 1 + slices.count)
    }

    /**
     `/bin/ls` copied into a fresh directory with a 10-byte, executable file under each artifact's name.
     */
    private func lsWithFilesInTheWay(_ name: String) throws -> (directory: URL, ls: URL, data: Data, slices: [Universal.Architecture], other: Data) {
        let directory = try self.directory(name)
        let (ls, data, slices) = try self.universalLs(in: directory)
        let other = Data("in the way".utf8)
        for slice in slices {
            try other.write(to: directory / "ls_\(slice.name)")
            try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: (directory / "ls_\(slice.name)").path)
        }
        return (directory, ls, data, slices, other)
    }

    func testDifferentFilesInTheWayAreReportedAndLeftAlone() throws {
        // Without --overwrite, a different file under an artifact's name stays as it is, executable bit included, and
        // standard error names it with its size and SHA-256 and the slice's; the run fails.
        let (directory, ls, data, slices, other) = try self.lsWithFilesInTheWay("differs")
        defer {
            try? FileManager.default.removeItem(at: directory)
        }

        let (status, errors) = try runFashion(["thin", ls.path])
        XCTAssertEqual(status, 2)
        XCTAssertEqual(errors, slices.map { slice in
            let bytes = data[slice.offset ..< slice.offset + slice.length]
            return "fashion: \(ls.path)_\(slice.name): exists and differs, 10 bytes, sha256 \(self.sha256(other)) where the slice is \(bytes.count) bytes, sha256 \(self.sha256(bytes)); left alone without --overwrite"
        })
        for slice in slices {
            let artifact = directory / "ls_\(slice.name)"
            XCTAssertEqual(try Data(contentsOf: artifact), other)
            XCTAssertEqual(try self.mode(artifact) & 0o111, 0o111)
        }
        let lines = Thinner.lines(for: ls.path, exact: false, overwrite: false, reporter: Reporter(console: Console()))
        XCTAssertEqual(lines.count, slices.count)
        XCTAssertTrue(lines.allSatisfy { $0.diagnostic && $0.tint == .error })
    }

    func testOverwriteReplacesDifferentFilesQuietly() throws {
        // With --overwrite, a different file under an artifact's name is replaced by the slice, without the execute
        // bit it had, and nothing is said on standard error: the unified log alone records the replacement.
        let (directory, ls, data, slices, _) = try self.lsWithFilesInTheWay("overwrite")
        defer {
            try? FileManager.default.removeItem(at: directory)
        }

        let (status, errors) = try runFashion(["thin", "--overwrite", ls.path])
        XCTAssertEqual(status, 0)
        XCTAssertEqual(errors, [])
        for slice in slices {
            let artifact = directory / "ls_\(slice.name)"
            XCTAssertEqual(try Data(contentsOf: artifact), data[slice.offset ..< slice.offset + slice.length])
            XCTAssertEqual(try self.mode(artifact) & 0o111, 0)
        }
        // The lines of such a run are the artifacts alone.
        try Data("in the way".utf8).write(to: directory / "ls_\(slices[0].name)")
        let lines = Thinner.lines(for: ls.path, exact: false, overwrite: true, reporter: Reporter(console: Console()))
        XCTAssertEqual(lines.map(\.text), slices.map { "\(ls.path)_\($0.name)" })
        XCTAssertTrue(lines.allSatisfy { !$0.diagnostic })
    }

    func testOverwriteLeavesAFileLinkedUnderAnArtifactsNameAlone() throws {
        // A hard link under an artifact's name, to a file elsewhere: --overwrite renames a new file over the name, as
        // lipo writes its output, rather than writing into the file the name links to, which keeps its bytes and mode.
        let directory = try self.directory("hardlink")
        defer {
            try? FileManager.default.removeItem(at: directory)
        }
        let (ls, data, slices) = try self.universalLs(in: directory)
        let elsewhere = directory / "elsewhere"
        try FileManager.default.createDirectory(at: elsewhere, withIntermediateDirectories: false)
        let victim = elsewhere / "notes"
        let notes = Data("precious notes".utf8)
        try notes.write(to: victim)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: victim.path)
        let link = directory / "ls_\(slices[0].name)"
        try FileManager.default.linkItem(at: victim, to: link)

        let lines = Thinner.lines(for: ls.path, exact: false, overwrite: true, reporter: Reporter(console: Console()))
        XCTAssertEqual(lines.map(\.text), slices.map { "\(ls.path)_\($0.name)" })
        XCTAssertEqual(try Data(contentsOf: victim), notes)
        XCTAssertEqual(try self.mode(victim) & 0o777, 0o755)
        XCTAssertEqual(try Data(contentsOf: link), data[slices[0].offset ..< slices[0].offset + slices[0].length])
        XCTAssertEqual(try self.mode(link) & 0o111, 0)
        // Nothing is left of the new file but the artifact it became.
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path).sorted(), (["elsewhere", "ls"] + slices.map { "ls_\($0.name)" }).sorted())
    }

    func testSymlinkInTheWayIsLeftAlone() throws {
        // A symbolic link under an artifact's name is neither followed nor replaced, --overwrite or not: reported,
        // counted, its target untouched.
        let directory = try self.directory("symlink")
        defer {
            try? FileManager.default.removeItem(at: directory)
        }
        let (ls, data, slices) = try self.universalLs(in: directory)
        let target = directory / "elsewhere"
        try Data("elsewhere".utf8).write(to: target)
        let link = directory / "ls_\(slices[0].name)"
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)

        let (status, errors) = try runFashion(["thin", "--overwrite", ls.path])
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
            XCTAssertEqual(Thinner.lines(for: (directory / name).path, exact: false, overwrite: false, reporter: Reporter(console: Console())).count, 0)
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
        let lines = Thinner.lines(for: fat.path, exact: false, overwrite: false, reporter: reporter)
        XCTAssertEqual(lines.count, 1)
        XCTAssertEqual(lines.first?.tint, .malformed)
        XCTAssertEqual(lines.first?.diagnostic, true)
        XCTAssertEqual(reporter.errorCount, 1)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path), ["fat"])
        XCTAssertEqual(try Thinner.parse([fat.path]).scan(), 2)
    }

    /// The x86_64 slice of `/bin/ls`; skips when the OS's `ls` has no such slice.
    private func lsX86() throws -> Data {
        let data = try Data(contentsOf: URL(fileURLWithPath: "/bin/ls"))
        guard case let .fat(slices) = try Universal.open(data: data), let x86 = slices.first(where: { $0.name == "x86_64" }) else {
            throw XCTSkip("/bin/ls has no x86_64 slice")
        }
        return Universal.sliceData(fileData: data, arch: x86)
    }

    /**
     A one-architecture universal binary wrapping `slice`, the x86_64 slice of `/bin/ls` by default, with `appended`
     bytes after its image, at offset 4096.
     */
    private func fatX86(_ image: Data? = nil, appended: Data) throws -> (fat: Data, slice: Data) {
        let slice = try (image ?? self.lsX86()) + appended
        var fat = Data()
        fat.appendUInt32BE(FAT_MAGIC)
        fat.appendUInt32BE(1)
        fat.appendInt32BE(CPU_TYPE_X86_64)
        fat.appendInt32BE(CPU_SUBTYPE_X86_64_ALL)
        fat.appendUInt32BE(4096)
        fat.appendUInt32BE(UInt32(slice.count))
        fat.appendUInt32BE(12)
        fat.append(Data(repeating: 0, count: 4096 - fat.count))
        fat.append(slice)
        return (fat, slice)
    }

    func testExactCutsAppendedBytesOffSlices() throws {
        // Without --exact a slice is written as the fat table places it, appended bytes included; with it, the slice
        // ends where its Mach-O image ends, as hash mode's --exact hashes it, named for the cut beside the plain one.
        let directory = try self.directory("exact-fat")
        defer {
            try? FileManager.default.removeItem(at: directory)
        }
        let junk = Data(repeating: 0x4a, count: 100)
        let (fat, slice) = try self.fatX86(appended: junk)
        let end = MachO.logicalEnd(data: slice)
        XCTAssertEqual(end, slice.count - junk.count)
        let file = directory / "fat"
        try fat.write(to: file)
        let artifact = directory / "fat_x86_64"
        let exact = directory / "fat_x86_64_exact"

        XCTAssertEqual(Thinner.lines(for: file.path, exact: false, overwrite: false, reporter: Reporter(console: Console())).map(\.text), [artifact.path])
        XCTAssertEqual(try Data(contentsOf: artifact), slice)
        XCTAssertEqual(Thinner.lines(for: file.path, exact: true, overwrite: false, reporter: Reporter(console: Console())).map(\.text), [exact.path])
        XCTAssertEqual(try Data(contentsOf: exact), slice.prefix(end))
        XCTAssertEqual(try Data(contentsOf: artifact), slice)
        XCTAssertEqual(try codesignArchs(exact.path), ["x86_64"])
    }

    func testExactWritesAThinImageWithoutItsAppendedBytes() throws {
        // A thin Mach-O that appended bytes follow has an artifact with --exact alone: the image, named for the cut,
        // which a thin file needs no architecture beside. One that ends where its image ends has nothing to write.
        let directory = try self.directory("exact-thin")
        defer {
            try? FileManager.default.removeItem(at: directory)
        }
        let junk = Data("appended".utf8)
        let (_, padded) = try self.fatX86(appended: junk)
        let image = padded.prefix(padded.count - junk.count)
        try padded.write(to: directory / "padded")
        try image.write(to: directory / "plain")
        let reporter = Reporter(console: Console())

        XCTAssertEqual(Thinner.lines(for: (directory / "padded").path, exact: false, overwrite: false, reporter: reporter).count, 0)
        XCTAssertEqual(Thinner.lines(for: (directory / "plain").path, exact: true, overwrite: false, reporter: reporter).count, 0)
        XCTAssertEqual(Thinner.lines(for: (directory / "padded").path, exact: true, overwrite: false, reporter: reporter).map(\.text), [(directory / "padded_exact").path])
        XCTAssertEqual(try Data(contentsOf: directory / "padded_exact"), image)
        XCTAssertEqual(reporter.errorCount, 0)
        // Through the binary: a second pass over the directory finds the artifact in place and writes nothing new.
        let (status, errors) = try runFashion(["thin", "--exact", directory.path])
        XCTAssertEqual(status, 0)
        XCTAssertEqual(errors, [])
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path).sorted(), ["padded", "padded_exact", "plain"])
    }

    func testFilesThatYieldOneArtifactWriteItInTurn() throws {
        // A universal file whose slice appended bytes follow, and that slice as a thin file beside it, yield one
        // artifact under --exact. Handed to two threads at once, again and again, the second to reach it waits for the
        // first and finds it in place, rather than half written and reported as a different file. The image is grown
        // by 8 MiB, its __LINKEDIT filesize with it, so writing it takes long enough for the second thread to arrive.
        let directory = try self.directory("in-turn")
        defer {
            try? FileManager.default.removeItem(at: directory)
        }
        var image = try self.lsX86()
        let linkedit = try XCTUnwrap(MachO(image)?.findSegment("__LINKEDIT"))
        let filesize = try linkedit.data.startIndex + XCTUnwrap(MemoryLayout<segment_command_64>.offset(of: \.filesize))
        let grown = try linkedit.load(segment_command_64.self).filesize + UInt64(8 << 20)
        image.replaceSubrange(filesize ..< filesize + 8, with: withUnsafeBytes(of: grown) { Data($0) })
        image.append(Data(count: 8 << 20))
        let junk = Data(repeating: 0x4a, count: 100)
        let (fat, slice) = try self.fatX86(image, appended: junk)
        XCTAssertEqual(MachO.logicalEnd(data: slice), image.count)
        try fat.write(to: directory / "fat")
        try slice.write(to: directory / "fat_x86_64")
        let artifact = directory / "fat_x86_64_exact"

        for _ in 0 ..< 20 {
            try? FileManager.default.removeItem(at: artifact)
            let reporter = Reporter(console: Console())
            let texts = OSAllocatedUnfairLock(initialState: [String]())
            let group = DispatchGroup()
            for name in ["fat", "fat_x86_64"] {
                group.enter()
                Thread {
                    let lines = Thinner.lines(for: (directory / name).path, exact: true, overwrite: false, reporter: reporter)
                    texts.withLock { $0 += lines.map(\.text) }
                    group.leave()
                }.start()
            }
            group.wait()
            XCTAssertEqual(reporter.errorCount, 0)
            XCTAssertEqual(texts.withLock { $0 }, [artifact.path, artifact.path])
        }
        XCTAssertEqual(try Data(contentsOf: artifact), slice.prefix(slice.count - junk.count))
    }
}
