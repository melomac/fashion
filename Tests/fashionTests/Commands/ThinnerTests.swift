import CryptoKit
@testable import fashion
import MachO
import os
import XCTest

/**
 `fashion thin`: each architecture of a universal Mach-O listed, and written out beside it with --write, byte for byte;
 a second run leaves it alone, another file in its place is replaced and logged, a symlink in its place is left alone.
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
        return (url, data, slices.archs)
    }

    private func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private func mode(_ url: URL) throws -> Int {
        try XCTUnwrap(FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as? Int)
    }

    func testSlicesAreWrittenBesideTheFileWithWrite() throws {
        let directory = try self.directory("ls")
        defer {
            try? FileManager.default.removeItem(at: directory)
        }
        let (ls, data, slices) = try self.universalLs(in: directory)

        // One line per artifact, its path, and the artifacts beside the file: the bytes of each slice as the fat
        // table places them, named as codesign spells the architecture, which reads each as the thin Mach-O it is.
        let lines = try Thinner.lines(for: ls.path, exact: false, unsign: false, unpack: false, write: true, reporter: Reporter(console: Console()))
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

    /**
     A second run finds every artifact in place, byte for byte: the same lines, nothing rewritten, nothing said.
     */
    func testIdenticalArtifactsAreLeftInPlace() throws {
        let directory = try self.directory("twice")
        defer {
            try? FileManager.default.removeItem(at: directory)
        }
        let (ls, _, slices) = try self.universalLs(in: directory)
        XCTAssertEqual(try Thinner.parse(["--write", directory.path]).scan(), 0)
        let artifacts = slices.map { directory / "ls_\($0.name)" }
        let before = try artifacts.map { try FileManager.default.attributesOfItem(atPath: $0.path)[.modificationDate] as? Date }

        let (status, errors) = try runFashion(["thinr", "--write", ls.path])
        XCTAssertEqual(status, 0)
        XCTAssertEqual(errors, [])
        XCTAssertEqual(try Thinner.lines(for: ls.path, exact: false, unsign: false, unpack: false, write: true, reporter: Reporter(console: Console())).map(\.text), artifacts.map(\.path))
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

    /**
     Without --write, nothing is written: the lines name the artifacts as hash mode labels the states, one per slice
     and per state, the directory holds the file alone after, and the run succeeds. The edits are made all the
     same, so --unsign lists the unsigned state of each slice.
     */
    func testWithoutWriteArtifactsAreListedAndNotWritten() throws {
        let directory = try self.directory("list")
        defer {
            try? FileManager.default.removeItem(at: directory)
        }
        let (ls, _, slices) = try self.universalLs(in: directory)

        let (status, errors) = try runFashion(["thinr", ls.path])
        XCTAssertEqual(status, 0)
        XCTAssertEqual(errors, [])
        let lines = try Thinner.lines(for: ls.path, exact: false, unsign: false, unpack: false, write: false, reporter: Reporter(console: Console()))
        XCTAssertEqual(lines.map(\.text), slices.map { "\(ls.path) (\($0.name))" })
        XCTAssertTrue(lines.allSatisfy { !$0.diagnostic && $0.tint == .none })
        XCTAssertEqual(try Thinner.lines(for: ls.path, exact: false, unsign: true, unpack: false, write: false, reporter: Reporter(console: Console())).map(\.text), slices.flatMap { ["\(ls.path) (\($0.name))", "\(ls.path) (\($0.name), unsigned)"] })
        XCTAssertEqual(try Thinner.parse([directory.path, "--unsign", "--unpack", "--exact"]).scan(), 0)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path), ["ls"])
    }

    /**
     With --quiet, a file that has artifacts is printed once, its own path, written or not; one with none prints
     nothing, and what is reported about a file stands: a malformed one is reported and nothing else.
     */
    func testQuietNamesTheFileOnce() throws {
        let directory = try self.directory("quiet")
        defer {
            try? FileManager.default.removeItem(at: directory)
        }
        let (ls, _, slices) = try self.universalLs(in: directory)
        let thin = directory / "thin"
        try Universal.sliceData(fileData: Data(contentsOf: ls), arch: slices[0]).write(to: thin)
        // A fat table pointing past the end of the file, malformed.
        var table = Data()
        table.appendUInt32BE(FAT_MAGIC)
        table.appendUInt32BE(1)
        table.appendInt32BE(CPU_TYPE_X86_64)
        table.appendInt32BE(CPU_SUBTYPE_X86_64_ALL)
        [4096, 4096, 12].forEach { table.appendUInt32BE(UInt32($0)) }
        let fat = directory / "fat"
        try table.write(to: fat)
        let reporter = Reporter(console: Console())

        for write in [false, true] {
            let lines = try Thinner.lines(for: ls.path, exact: false, unsign: true, unpack: false, write: write, quiet: true, reporter: reporter)
            XCTAssertEqual(lines.map(\.text), [ls.path], "write \(write)")
            XCTAssertTrue(lines.allSatisfy { !$0.diagnostic && $0.tint == .none })
            XCTAssertEqual(try Thinner.lines(for: thin.path, exact: false, unsign: false, unpack: false, write: write, quiet: true, reporter: reporter).count, 0)
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path).count, write ? 3 + 2 * slices.count : 3)
        }
        XCTAssertEqual(reporter.errorCount, 0)
        let malformed = try Thinner.lines(for: fat.path, exact: false, unsign: false, unpack: false, write: false, quiet: true, reporter: reporter)
        XCTAssertEqual(malformed.count, 1)
        XCTAssertEqual(malformed.first?.diagnostic, true)
        XCTAssertEqual(reporter.errorCount, 1)
        XCTAssertEqual(try Thinner.parse(["-q", "--unsign", directory.path]).scan(), 2)
    }

    /**
     Without --write, a different file under an artifact's name is not looked at: it stays as it is, executable bit
     included, the artifact is listed by its label as any other, and nothing is said.
     */
    func testWithoutWriteFilesInTheWayAreNotLookedAt() throws {
        let (directory, ls, _, slices, other) = try self.lsWithFilesInTheWay("differs")
        defer {
            try? FileManager.default.removeItem(at: directory)
        }

        let (status, errors) = try runFashion(["thinr", ls.path])
        XCTAssertEqual(status, 0)
        XCTAssertEqual(errors, [])
        for slice in slices {
            let artifact = directory / "ls_\(slice.name)"
            XCTAssertEqual(try Data(contentsOf: artifact), other)
            XCTAssertEqual(try self.mode(artifact) & 0o111, 0o111)
        }
        let lines = try Thinner.lines(for: ls.path, exact: false, unsign: false, unpack: false, write: false, reporter: Reporter(console: Console()))
        XCTAssertEqual(lines.map(\.text), slices.map { "\(ls.path) (\($0.name))" })
        XCTAssertTrue(lines.allSatisfy { !$0.diagnostic })
    }

    /**
     An artifact is written beside its name under a temporary one, 45 bytes whatever the artifact's, and renamed into
     it: a file of 240 bytes' name gets its `_unsigned` artifact, 249, under --write, where a temporary named after
     the artifact would run past the 255 a name may have. A different file under that name cannot be kept, its backup
     name would run past them too: it is reported, and keeps its name and bytes.
     */
    func testWriteWritesAnArtifactWhateverItsNameLength() throws {
        let directory = try self.directory("long-name")
        defer {
            try? FileManager.default.removeItem(at: directory)
        }
        let data = try Data(contentsOf: compile("program", in: directory, ["-arch", "x86_64"]))
        let long = directory / String(repeating: "n", count: 240)
        try FileManager.default.copyItem(at: self.codesignedFile(data, in: directory), to: long)
        let artifact = long.path + "_unsigned"
        let listed = try Thinner.lines(for: long.path, exact: false, unsign: true, unpack: false, write: false, reporter: Reporter(console: Console()))
        XCTAssertEqual(listed.map(\.text), ["\(long.path) (unsigned)"])
        XCTAssertFalse(FileManager.default.fileExists(atPath: artifact))

        let written = try Thinner.lines(for: long.path, exact: false, unsign: true, unpack: false, write: true, reporter: Reporter(console: Console()))
        XCTAssertEqual(written.map(\.text), [artifact])
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: artifact)), data)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path).filter { $0.hasPrefix(".fashion-") }, [])

        try Data("something else".utf8).write(to: URL(fileURLWithPath: artifact))
        let reporter = Reporter(console: Console())
        let refused = try Thinner.lines(for: long.path, exact: false, unsign: true, unpack: false, write: true, reporter: reporter)
        XCTAssertEqual(refused.count, 1)
        XCTAssertTrue(refused[0].diagnostic)
        XCTAssertTrue(refused[0].text.lowercased().contains("too long"), refused[0].text)
        XCTAssertEqual(reporter.errorCount, 1)
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: artifact)), Data("something else".utf8))
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path).filter { $0.contains("~") }, [])
    }

    /**
     With --write, a different file under an artifact's name gives it up to the slice, written without the execute
     bit, and is kept beside as the conflict backup, `ls_x86_64~<seconds>.<milliseconds>`, bytes and execute bit as
     they were; the backup's path is printed after the artifact's, and nothing is said on standard error: the unified
     log records both.
     */
    func testWriteKeepsDifferentFilesAsConflictBackups() throws {
        let (directory, ls, data, slices, _) = try self.lsWithFilesInTheWay("write")
        defer {
            try? FileManager.default.removeItem(at: directory)
        }

        let (status, errors) = try runFashion(["thinr", "--write", ls.path])
        XCTAssertEqual(status, 0)
        XCTAssertEqual(errors, [])
        for slice in slices {
            let artifact = directory / "ls_\(slice.name)"
            XCTAssertEqual(try Data(contentsOf: artifact), data[slice.offset ..< slice.offset + slice.length])
            XCTAssertEqual(try self.mode(artifact) & 0o111, 0)
        }
        let backups = try FileManager.default.contentsOfDirectory(atPath: directory.path).filter { $0.contains("~") }
        XCTAssertEqual(backups.count, slices.count)
        for backup in backups {
            XCTAssertNotNil(backup.wholeMatch(of: /ls_[^~]+~[0-9]+\.[0-9]{3}/), backup)
            XCTAssertEqual(try Data(contentsOf: directory / backup), Data("in the way".utf8))
            XCTAssertEqual(try self.mode(directory / backup) & 0o111, 0o111)
        }
        // The lines of such a run are the artifacts, each followed by the backup of what was in its way.
        try Data("in the way".utf8).write(to: directory / "ls_\(slices[0].name)")
        let lines = try Thinner.lines(for: ls.path, exact: false, unsign: false, unpack: false, write: true, reporter: Reporter(console: Console()))
        XCTAssertEqual(lines.count, slices.count + 1)
        XCTAssertEqual(lines[0].text, "\(ls.path)_\(slices[0].name)")
        XCTAssertTrue(lines[1].text.hasPrefix("\(ls.path)_\(slices[0].name)~"), lines[1].text)
        XCTAssertEqual(lines.dropFirst(2).map(\.text), slices.dropFirst().map { "\(ls.path)_\($0.name)" })
        XCTAssertTrue(lines.allSatisfy { !$0.diagnostic })
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: lines[1].text)), Data("in the way".utf8))
        // Nothing is left beside the artifacts: each was written under a temporary name and renamed into its own.
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path).filter { $0.hasPrefix(".fashion-") }, [])
    }

    /**
     A hard link under an artifact's name, to a file elsewhere: --write renames the link aside as the conflict
     backup, still a link to the file, and places a new file under the name, rather than writing into the file the
     name links to, which keeps its bytes and mode.
     */
    func testWriteLeavesAFileLinkedUnderAnArtifactsNameAlone() throws {
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

        let lines = try Thinner.lines(for: ls.path, exact: false, unsign: false, unpack: false, write: true, reporter: Reporter(console: Console()))
        XCTAssertEqual(lines.count, slices.count + 1)
        let backup = lines[1].text
        XCTAssertTrue(backup.hasPrefix(link.path + "~"), backup)
        XCTAssertEqual([lines[0].text] + lines.dropFirst(2).map(\.text), slices.map { "\(ls.path)_\($0.name)" })
        XCTAssertEqual(try Data(contentsOf: victim), notes)
        XCTAssertEqual(try self.mode(victim) & 0o777, 0o755)
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: backup)), notes)
        XCTAssertEqual(try self.mode(URL(fileURLWithPath: backup)) & 0o777, 0o755)
        XCTAssertEqual(try Data(contentsOf: link), data[slices[0].offset ..< slices[0].offset + slices[0].length])
        XCTAssertEqual(try self.mode(link) & 0o111, 0)
        // Nothing is left of the new file but the artifact it became, and the backup beside it.
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path).sorted(), (["elsewhere", "ls", URL(fileURLWithPath: backup).lastPathComponent] + slices.map { "ls_\($0.name)" }).sorted())
    }

    /**
     A symbolic link under an artifact's name is neither followed nor replaced, --write or not: reported,
     counted, its target untouched.
     */
    func testSymlinkInTheWayIsLeftAlone() throws {
        let directory = try self.directory("symlink")
        defer {
            try? FileManager.default.removeItem(at: directory)
        }
        let (ls, data, slices) = try self.universalLs(in: directory)
        let target = directory / "elsewhere"
        try Data("elsewhere".utf8).write(to: target)
        let link = directory / "ls_\(slices[0].name)"
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)

        let (status, errors) = try runFashion(["thinr", "--write", ls.path])
        XCTAssertEqual(status, 2)
        XCTAssertEqual(errors, ["fashion: \(link.path): exists and is not a regular file, left alone"])
        XCTAssertEqual(try Data(contentsOf: target), Data("elsewhere".utf8))
        XCTAssertEqual(try FileManager.default.destinationOfSymbolicLink(atPath: link.path), target.path)
        // The other slices were written.
        for slice in slices.dropFirst() {
            XCTAssertEqual(try Data(contentsOf: directory / "ls_\(slice.name)"), data[slice.offset ..< slice.offset + slice.length])
        }
    }

    /**
     An artifact in a directory the user cannot write to is reported with the system's word, per artifact, and
     counted, the run exiting 2: the temporary file beside the name cannot be opened. `unsign` likewise.
     */
    func testAnArtifactThatCannotBeWrittenIsReported() throws {
        try XCTSkipIf(getuid() == 0, "root writes anywhere")
        let directory = try self.directory("readonly")
        defer {
            chmod(directory.path, 0o755)
            try? FileManager.default.removeItem(at: directory)
        }
        let (ls, _, slices) = try self.universalLs(in: directory)
        XCTAssertEqual(chmod(directory.path, 0o555), 0)

        let (status, errors) = try runFashion(["thinr", "--write", ls.path])
        XCTAssertEqual(status, 2)
        XCTAssertEqual(errors, slices.map { "fashion: \(ls.path)_\($0.name): Permission denied" })
        let (unsigning, unsigned) = try runFashion(["unsign", ls.path])
        XCTAssertEqual(unsigning, 2)
        XCTAssertEqual(unsigned, ["fashion: \(ls.path)_unsigned: Permission denied"])
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path), ["ls"], "nothing written, no temporary left")
    }

    /**
     A thin Mach-O has nothing to extract, nor has any other file: no artifact, no line, exit 0.
     */
    func testThinAndOtherFilesAreLeftAlone() throws {
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
            XCTAssertEqual(try Thinner.lines(for: (directory / name).path, exact: false, unsign: false, unpack: false, write: true, reporter: Reporter(console: Console())).count, 0)
        }
        XCTAssertEqual(try Thinner.parse([directory.path]).scan(), 0)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path).count, 2)
    }

    /**
     A fat table pointing past the end of the file is a malformed Mach-O: red, counted, nothing written.
     */
    func testMalformedFatIsReported() throws {
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
        let lines = try Thinner.lines(for: fat.path, exact: false, unsign: false, unpack: false, write: true, reporter: reporter)
        XCTAssertEqual(lines.count, 1)
        XCTAssertEqual(lines.first?.tint, .malformed)
        XCTAssertEqual(lines.first?.diagnostic, true)
        XCTAssertEqual(reporter.errorCount, 1)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path), ["fat"])
        XCTAssertEqual(try Thinner.parse([fat.path]).scan(), 2)
    }

    /**
     A slice whose Mach-O does not parse, its sizeofcmds past the slice, is written as the fat table places it,
     as lipo -thin writes it: the table alone decides the bytes. With --exact, which reads the slice as a Mach-O
     to cut it, the file is reported red after the slice's architecture, and nothing is written.
     */
    func testMalformedSliceIsWrittenAsTheFatTablePlacesIt() throws {
        let directory = try self.directory("malformed-slice")
        defer {
            try? FileManager.default.removeItem(at: directory)
        }
        var (fat, _) = try self.fatX86(appended: Data())
        let sizeofcmds = try 4096 + XCTUnwrap(MemoryLayout<mach_header>.offset(of: \.sizeofcmds))
        fat.replaceSubrange(sizeofcmds ..< sizeofcmds + 4, with: [0xff, 0xff, 0xff, 0xff])
        let file = directory / "fat"
        try fat.write(to: file)
        let artifact = directory / "fat_x86_64"

        let reporter = Reporter(console: Console())
        XCTAssertEqual(try Thinner.lines(for: file.path, exact: false, unsign: false, unpack: false, write: true, reporter: reporter).map(\.text), [artifact.path])
        XCTAssertEqual(reporter.errorCount, 0)
        XCTAssertEqual(try Data(contentsOf: artifact), fat[4096...])
        try FileManager.default.removeItem(at: artifact)

        let lines = try Thinner.lines(for: file.path, exact: true, unsign: false, unpack: false, write: true, reporter: reporter)
        XCTAssertEqual(lines.count, 1)
        XCTAssertTrue(try XCTUnwrap(lines.first).text.hasPrefix("fashion: \(file.path) (x86_64): Invalid Mach-O: sizeofcmds 4294967295 does not hold"))
        XCTAssertEqual(lines.first?.tint, .malformed)
        XCTAssertEqual(reporter.errorCount, 1)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path), ["fat"])
    }

    /// The `x86_64` slice of `/bin/ls`; skips when the OS's `ls` has no such slice.
    private func lsX86() throws -> Data {
        let data = try Data(contentsOf: URL(fileURLWithPath: "/bin/ls"))
        guard case let .fat(slices) = try Universal.open(data: data), let x86 = slices.first(where: { $0.name == "x86_64" }) else {
            throw XCTSkip("/bin/ls has no x86_64 slice")
        }
        return Universal.sliceData(fileData: data, arch: x86)
    }

    /**
     A one-architecture universal binary wrapping `slice`, the `x86_64` slice of `/bin/ls` by default, with `appended`
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

    /**
     Without --exact a slice is written as the fat table places it, appended bytes included; with it, the slice
     ends where its Mach-O image ends, as hash mode's --exact hashes it, named for the cut and written beside the
     plain one, which is written too.
     */
    func testExactCutsAppendedBytesOffSlices() throws {
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

        XCTAssertEqual(try Thinner.lines(for: file.path, exact: false, unsign: false, unpack: false, write: true, reporter: Reporter(console: Console())).map(\.text), [artifact.path])
        XCTAssertEqual(try Data(contentsOf: artifact), slice)
        XCTAssertEqual(try Thinner.lines(for: file.path, exact: true, unsign: false, unpack: false, write: true, reporter: Reporter(console: Console())).map(\.text), [artifact.path, exact.path])
        XCTAssertEqual(try Data(contentsOf: exact), slice.prefix(end))
        XCTAssertEqual(try Data(contentsOf: artifact), slice)
        XCTAssertEqual(try codesignArchs(exact.path), ["x86_64"])
    }

    /**
     A thin Mach-O that appended bytes follow has an artifact with --exact alone: the image, named for the cut,
     which a thin file needs no architecture beside. One that ends where its image ends has nothing to write.
     */
    func testExactWritesAThinImageWithoutItsAppendedBytes() throws {
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

        XCTAssertEqual(try Thinner.lines(for: (directory / "padded").path, exact: false, unsign: false, unpack: false, write: true, reporter: reporter).count, 0)
        XCTAssertEqual(try Thinner.lines(for: (directory / "plain").path, exact: true, unsign: false, unpack: false, write: true, reporter: reporter).count, 0)
        XCTAssertEqual(try Thinner.lines(for: (directory / "padded").path, exact: true, unsign: false, unpack: false, write: true, reporter: reporter).map(\.text), [(directory / "padded_exact").path])
        XCTAssertEqual(try Data(contentsOf: directory / "padded_exact"), image)
        XCTAssertEqual(reporter.errorCount, 0)
        // Through the binary: a second pass over the directory finds the artifact in place and writes nothing new.
        let (status, errors) = try runFashion(["thinr", "--write", "--exact", directory.path])
        XCTAssertEqual(status, 0)
        XCTAssertEqual(errors, [])
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path).sorted(), ["padded", "padded_exact", "plain"])
    }

    /**
     A universal file whose slice appended bytes follow, and that slice as a thin file beside it, yield one
     artifact under --exact, the cut slice; the universal file finds the thin file in place as its plain slice.
     Handed to two threads at once, again and again, the second to reach it waits for the
     first and finds it in place, rather than half written and reported as a different file. The image is grown
     by 8 MiB, its `__LINKEDIT` filesize with it, so writing it takes long enough for the second thread to arrive.
     */
    func testFilesThatYieldOneArtifactWriteItInTurn() throws {
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

        let writer = try ArtifactWriter(Thinner.parse(["--exact", "--write", directory.path]))
        for _ in 0 ..< 20 {
            try? FileManager.default.removeItem(at: artifact)
            let reporter = Reporter(console: Console())
            let texts = OSAllocatedUnfairLock(initialState: [String]())
            let group = DispatchGroup()
            for name in ["fat", "fat_x86_64"] {
                group.enter()
                let thread = Thread {
                    let lines = ScanOptions.open((directory / name).path, reporter: reporter) { writer.lines(for: $0, reporter: reporter) }
                    texts.withLock { $0 += lines.map(\.text) }
                    group.leave()
                }
                // The test waits at its own QoS: a thread below it would be an inversion, which Xcode flags.
                thread.qualityOfService = .userInitiated
                thread.start()
            }
            group.wait()
            XCTAssertEqual(reporter.errorCount, 0)
            XCTAssertEqual(texts.withLock { $0.sorted() }, [artifact.path, artifact.path, (directory / "fat_x86_64").path].sorted())
        }
        XCTAssertEqual(try Data(contentsOf: artifact), slice.prefix(slice.count - junk.count))
    }

    /// `data` signed ad hoc by codesign, in a file of its own in `directory` for as long as codesign takes.
    private func codesigned(_ data: Data, in directory: URL) throws -> Data {
        let url = directory / "codesigned-\(UUID())"
        try data.write(to: url)
        defer {
            try? FileManager.default.removeItem(at: url)
        }
        _ = try codesign(["-f", "-s", "-", url.path])
        return try Data(contentsOf: url)
    }

    /// The lines hash mode prints for `path` with `arguments`.
    private func hashLines(_ path: String, _ arguments: [String] = []) throws -> [String] {
        try Digester(Hasher.parse([path, "--quiet"] + arguments)).lines(for: path, reporter: Reporter(console: Console())).map(\.text)
    }

    /**
     An `x86_64` and an `arm64` image as the linker leaves them unsigned, and the universal file lipo makes of them,
     all signed by `codesign`: `unsign` gives each back byte for byte, with the `__LINKEDIT` vmsize the linker rounded to
     its page where codesign rounds it to 16 KiB, and the universal file laid out as `lipo` laid it out, where `codesign`
     moves every architecture to 16 KiB, its signed slices written beside the unsigned ones. An unsigned file is left
     as it is.
     */
    func testUnsignRestoresTheUnsignedOriginals() throws {
        let directory = try self.directory("unsign-originals")
        defer {
            try? FileManager.default.removeItem(at: directory)
        }
        let x86 = try compile("x86_64", in: directory, ["-arch", "x86_64"])
        let arm = try compile("arm64", in: directory, ["-arch", "arm64"])
        let universal = directory / "universal"
        try XCTSkipUnless(execute("/usr/bin/xcrun", ["lipo", "-create", x86.path, arm.path, "-output", universal.path]), "cannot run lipo")
        let signed = directory / "signed"
        try FileManager.default.createDirectory(at: signed, withIntermediateDirectories: false)

        for original in [x86, arm, universal] {
            let data = try Data(contentsOf: original)
            let copy = signed / original.lastPathComponent
            try data.write(to: copy)
            _ = try codesign(["-s", "-", copy.path])
            XCTAssertNotEqual(try Data(contentsOf: copy), data)
            XCTAssertEqual(try self.hashLines(copy.path, ["--unsign"]).last, try ByteHash.sha256.digest(data), original.lastPathComponent)
            XCTAssertEqual(try self.hashLines(original.path, ["--unsign"]), try [ByteHash.sha256.digest(data)], original.lastPathComponent)
        }
        let reporter = Reporter(console: Console())
        let signedUniversal = try Data(contentsOf: signed / "universal")
        guard case let .fat(archs) = try Universal.open(data: signedUniversal), archs.count == 2 else {
            return XCTFail("the signed universal file is not universal")
        }
        let signedSlices = archs.map { Universal.sliceData(fileData: signedUniversal, arch: $0) }
        let originals = try [x86, arm].map { try Data(contentsOf: $0) }
        for (file, artifacts) in [("x86_64", ["x86_64_unsigned": originals[0]]), ("arm64", ["arm64_unsigned": originals[1]]), ("universal", ["universal_x86_64": signedSlices[0], "universal_x86_64_unsigned": originals[0], "universal_arm64": signedSlices[1], "universal_arm64_unsigned": originals[1]])] {
            let lines = try Thinner.lines(for: (signed / file).path, exact: false, unsign: true, unpack: false, write: true, reporter: reporter)
            XCTAssertEqual(Set(lines.map(\.text)), Set(artifacts.keys.map { (signed / $0).path }))
            for (name, original) in artifacts {
                XCTAssertEqual(try Data(contentsOf: signed / name), original, name)
            }
        }
        XCTAssertEqual(try Thinner.lines(for: x86.path, exact: false, unsign: true, unpack: false, write: true, reporter: reporter).count, 0)
        XCTAssertEqual(reporter.errorCount, 0)
    }

    /**
     The universal file is laid out with the alignment `lipo` gives each architecture, not with what the segments'
     addresses allow: an `x86_64` image linked with 16 KiB segments goes at 2^12 all the same, so the universal file
     `unsign` restores is the one `lipo` makes of the slices it restores, byte for byte.
     */
    func testUnsignLaysTheUniversalFileOutAsLipoAlignsIt() throws {
        let directory = try self.directory("unsign-alignment")
        defer {
            try? FileManager.default.removeItem(at: directory)
        }
        let x86 = try compile("x86_64", in: directory, ["-arch", "x86_64", "-Wl,-segalign,0x4000"])
        let arm = try compile("arm64", in: directory, ["-arch", "arm64"])
        let universal = directory / "universal"
        try XCTSkipUnless(execute("/usr/bin/xcrun", ["lipo", "-create", x86.path, arm.path, "-output", universal.path]), "cannot run lipo")
        guard case let .fat(archs) = try Universal.open(File(path: universal.path)) else {
            return XCTFail("a universal file")
        }
        XCTAssertEqual(archs.map(\.align), [12, 14])
        _ = try codesign(["-s", "-", universal.path])
        let reporter = Reporter(console: Console())
        let artifacts = try Thinner.lines(for: universal.path, exact: false, unsign: true, unpack: false, write: true, reporter: reporter).map(\.text)
        XCTAssertEqual(Set(artifacts), Set(["universal_x86_64", "universal_x86_64_unsigned", "universal_arm64", "universal_arm64_unsigned"].map { (directory / $0).path }))
        XCTAssertEqual(reporter.errorCount, 0)
        let expected = directory / "expected"
        try XCTSkipUnless(execute("/usr/bin/xcrun", ["lipo", "-create", (directory / "universal_x86_64_unsigned").path, (directory / "universal_arm64_unsigned").path, "-output", expected.path]), "cannot run lipo")
        XCTAssertEqual(try self.hashLines(universal.path, ["--unsign"]).last, try ByteHash.sha256.digest(Data(contentsOf: expected)))
    }

    /**
     `__LINKEDIT`'s vmsize is restored as the tool that last wrote the segment left it, which signing rounds to 16 KiB
     and keeps nothing of: the page ld64 aligns segments to for an image with a local symbol; the segment's file size
     for one `strip` emptied of them, as `strip` wrote it through cctools 1009, here today's stripped image reshaped so
     and given Xcode 15.2's linker, ld64 1022.1, for its own; 16 KiB for one whose linker is ld64 1115 or later, as the
     `strip` beside it has written it since cctools 1010, today's. Each, signed by `codesign`, comes back byte for byte.
     */
    func testUnsignRestoresTheLinkeditSizeAsStripOrTheLinkerLeftIt() throws {
        let directory = try self.directory("linkedit-size")
        defer {
            try? FileManager.default.removeItem(at: directory)
        }
        for arch in ["x86_64", "arm64"] {
            let linked = try compile("linked-\(arch)", in: directory, ["-arch", arch])
            let stripped = directory / "stripped-\(arch)"
            try FileManager.default.copyItem(at: linked, to: stripped)
            try XCTSkipUnless(execute("/usr/bin/xcrun", ["strip", stripped.path]), "cannot run strip")
            let image = try XCTUnwrap(MachO(File(path: linked.path)))
            XCTAssertFalse(image.isStripped, arch)
            XCTAssertEqual(image.linkeditSizeRounding, image.segmentAlignment, arch)
            let strippedImage = try XCTUnwrap(MachO(File(path: stripped.path)))
            XCTAssertTrue(strippedImage.isStripped, arch)
            XCTAssertEqual(strippedImage.linkeditSizeRounding, 0x4000, "\(arch): today's strip rounds 64-bit to 16 KiB")
            let linkedit = try XCTUnwrap(strippedImage.findSegment("__LINKEDIT"))
            let segment = try linkedit.load(segment_command_64.self)
            XCTAssertEqual(segment.vmsize, 0x4000, arch)

            // The stripped image as strip left it through cctools 1009: the file size, its linker ld64 1022.1.
            var old = try Data(contentsOf: stripped)
            let vmsize = try linkedit.data.startIndex + XCTUnwrap(MemoryLayout<segment_command_64>.offset(of: \.vmsize))
            old.replaceSubrange(vmsize ..< vmsize + 8, with: withUnsafeBytes(of: segment.filesize.littleEndian) { Data($0) })
            XCTAssertNotNil(strippedImage.linkerVersion, arch)
            let build = try XCTUnwrap(strippedImage.findCommand(UInt32(LC_BUILD_VERSION)))
            let tools = build.data.startIndex + MemoryLayout<build_version_command>.size
            let linker = try tools + XCTUnwrap((0 ..< Int(XCTUnwrap(build.payload(as: build_version_command.self)).ntools)).first { old[tools + $0 * 8] == UInt8(TOOL_LD) }) * 8 + 4
            old.replaceSubrange(linker ..< linker + 4, with: withUnsafeBytes(of: UInt32(0x03fe_0100).littleEndian) { Data($0) })
            let older = directory / "older-\(arch)"
            try old.write(to: older)
            XCTAssertEqual(try XCTUnwrap(MachO(File(path: older.path))).linkeditSizeRounding, 1, arch)

            for original in [linked, stripped, older] {
                let name = "\(arch) \(original.lastPathComponent)"
                let data = try Data(contentsOf: original)
                let signed = try self.codesignedFile(data, in: directory)
                XCTAssertEqual(try XCTUnwrap(MachO(File(path: signed.path))).findSegment("__LINKEDIT")?.load(segment_command_64.self).vmsize, 0x4000, "\(name): codesign rounds to 16 KiB")
                XCTAssertEqual(try self.hashLines(signed.path, ["--unsign"]).last, try ByteHash.sha256.digest(data), name)
                XCTAssertEqual(try Thinner.lines(for: signed.path, exact: false, unsign: true, unpack: false, write: true, reporter: Reporter(console: Console())).map(\.text), [signed.path + "_unsigned"], name)
                XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: signed.path + "_unsigned")), data, name)
            }
        }
    }

    /**
     A dylib with no local symbol is the linker's, not `strip`'s, while it has an indirect symbol table: `strip` writes
     the `radr://5614542` placeholder beside one whenever no local symbol is left, so `strip -x` tells it stripped. And an
     image that records no linker, built for macOS 10.13 with `LC_VERSION_MIN_MACOSX`, is dated by its SDK, today's:
     `strip` rounds its `__LINKEDIT` to 16 KiB. Each, signed by `codesign`, comes back byte for byte.
     */
    func testADylibAndAnOldDeploymentTargetAreToldStrippedAsStripLeavesThem() throws {
        let directory = try self.directory("dylib-old")
        defer {
            try? FileManager.default.removeItem(at: directory)
        }
        let dylib = try compile("calling.dylib", in: directory, source: "#include <stdio.h>\nvoid hello(void) { puts(\"hi\"); }\n", ["-arch", "x86_64", "-dynamiclib"])
        let old = try compile("old", in: directory, ["-arch", "x86_64", "-mmacosx-version-min=10.13"])
        XCTAssertNil(try XCTUnwrap(MachO(File(path: old.path))).findCommand(UInt32(LC_BUILD_VERSION)), "LC_VERSION_MIN_MACOSX dates it")
        for (linked, strip) in [(dylib, ["-x"]), (old, [])] {
            let name = linked.lastPathComponent
            let image = try XCTUnwrap(MachO(File(path: linked.path)))
            XCTAssertFalse(image.isStripped, name)
            XCTAssertEqual(image.linkeditSizeRounding, 0x1000, name)
            let stripped = directory / "stripped-\(name)"
            try FileManager.default.copyItem(at: linked, to: stripped)
            try XCTSkipUnless(execute("/usr/bin/xcrun", ["strip"] + strip + [stripped.path]), "cannot run strip")
            let strippedImage = try XCTUnwrap(MachO(File(path: stripped.path)))
            XCTAssertTrue(strippedImage.isStripped, name)
            XCTAssertEqual(strippedImage.linkeditSizeRounding, 0x4000, name)
            XCTAssertEqual(try XCTUnwrap(strippedImage.findSegment("__LINKEDIT")).load(segment_command_64.self).vmsize, 0x4000, name)
            for original in [linked, stripped] {
                let data = try Data(contentsOf: original)
                let signed = try self.codesignedFile(data, in: directory)
                XCTAssertEqual(try self.hashLines(signed.path, ["--unsign"]).last, try ByteHash.sha256.digest(data), original.lastPathComponent)
            }
        }
    }

    /**
     A thin file cut short of an empty segment within a page is padded with zeros up to it, and the padding said; when
     the padded file still fails to parse, a second empty segment lying a page or more past the end, the padding is
     said before the error, which names the padded size, under thinr -i as under --exact.
     */
    func testThePaddingIsSaidBeforeTheErrorAPaddedFileEndsIn() throws {
        let directory = try self.directory("padded-error")
        defer {
            try? FileManager.default.removeItem(at: directory)
        }
        var data = try Data(contentsOf: compile("program", in: directory, ["-arch", "x86_64", "-Wl,-headerpad,0x800"]))
        let end = data.count
        func segment(_ name: String, at fileoff: Int) -> Data {
            var command = Data()
            [UInt32(LC_SEGMENT_64), 72].forEach { command.appendUInt32($0) }
            command.append(Data(name.utf8)); command.append(Data(count: 16 - name.utf8.count))
            [UInt64(0x2000_0000) + UInt64(fileoff), 0, UInt64(fileoff), 0].forEach { command.appendUInt64($0) }
            [UInt32(1), 1, 0, 0].forEach { command.appendUInt32($0) }
            return command
        }
        data = appending(segment("__PAD2", at: end + 0x6000), to: appending(segment("__PAD1", at: end + 0x10), to: data))
        let file = directory / "cut"
        try data.write(to: file)
        let (status, errors) = try runFashion(["thinr", "-i", file.path])
        XCTAssertEqual(status, 2)
        XCTAssertEqual(errors, [
            "fashion: \(file.path): cut short of its last page, 0x10 bytes before __PAD1 at \((end + 0x10).hex): padded with zeros",
            "fashion: \(file.path): Invalid Mach-O: segment __PAD2 at offset \((end + 0x6000).hex) with size 0x0 is outside the \((end + 0x10).hex)-byte slice",
        ])
    }

    /**
     An executable with no local symbol to show for it is told stripped by its global symbols: a program with none at
     all, one calling `puts` through a stub, and one `ld -x` emptied of them keep `_main` beside `__mh_execute_header`
     and get the linker's page back, 4 KiB on `x86_64` where today's `strip` writes 16 KiB; through `strip`, they keep
     what it keeps alone, `__mh_execute_header`, a weak definition, the `radr://5614542` placeholder written for the
     stub's sake, and get the 16 KiB. Each, signed by `codesign`, comes back byte for byte.
     */
    func testAnExecutableWithoutLocalSymbolsIsToldStrippedByItsGlobalOnes() throws {
        let directory = try self.directory("no-locals")
        defer {
            try? FileManager.default.removeItem(at: directory)
        }
        let plain = try compile("plain", in: directory, source: "int main(void) { return 0; }\n", ["-arch", "x86_64"])
        let calling = try compile("calling", in: directory, source: "#include <stdio.h>\nint main(void) { puts(\"hi\"); return 0; }\n", ["-arch", "x86_64"])
        let emptied = try compile("emptied", in: directory, ["-arch", "x86_64", "-Wl,-x"])
        let weak = try compile("weak", in: directory, source: "__attribute__((weak)) int weak(int x) { return x + 1; }\nint (*pointer)(int) = weak;\nint main(void) { return pointer(1); }\n", ["-arch", "x86_64"])
        func symbols(_ url: URL) throws -> (locals: UInt32, globals: UInt32, stripped: Bool, rounding: Int?, vmsize: UInt64) {
            let image = try XCTUnwrap(MachO(File(path: url.path)))
            let dysymtab = try XCTUnwrap(image.findCommand(UInt32(LC_DYSYMTAB))?.payload(as: dysymtab_command.self))
            let linkedit = try XCTUnwrap(image.findSegment("__LINKEDIT")).load(segment_command_64.self)
            return (dysymtab.nlocalsym, dysymtab.nextdefsym, image.isStripped, image.linkeditSizeRounding, linkedit.vmsize)
        }
        for linked in [plain, calling, emptied] {
            let symbols = try symbols(linked)
            XCTAssertEqual(symbols.locals, 0, linked.lastPathComponent)
            XCTAssertEqual(symbols.globals, 2, "\(linked.lastPathComponent): __mh_execute_header and _main")
            XCTAssertFalse(symbols.stripped, linked.lastPathComponent)
            XCTAssertEqual(symbols.rounding, 0x1000, linked.lastPathComponent)
            XCTAssertEqual(symbols.vmsize, 0x1000, linked.lastPathComponent)
        }

        var stripped: [URL] = []
        for linked in [plain, calling, weak] {
            let copy = directory / "stripped-\(linked.lastPathComponent)"
            try FileManager.default.copyItem(at: linked, to: copy)
            try XCTSkipUnless(execute("/usr/bin/xcrun", ["strip", copy.path]), "cannot run strip")
            stripped.append(copy)
            let symbols = try symbols(copy)
            XCTAssertEqual(symbols.locals, linked == calling ? 1 : 0, "\(copy.lastPathComponent): the placeholder for the stub")
            XCTAssertEqual(symbols.globals, linked == weak ? 2 : 1, "\(copy.lastPathComponent): __mh_execute_header, a weak definition")
            XCTAssertTrue(symbols.stripped, copy.lastPathComponent)
            XCTAssertEqual(symbols.rounding, 0x4000, copy.lastPathComponent)
            XCTAssertEqual(symbols.vmsize, 0x4000, copy.lastPathComponent)
        }

        for original in [plain, calling, emptied] + stripped {
            let name = original.lastPathComponent
            let data = try Data(contentsOf: original)
            let signed = try self.codesignedFile(data, in: directory)
            XCTAssertEqual(try self.hashLines(signed.path, ["--unsign"]).last, try ByteHash.sha256.digest(data), name)
            XCTAssertEqual(try Thinner.lines(for: signed.path, exact: false, unsign: true, unpack: false, write: true, reporter: Reporter(console: Console())).map(\.text), [signed.path + "_unsigned"], name)
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: signed.path + "_unsigned")), data, name)
        }
    }

    /**
     `LC_BUILD_VERSION` names the linker among its tools, read within the command whatever ntools claims: a command of
     24 bytes claiming four billion tools names none, at once, and one claiming a tool past its end names what it holds.
     */
    func testTheLinkerVersionIsReadWithinTheCommand() throws {
        func image(ntools: UInt32, tools: [(UInt32, UInt32)]) throws -> MachO {
            var data = Data()
            data.appendUInt32(MH_MAGIC_64)
            data.appendInt32(CPU_TYPE_X86_64)
            data.appendInt32(0)
            data.appendUInt32(UInt32(MH_EXECUTE))
            data.appendUInt32(1) // ncmds
            data.appendUInt32(UInt32(24 + 8 * tools.count)) // sizeofcmds
            data.appendUInt32(0)
            data.appendUInt32(0)
            data.appendUInt32(UInt32(LC_BUILD_VERSION))
            data.appendUInt32(UInt32(24 + 8 * tools.count))
            data.appendUInt32(UInt32(PLATFORM_MACOS)); data.appendUInt32(0x000e_0000); data.appendUInt32(0x000e_0000); data.appendUInt32(ntools) // platform, minos, sdk, ntools
            for (tool, version) in tools {
                data.appendUInt32(tool); data.appendUInt32(version)
            }
            return try XCTUnwrap(MachO(File(data: data)))
        }
        XCTAssertEqual(try image(ntools: 2, tools: [(UInt32(TOOL_CLANG), 0x0001_0000), (UInt32(TOOL_LD), 0x045b_0000)]).linkerVersion, 0x045b_0000)
        XCTAssertNil(try image(ntools: 1, tools: [(UInt32(TOOL_CLANG), 0x0001_0000)]).linkerVersion)
        XCTAssertNil(try image(ntools: 0xffff_ffff, tools: []).linkerVersion)
        XCTAssertEqual(try image(ntools: 2, tools: [(UInt32(TOOL_LD), 0x045b_0000)]).linkerVersion, 0x045b_0000, "a tool claimed past the command")
    }

    /// `data` written and signed ad hoc into a file of its own in `directory`, kept.
    private func codesignedFile(_ data: Data, in directory: URL) throws -> URL {
        let url = directory / "codesigned-\(UUID())"
        try data.write(to: url)
        _ = try codesign(["-f", "-s", "-", url.path])
        return url
    }

    /**
     One run with --unsign leaves the signed slices beside the unsigned ones. A later run with other flags edits
     the artifacts of an earlier one too, thin files all: what it makes of `ls_x86_64` is named and made as one run
     makes it of `ls`, `ls_x86_64_unsigned`, so it is found in place. Running either again makes nothing more.
     */
    func testRunsWithOtherFlagsConvergeOnTheSameArtifacts() throws {
        let directory = try self.directory("converge")
        defer {
            try? FileManager.default.removeItem(at: directory)
        }
        let (_, _, slices) = try self.universalLs(in: directory)
        let expected = (["ls"] + slices.flatMap { ["ls_\($0.name)", "ls_\($0.name)_unsigned"] }).sorted()

        XCTAssertEqual(try Thinner.parse(["--write", "--unsign", directory.path]).scan(), 0)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path).sorted(), expected)
        XCTAssertEqual(try Thinner.parse(["--write", directory.path]).scan(), 0)
        XCTAssertEqual(try Thinner.parse(["--write", "--unsign", directory.path]).scan(), 0)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path).sorted(), expected)

        // The same files, made of ls_x86_64 and the others alone: thin over ls finds them in place.
        try FileManager.default.removeItem(at: directory)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        _ = try self.universalLs(in: directory)
        XCTAssertEqual(try Thinner.parse(["--write", directory.path]).scan(), 0)
        try FileManager.default.removeItem(at: directory / "ls")
        XCTAssertEqual(try Thinner.parse(["--write", "--unsign", directory.path]).scan(), 0)
        try FileManager.default.copyItem(at: URL(fileURLWithPath: "/bin/ls"), to: directory / "ls")
        XCTAssertEqual(try Thinner.parse(["--write", "--unsign", directory.path]).scan(), 0)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path).sorted(), expected)
    }

    /**
     `/bin/ls` as Apple signed it, and signed again ad hoc: `unsign` gives both the same artifacts and digests, a
     cdhash included, though their signatures and the `__LINKEDIT` vmsize the signatures needed differ.
     */
    func testUnsignGivesCopiesSignedByDifferentIdentitiesTheSameBytes() throws {
        let directory = try self.directory("unsign-identities")
        defer {
            try? FileManager.default.removeItem(at: directory)
        }
        let (ls, data, slices) = try self.universalLs(in: directory)
        let resigned = directory / "resigned"
        try self.codesigned(data, in: directory).write(to: resigned)
        XCTAssertNotEqual(try self.hashLines(ls.path), try self.hashLines(resigned.path))

        for arguments in [[], ["--slices"], ["--algo", "cdhash"]] {
            // The files as they are differ by their signatures, and so does the signed state of each slice under
            // --slices: the unsigned states, the whole file's then each slice's, every other line, agree.
            let unsigned = { (lines: [String]) in arguments == ["--slices"] ? lines.enumerated().filter { $0.offset % 2 == 1 }.map(\.element) : arguments.isEmpty ? Array(lines.dropFirst()) : lines }
            XCTAssertEqual(try unsigned(self.hashLines(ls.path, ["--unsign"] + arguments)), try unsigned(self.hashLines(resigned.path, ["--unsign"] + arguments)), "\(arguments)")
        }
        for file in [ls, resigned] {
            XCTAssertEqual(try Thinner.lines(for: file.path, exact: false, unsign: true, unpack: false, write: true, reporter: Reporter(console: Console())).count, 2 * slices.count)
        }
        // Each ends with its string table, without the padding that aligned the signature after it.
        for slice in slices {
            let artifact = try Data(contentsOf: directory / "ls_\(slice.name)_unsigned")
            XCTAssertEqual(artifact, try Data(contentsOf: directory / "resigned_\(slice.name)_unsigned"), slice.name)
            let symtab = try XCTUnwrap(MachO(artifact)?.findCommand(UInt32(LC_SYMTAB))).load(symtab_command.self)
            XCTAssertEqual(artifact.count, Int(symtab.stroff + symtab.strsize), slice.name)
        }
    }

    /**
     Up to 7 bytes after the signature go with it, as `codesign` lets them go. Any more would be cut off with it, so
     hash mode's --unsign reports the file in Security's words and hashes nothing, as codesign fails too, where thinr
     --unsign cuts them off first, as --exact would, the cut a state of its own: the slice as it is, cut, then without
     its signature, what thinr --exact --unsign writes, found in place then; unsign writes the whole, named for it.
     */
    func testUnsignCutsAppendedBytesAsNeeded() throws {
        let directory = try self.directory("unsign-appended")
        defer {
            try? FileManager.default.removeItem(at: directory)
        }
        let (plain, slice) = try self.fatX86(appended: Data())
        try plain.write(to: directory / "plain")
        XCTAssertEqual(try Thinner.lines(for: (directory / "plain").path, exact: false, unsign: true, unpack: false, write: true, reporter: Reporter(console: Console())).count, 2)
        let unsigned = try Data(contentsOf: directory / "plain_x86_64_unsigned")
        let (seven, _) = try self.fatX86(appended: Data(repeating: 0x4a, count: 7))
        try seven.write(to: directory / "seven")
        let junk = Data(repeating: 0x4a, count: 8)
        let (eight, _) = try self.fatX86(appended: junk)
        let file = directory / "eight"
        try eight.write(to: file)
        let artifact = directory / "eight_x86_64_exact_unsigned"

        XCTAssertEqual(try Thinner.lines(for: (directory / "seven").path, exact: false, unsign: true, unpack: false, write: true, reporter: Reporter(console: Console())).count, 2)
        XCTAssertEqual(try Data(contentsOf: directory / "seven_x86_64_unsigned"), unsigned)

        let oracle = directory / "oracle"
        try (slice + junk).write(to: oracle)
        XCTAssertThrowsError(try codesign(["--remove-signature", oracle.path]))
        let reporter = Reporter(console: Console())
        let states = [(directory / "eight_x86_64").path, (directory / "eight_x86_64_exact").path, artifact.path]
        XCTAssertEqual(try Thinner.lines(for: file.path, exact: false, unsign: true, unpack: false, write: true, reporter: reporter).map(\.text), states)
        XCTAssertEqual(reporter.errorCount, 0)
        XCTAssertEqual(try Data(contentsOf: directory / "eight_x86_64"), slice + junk)
        XCTAssertEqual(try Data(contentsOf: directory / "eight_x86_64_exact"), slice)
        XCTAssertEqual(try Data(contentsOf: artifact), unsigned)
        XCTAssertFalse(FileManager.default.fileExists(atPath: (directory / "eight_x86_64_unsigned").path))
        // Hash mode cuts as needed as thinr does, and says nothing of it.
        let (status, errors) = try runFashion(["--unsign", file.path])
        XCTAssertEqual(status, 0)
        XCTAssertEqual(errors, [])
        XCTAssertEqual(try runFashion(["thinr", "--unsign", file.path]).status, 0)

        // The same states with the flag, found in place; the whole file as unsign writes it, named for its slice.
        XCTAssertEqual(try Thinner.lines(for: file.path, exact: true, unsign: true, unpack: false, write: true, reporter: Reporter(console: Console())).map(\.text), states)
        XCTAssertEqual(try Unsigner.lines(for: file.path, write: false, reporter: Reporter(console: Console())).map(\.text), [(directory / "eight_exact_unsigned").path])
        // --slices digests the file as it is, then whole as the edits left it, then every state of the slice, as the
        // table places it, cut, then cut and unsigned: the last is what plain's unsigned slice is.
        XCTAssertEqual(try self.hashLines(file.path, ["--unsign", "--exact", "--slices"]).count, 5)
        XCTAssertEqual(try self.hashLines(file.path, ["--unsign", "--exact", "--slices"]).last, try self.hashLines((directory / "plain").path, ["--unsign", "--slices"]).last)
    }

    /**
     Wherever `LC_CODE_SIGNATURE` sits among the load commands, the others close up behind it and `__LINKEDIT`, moved
     with them, is restored: the image is the one where the command comes last, unsigned. codesign itself writes the
     new `__LINKEDIT` size 16 bytes past the command that moved, over its nsects and flags.
     */
    func testUnsignClosesUpTheCommandsAfterTheSignature() throws {
        let directory = try self.directory("unsign-moved")
        defer {
            try? FileManager.default.removeItem(at: directory)
        }
        let (_, signed) = try self.fatX86(appended: Data())
        let image = try XCTUnwrap(MachO(signed))
        let signature = try XCTUnwrap(image.findCommand(UInt32(LC_CODE_SIGNATURE)))
        let table = try XCTUnwrap(image.loadCommands.first).data.startIndex ..< signature.data.endIndex
        XCTAssertEqual(table.upperBound, MemoryLayout<mach_header_64>.size + image.sizeofcmds)
        var moved = signed
        moved.replaceSubrange(table, with: signature.data + image.loadCommands.filter { $0.cmd != UInt32(LC_CODE_SIGNATURE) }.reduce(Data()) { $0 + $1.data })
        try signed.write(to: directory / "last")
        try moved.write(to: directory / "first")

        for name in ["last", "first"] {
            XCTAssertEqual(try Thinner.lines(for: (directory / name).path, exact: false, unsign: true, unpack: false, write: true, reporter: Reporter(console: Console())).map(\.text), [(directory / "\(name)_unsigned").path])
        }
        XCTAssertEqual(try Data(contentsOf: directory / "first_unsigned"), try Data(contentsOf: directory / "last_unsigned"))
    }

    /**
     A big-endian image, 32-bit and 64-bit, signed by codesign, given back byte for byte: its `__LINKEDIT` ends on
     the 16-byte boundary where codesign puts the signature, so no padding is left to tell, and zeros follow its
     load commands, as a linker leaves room there, for the `LC_CODE_SIGNATURE` codesign adds.
     */
    func testUnsignRestoresBigEndianImages() throws {
        let directory = try self.directory("unsign-ppc")
        defer {
            try? FileManager.default.removeItem(at: directory)
        }
        for (name, is64) in [("ppc", false), ("ppc64", true)] {
            var original = makeBigEndianMachO(is64: is64, linkeditSize: 16)
            let commands = try (is64 ? MemoryLayout<mach_header_64>.size : MemoryLayout<mach_header>.size) + XCTUnwrap(MachO(original)).sizeofcmds
            original.replaceSubrange(commands ..< commands + 16, with: Data(count: 16))
            let file = directory / name
            try self.codesigned(original, in: directory).write(to: file)

            XCTAssertEqual(try Thinner.lines(for: file.path, exact: false, unsign: true, unpack: false, write: true, reporter: Reporter(console: Console())).map(\.text), ["\(file.path)_unsigned"])
            XCTAssertEqual(try Data(contentsOf: directory / "\(name)_unsigned"), original, name)
        }
    }

    /**
     hash mode's --slices digests every state thinr writes, labeled by the artifact's name, `x86_64, unsigned`, so the digests are those
     of the files thinr --write leaves and match them; a file in place of an artifact that holds other bytes is hashed
     too, under its own path, and said on standard error, while one that holds the state is noted in the log alone.
     */
    func testSlicesDigestEveryStateAndAFileInPlace() throws {
        let directory = try self.directory("states")
        defer {
            try? FileManager.default.removeItem(at: directory)
        }
        let (ls, _, slices) = try self.universalLs(in: directory)
        let reporter = Reporter(console: Console())
        let artifacts = try Thinner.lines(for: ls.path, exact: false, unsign: true, unpack: false, write: true, reporter: reporter).map(\.text)
        XCTAssertEqual(artifacts, slices.flatMap { ["\(ls.path)_\($0.name)", "\(ls.path)_\($0.name)_unsigned"] })
        func hashed(_ arguments: [String] = []) throws -> (said: [String], digests: [String], subjects: [String]) {
            let lines = try Digester(Hasher.parse([ls.path, "--slices", "--unsign"] + arguments)).lines(for: ls.path, reporter: reporter)
            let printed = lines.filter { !$0.diagnostic }.map { $0.text.components(separatedBy: "  ") }
            return (lines.filter(\.diagnostic).map(\.text), printed.map { $0.first ?? "" }, printed.map { $0.dropFirst().joined(separator: "  ") })
        }

        // Every artifact in place, byte for byte: the file as it is, then whole as unsign writes it, then one line per
        // state, labeled, its digest the file's, nothing said.
        let inPlace = try hashed()
        XCTAssertEqual(inPlace.said, [])
        XCTAssertEqual(inPlace.subjects, [ls.path, "\(ls.path) (unsigned)"] + slices.flatMap { ["\(ls.path) (\($0.name))", "\(ls.path) (\($0.name), unsigned)"] })
        XCTAssertEqual(inPlace.digests.first, try self.sha256(Data(contentsOf: ls)))
        XCTAssertEqual(inPlace.digests.dropFirst(2), try artifacts.map { try self.sha256(Data(contentsOf: URL(fileURLWithPath: $0))) }[...])

        // Other bytes under an artifact's name: said, with both identities, and hashed under its own path.
        let stale = Data("stale".utf8)
        try stale.write(to: URL(fileURLWithPath: artifacts[1]))
        let differs = try hashed()
        XCTAssertEqual(differs.said.count, 1)
        XCTAssertTrue(differs.said[0].hasPrefix("fashion: \(artifacts[1]): exists and differs, 5 bytes, sha256 \(self.sha256(stale)) where the state is "), differs.said[0])
        XCTAssertEqual(differs.subjects, inPlace.subjects[0 ... 3] + [artifacts[1]] + inPlace.subjects[4...])
        XCTAssertEqual(differs.digests[4], self.sha256(stale))
        XCTAssertEqual(reporter.errorCount, 0)

        // Plain hash mode names its one state too, the file as unsign writes it whole, and compares that artifact:
        // in place and the same, nothing said; stale, said and hashed under its own path.
        let whole = (directory / "ls_unsigned").path
        XCTAssertEqual(try Unsigner.lines(for: ls.path, write: true, reporter: reporter).map(\.text), [whole])
        let unsigned = try Digester(Hasher.parse([ls.path, "--unsign"])).lines(for: ls.path, reporter: reporter)
        XCTAssertEqual(unsigned.map(\.text), try ["\(self.sha256(Data(contentsOf: ls)))  \(ls.path)", "\(self.sha256(Data(contentsOf: URL(fileURLWithPath: whole))))  \(ls.path) (unsigned)"])
        try stale.write(to: URL(fileURLWithPath: whole))
        let staleWhole = try Digester(Hasher.parse([ls.path, "--unsign"])).lines(for: ls.path, reporter: reporter)
        XCTAssertEqual(staleWhole.filter(\.diagnostic).count, 1)
        XCTAssertEqual(staleWhole.filter { !$0.diagnostic }.map(\.text).last, "\(self.sha256(stale))  \(whole)")
        XCTAssertEqual(try Digester(Hasher.parse([ls.path])).lines(for: ls.path, reporter: reporter).map(\.text).count, 1)

        // --symhash walks the same states, without the whole file's line: the symbols of each slice, signed then
        // unsigned, the same; the stale file is said, and has no symbols to print.
        let symbols = try Digester(Hasher.parse([ls.path, "--symhash", "--unsign"])).lines(for: ls.path, reporter: reporter)
        XCTAssertEqual(symbols.filter(\.diagnostic).count, 1)
        let symhashed = symbols.filter { !$0.diagnostic }.map { $0.text.components(separatedBy: "  ") }
        XCTAssertEqual(symhashed.map { $0.dropFirst().joined(separator: "  ") }, slices.flatMap { ["\(ls.path) (\($0.name))", "\(ls.path) (\($0.name), unsigned)"] })
        for signed in stride(from: 0, to: symhashed.count, by: 2) {
            XCTAssertEqual(symhashed[signed].first, symhashed[signed + 1].first, "\(symhashed[signed])")
        }

        // Both match: the state by its digest, the file in place by what it holds; the warning is said either way.
        func matched(_ arguments: [String]) throws -> [String] {
            try self.hashLines(ls.path, ["--slices"] + arguments).filter { !$0.hasPrefix("fashion: ") }
        }
        XCTAssertEqual(try matched(["--unsign", "--match", inPlace.digests[2]]), [ls.path])
        XCTAssertEqual(try matched(["--unsign", "--match", self.sha256(stale)]), [ls.path])
        XCTAssertEqual(try matched(["--match", self.sha256(stale)]), [])
    }

    /**
     Two slices of one architecture, which the kernel refuses, come out under names of their own, the second numbered,
     `ls_x86_64` and `ls_x86_64_2`, and their states after them; hash mode's --slices labels their digests the same.
     */
    func testSlicesOfOneArchitectureAreNamedApart() throws {
        let directory = try self.directory("twice")
        defer {
            try? FileManager.default.removeItem(at: directory)
        }
        let slice = try self.lsX86()
        let x86 = (cpuType: CPU_TYPE_X86_64, cpuSubtype: CPU_SUBTYPE_X86_64_ALL, data: slice, align: 12)
        let file = directory / "ls"
        try makeUniversal([x86, x86]).write(to: file)
        let reporter = Reporter(console: Console())
        XCTAssertEqual(try Thinner.lines(for: file.path, exact: false, unsign: true, unpack: false, write: true, reporter: reporter).map(\.text), [file.path + "_x86_64", file.path + "_x86_64_unsigned", file.path + "_x86_64_2", file.path + "_x86_64_2_unsigned"])
        XCTAssertEqual(try Data(contentsOf: directory / "ls_x86_64_2"), slice)
        XCTAssertEqual(try Data(contentsOf: directory / "ls_x86_64_2_unsigned"), try Data(contentsOf: directory / "ls_x86_64_unsigned"))
        let labeled = try Digester(Hasher.parse([file.path, "--slices", "--algo", "sha256"])).lines(for: file.path, reporter: reporter).map { $0.text.components(separatedBy: "  ").last ?? "" }
        XCTAssertEqual(labeled, [file.path, "\(file.path) (x86_64)", "\(file.path) (x86_64_2)"])
        XCTAssertEqual(reporter.errorCount, 0)
    }

    /**
     A stripped image's symbol tables are read within the image, and its symbols within the tables: a count of global
     symbols past the table, or a table past the image, as a crafted header has them, is read as unstripped rather
     than read past, into another slice of a universal file.
     */
    func testAStrippedImagesTablesAreReadWithinTheImage() throws {
        let directory = try self.directory("tables")
        defer {
            try? FileManager.default.removeItem(at: directory)
        }
        let built = try compile("built", in: directory, source: "int main(void) { return 0; }\n", ["-arch", "x86_64"])
        try XCTSkipUnless(execute("/usr/bin/xcrun", ["strip", built.path]), "cannot run strip")
        let data = try Data(contentsOf: built)
        let image = try XCTUnwrap(MachO(File(data: data)))
        XCTAssertTrue(image.isStripped)
        let dysymtab = try XCTUnwrap(image.findCommand(UInt32(LC_DYSYMTAB)))
        let symtab = try XCTUnwrap(image.findCommand(UInt32(LC_SYMTAB)))
        var globals = data
        globals.replaceSubrange(dysymtab.data.startIndex + 20 ..< dysymtab.data.startIndex + 24, with: withUnsafeBytes(of: UInt32.max.littleEndian) { Data($0) }) // nextdefsym
        XCTAssertFalse(try XCTUnwrap(MachO(File(data: globals))).isStripped)
        var past = data
        past.replaceSubrange(symtab.data.startIndex + 8 ..< symtab.data.startIndex + 12, with: withUnsafeBytes(of: UInt32(data.count).littleEndian) { Data($0) }) // symoff
        XCTAssertFalse(try XCTUnwrap(MachO(File(data: past))).isStripped)
    }
}
