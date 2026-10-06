@testable import fashion
import MachO
import XCTest

/**
 The exit-code contract: 0 when every path hashed, 2 when any path could not be hashed.
 */
final class RunnerTests: XCTestCase {
    private func run(_ url: URL, algorithm: Algorithm = .sha256, slices: Bool = false) throws -> Int32 {
        let arguments = [url.path, "--algo", algorithm.rawValue, "--quiet", "--sort"] + (slices ? ["--slices"] : [])
        return try Fashion.parse(arguments).scan()
    }

    /**
     A thin arm64 Mach-O with one LC_SYMTAB, whose declared load-command table is `padding` bytes longer than the command.
     */
    private func machO(padding: UInt32 = 0) -> Data {
        var data = Data()
        data.appendUInt32(MH_MAGIC_64)
        data.appendInt32(CPU_TYPE_ARM64)
        data.appendInt32(0)
        data.appendUInt32(UInt32(MH_EXECUTE))
        data.appendUInt32(1) // ncmds
        data.appendUInt32(24 + padding) // sizeofcmds
        data.appendUInt32(0)
        data.appendUInt32(0)
        data.appendUInt32(UInt32(LC_SYMTAB))
        data.appendUInt32(24)
        data.appendUInt32(56) // symoff
        data.appendUInt32(0) // nsyms
        data.appendUInt32(56) // stroff
        data.appendUInt32(0) // strsize
        data.append(Data(repeating: 0, count: Int(padding)))
        return data
    }

    /**
     A one-architecture universal binary wrapping `slice` at offset 64, declared `size` bytes long when the file is
     extended past `slice` afterwards.
     */
    private func fat(wrapping slice: Data, size: Int? = nil) -> Data {
        var data = Data()
        data.appendUInt32BE(FAT_MAGIC)
        data.appendUInt32BE(1)
        data.appendInt32BE(CPU_TYPE_ARM64)
        data.appendInt32BE(0)
        data.appendUInt32BE(64)
        data.appendUInt32BE(UInt32(size ?? slice.count))
        data.appendUInt32BE(0)
        data.append(Data(repeating: 0, count: 64 - data.count))
        data.append(slice)
        return data
    }

    private func write(_ data: Data, name: String) throws -> URL {
        let url = FileManager.default.temporaryDirectory / "fashion-runner-\(name)-\(UUID())"
        try data.write(to: url)
        return url
    }

    func testSortedOutputDoesNotDependOnJobs() throws {
        // Hash threads finish out of order, the large files last: --sort must still print in path order.
        let binary = try fashionExecutable()
        let directory = FileManager.default.temporaryDirectory / "fashion-runner-sort-\(UUID())"
        try FileManager.default.createDirectory(at: directory / "sub", withIntermediateDirectories: true)
        defer {
            try? FileManager.default.removeItem(at: directory)
        }
        for index in 0 ..< 300 {
            let size = index % 25 == 0 ? 4 << 20 : 1
            let name = index % 3 == 0 ? "sub/\(index)" : "f\(index)"
            try Data(repeating: UInt8(index % 256), count: size).write(to: directory / name)
        }

        func run(jobs: Int) throws -> [String] {
            let process = Process()
            process.executableURL = binary
            process.arguments = ["--sort", "-j", "\(jobs)", directory.path]
            let stdout = Pipe()
            process.standardOutput = stdout
            try process.run()
            let output = stdout.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            return String(decoding: output, as: UTF8.self).split(separator: "\n").map(String.init)
        }

        let sequential = try run(jobs: 1)
        XCTAssertEqual(sequential.count, 300)
        let paths = sequential.map { String($0.split(separator: "  ", maxSplits: 1)[1]) }
        XCTAssertEqual(paths, paths.sorted { $0.utf8.lexicographicallyPrecedes($1.utf8) })
        XCTAssertEqual(try run(jobs: 8), sequential)
    }

    func testWellFormedMachOExitsZero() throws {
        let url = try self.write(self.machO(), name: "ok")
        defer {
            try? FileManager.default.removeItem(at: url)
        }

        let exitCode = try self.run(url, algorithm: .cdhash)
        XCTAssertEqual(exitCode, 0)
    }

    func testMalformedMachOSetsExitCode2() throws {
        let url = try self.write(self.machO(padding: 8), name: "bad")
        defer {
            try? FileManager.default.removeItem(at: url)
        }

        // A mode that parses the Mach-O reports it; plain hashing of the raw bytes does not care.
        let parsed = try self.run(url, algorithm: .cdhash)
        XCTAssertEqual(parsed, 2)
        let raw = try self.run(url)
        XCTAssertEqual(raw, 0)
    }

    func testSlicesRejectsMalformedSliceInsideFat() throws {
        // --slices is a Mach-O-aware mode: a broken slice is reported whether or not --exact is set.
        let bad = try self.write(self.fat(wrapping: self.machO(padding: 8)), name: "fat-bad")
        let good = try self.write(self.fat(wrapping: self.machO()), name: "fat-ok")
        defer {
            try? FileManager.default.removeItem(at: bad)
            try? FileManager.default.removeItem(at: good)
        }

        let rejected = try self.run(bad, slices: true)
        XCTAssertEqual(rejected, 2)
        let accepted = try self.run(good, slices: true)
        XCTAssertEqual(accepted, 0)
    }

    func testExactTrimsEachSliceInPlace() throws {
        // --exact ends a slice where it lies in the universal file: with 100 bytes appended inside the slice, the file
        // still hashes whole, and the slice without them.
        let slice = self.machO()
        let fat = self.fat(wrapping: slice + Data(repeating: 0x41, count: 100))
        let url = try self.write(fat, name: "fat-padded")
        defer {
            try? FileManager.default.removeItem(at: url)
        }

        let digester = try Digester(Fashion.parse([url.path, "--slices", "--exact", "--quiet"]))
        let lines = digester.lines(for: url.path, reporter: Reporter(console: Console()))
        XCTAssertEqual(lines, try [ByteHash.sha256.digest(fat), ByteHash.sha256.digest(slice)])
    }

    func testSlicesHashInPlace() throws {
        // A slice is read from the file at its offset, never copied: a copy made every slice a hash thread held
        // resident at once, gigabytes over /Applications. One larger than any earlier peak of the process shows it.
        let before = try XCTUnwrap(Reporter.peakFootprint())
        let size = Int(before) + 64 << 20
        let url = try self.write(self.fat(wrapping: self.machO(), size: size), name: "fat-big")
        defer {
            try? FileManager.default.removeItem(at: url)
        }
        // Sparse: the slice past its Mach-O header reads back as zeros, without taking memory or disk here.
        XCTAssertEqual(truncate(url.path, off_t(64 + size)), 0)

        XCTAssertEqual(try self.run(url, slices: true), 0)
        // A copy alone would reach `size`; hashing in place adds far less than the 64 MiB above `before`.
        XCTAssertLessThan(try XCTUnwrap(Reporter.peakFootprint()), Int64(size))
    }
}
