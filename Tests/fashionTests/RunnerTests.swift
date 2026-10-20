@testable import fashion
import MachO
import os
import System
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
        XCTAssertEqual(paths, naturallySorted(paths))
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
        let lines = digester.lines(for: url.path, reporter: Reporter(console: Console())).map(\.text)
        XCTAssertEqual(lines, try [ByteHash.sha256.digest(fat), ByteHash.sha256.digest(slice)])
    }

    func testFuzzyMatchTint() throws {
        // Greens by quarters of the way to --score: with 40, a TLSH distance of 0 is full green, then darker each 10.
        func sgr(_ arguments: [String], _ scores: [Int]) throws -> [String?] {
            let digester = try Digester(Fashion.parse(["x"] + arguments))
            return scores.map { digester.matchTint($0).sgr() }
        }
        let greens = ["38;5;46", "38;5;40", "38;5;34", "38;5;28", "38;5;22"]
        XCTAssertEqual(try sgr(["--algo", "tlsh"], [0, 10, 20, 30, 40]), greens)
        XCTAssertEqual(try sgr(["--algo", "ssdeep"], [100, 85, 70, 55, 40]), greens)
        // From a TLSH distance of 300 a match is gray, whatever the threshold, and the greens stop there.
        XCTAssertEqual(try sgr(["--algo", "tlsh", "--score", "1000"], [0, 150, 299, 300, 1000]), ["38;5;46", "38;5;34", "38;5;22", "38;5;245", "38;5;245"])
        // Those false positives count the length: without it, the greens run to the threshold.
        let tlsh = "T13D338D7A3B0DE1A6C29CC134A5EFCB829D63F9151D7863432B91C5792FC86942F21B4B"
        XCTAssertEqual(try sgr(["--algo", "tlsh", "--score", "1000", "--match", tlsh, "--xlen"], [300, 1000]), ["38;5;34", "38;5;22"])
        // A threshold of 100 (ssdeep) or 0 (TLSH) only matches the identical.
        XCTAssertEqual(try sgr(["--algo", "ssdeep", "--score", "100"], [100]), ["38;5;46"])
        XCTAssertEqual(try sgr(["--algo", "tlsh", "--score", "0"], [0]), ["38;5;46"])
        // An exact match has no score: full green, with any algorithm.
        XCTAssertEqual(try Digester(Fashion.parse(["x"])).matchTint(nil).sgr(), "38;5;46")
        XCTAssertEqual(try Digester(Fashion.parse(["x", "--algo", "cdhash"])).matchTint(nil).sgr(), "38;5;46")
    }

    func testExactMatchIsGreen() throws {
        // A digest searched for is full green when found, whatever the algorithm, an ad-hoc cdhash included, which is
        // dimmed otherwise. Without --match, lines keep their own tint.
        let slice = self.machO()
        let url = try self.write(slice, name: "match")
        defer {
            try? FileManager.default.removeItem(at: url)
        }
        func lines(_ arguments: [String]) throws -> [Line] {
            try Digester(Fashion.parse([url.path] + arguments)).lines(for: url.path, reporter: Reporter(console: Console()))
        }

        let sha256 = try XCTUnwrap(ByteHash.sha256.digest(slice))
        XCTAssertEqual(try lines([]).map(\.tint), [.none])
        XCTAssertEqual(try lines(["--match", sha256]).map(\.tint), [.match(distance: 0)])
        XCTAssertEqual(try lines(["--match", sha256.uppercased(), "--quiet"]).map(\.tint), [.match(distance: 0)])
        XCTAssertTrue(try lines(["--match", String(sha256.dropLast())]).isEmpty)

        let cdhash = try XCTUnwrap(CDHash.hash(data: slice))
        XCTAssertEqual(try lines(["--algo", "cdhash"]).map(\.tint), [.adhoc, .adhoc])
        XCTAssertEqual(try lines(["--algo", "cdhash", "--match", String(cdhash.prefix(40))]).map(\.tint), [.match(distance: 0)])
    }

    func testMalformedFileIsRed() {
        // A Mach-O whose load commands run past its end does not parse: red. A file that cannot be read, or changed, is
        // yellow.
        var data = Data()
        [MH_MAGIC_64, UInt32(bitPattern: CPU_TYPE_ARM64), 0, UInt32(MH_EXECUTE), 1, 0x1000, 0, 0].forEach { data.appendUInt32($0) }
        XCTAssertThrowsError(try Universal.open(data: data)) { error in
            XCTAssertEqual(Digester.tint(for: error).sgr(), "31")
        }
        XCTAssertEqual(Digester.tint(for: Errno.permissionDenied).sgr(), "33")
        XCTAssertEqual(Digester.tint(for: FileError.replaced).sgr(), "33")
    }

    func testTLSHCaveatsDoNotFail() throws {
        // A file or slice TLSH makes no digest of is named on stderr, after the slice it is, and the run still succeeds:
        // the universal file has a digest, its mostly zero slice none.
        let tiny = try self.write(Data("tiny file\n".utf8), name: "tlsh-tiny")
        let fat = try self.write(self.fat(wrapping: self.machO()), name: "tlsh-fat")
        defer {
            try? FileManager.default.removeItem(at: tiny)
            try? FileManager.default.removeItem(at: fat)
        }

        let (status, errors) = try runFashion(["--algo", "tlsh", "--slices", "-j", "1", tiny.path, fat.path])
        XCTAssertEqual(status, 0)
        XCTAssertEqual(errors, [
            "fashion: \(tiny.path): TLSH cannot hash: input too small (10 bytes, minimum 50)",
            "fashion: \(fat.path) (arm64): TLSH cannot hash: not enough variation in input",
        ])
        // --quiet keeps them off stderr.
        XCTAssertEqual(try runFashion(["--algo", "tlsh", "--slices", "-j", "1", "-q", tiny.path, fat.path]).errors, [])
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

/**
 The lock-guarded parts of a run, driven from threads the way the walker and the hash threads drive them, with stdout
 and stderr sent into pipes like `fashion | sort 2>errors`, or into a pty like a terminal: every line comes out whole,
 in index order with `--sort`, and the counts add up. The in-process side of the spawned runs above, where
 ThreadSanitizer sees the locking: `swift test --sanitize=thread --scratch-path .build/tsan`.
 */
final class RunnerConcurrencyTests: XCTestCase {
    /**
     The lines `body` writes to the process's `fd` (stdout or stderr), sent into a pipe like `fashion | sort` and read as
     they come, at the writers' QoS, so a full pipe never has a hash thread wait on a lower thread. A Console looks at
     its descriptors once: `body` makes its own.
     */
    private func piped(_ fd: Int32, _ body: () throws -> Void) throws -> [String] {
        var ends: [Int32] = [-1, -1]
        XCTAssertEqual(Darwin.pipe(&ends), 0)
        let (readEnd, writeEnd) = (ends[0], ends[1])
        let collected = OSAllocatedUnfairLock(initialState: Data())
        let reading = self.collect(readEnd, into: collected)

        let saved = dup(fd)
        XCTAssertNotEqual(saved, -1)
        dup2(writeEnd, fd)
        close(writeEnd)
        let result = Result(catching: body)
        dup2(saved, fd)
        close(saved)
        reading.wait()
        try result.get()
        return String(decoding: collected.withLock { $0 }, as: UTF8.self).split(separator: "\n").map(String.init)
    }

    /**
     Read `fd` to its end on a thread at the writers' QoS, so a full pipe never has a hash thread wait on a lower
     thread, appending to `collected`. With `pause`, the reader stops for that many microseconds after every 16 ms of
     reading, as an emulator does while it draws a frame, and as busy as one.
     */
    private func collect(_ fd: Int32, pause: useconds_t = 0, into collected: OSAllocatedUnfairLock<Data>) -> DispatchGroup {
        let reading = DispatchGroup()
        DispatchQueue.global(qos: .userInitiated).async(group: reading) {
            var buffer = [UInt8](repeating: 0, count: 64 << 10)
            var drawn = ContinuousClock.now
            while true {
                // 0 at the end of a pipe, -1 (EIO) once a pty's last slave descriptor is closed.
                let count = Darwin.read(fd, &buffer, buffer.count)
                guard count > 0 else {
                    break
                }
                let chunk = Data(bytes: buffer, count: count)
                collected.withLock { $0.append(chunk) }
                if pause > 0, ContinuousClock.now - drawn >= .milliseconds(16) {
                    let deadline = ContinuousClock.now + .microseconds(Int(pause))
                    while ContinuousClock.now < deadline {}
                    drawn = ContinuousClock.now
                }
            }
            close(fd)
        }
        return reading
    }

    /**
     The lines `body` writes to `fds` (stdout, stderr or both), sent into a pty like a terminal and read from its master
     as they come, pausing like an emulator with `pause` (see `collect`); a pty hands the reader 1 KiB per read, so a
     pause has the writer wait within a few lines. Tints are kept: `plain(_:)` takes them off. A Console looks at its
     descriptors once: `body` makes its own.
     */
    private func terminal(_ fds: [Int32], pause: useconds_t = 0, _ body: () throws -> Void) throws -> [String] {
        let master = posix_openpt(O_RDWR | O_NOCTTY)
        guard master != -1, grantpt(master) == 0, unlockpt(master) == 0, let name = ptsname(master) else {
            throw Errno(rawValue: errno)
        }
        let slave = open(String(cString: name), O_RDWR | O_NOCTTY)
        guard slave != -1 else {
            close(master)
            throw Errno(rawValue: errno)
        }
        let collected = OSAllocatedUnfairLock(initialState: Data())
        let reading = self.collect(master, pause: pause, into: collected)

        let saved = fds.map { dup($0) }
        for fd in fds {
            dup2(slave, fd)
        }
        close(slave)
        let result = Result(catching: body)
        for (fd, original) in zip(fds, saved) {
            dup2(original, fd)
            close(original)
        }
        reading.wait()
        try result.get()
        // The pty's output processing ends each line with CR LF, one Character.
        return String(decoding: collected.withLock { $0 }, as: UTF8.self).split(separator: "\r\n").map(String.init)
    }

    /**
     A line as written, without the tint a terminal got it in.
     */
    private static func plain(_ line: String) -> String {
        line.replacing(/\u{1B}\[[0-9;]*m/, with: "")
    }

    /**
     `body` on `count` threads at the hash threads' QoS, each given its number; the group ends when the last returns.
     */
    private func start(_ count: Int, _ body: @escaping @Sendable (Int) -> Void) -> DispatchGroup {
        let group = DispatchGroup()
        for number in 0 ..< count {
            group.enter()
            let thread = Thread {
                body(number)
                group.leave()
            }
            thread.qualityOfService = .userInitiated
            thread.start()
        }
        return group
    }

    /**
     Wait for the threads of `group`, failing the test rather than hanging it when they are stuck.
     */
    private func finish(_ group: DispatchGroup, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertEqual(group.wait(timeout: .now() + 10), .success, "threads still running", file: file, line: line)
    }

    private func run(_ count: Int, _ body: @escaping @Sendable (Int) -> Void, file: StaticString = #filePath, line: UInt = #line) {
        self.finish(self.start(count, body), file: file, line: line)
    }

    /**
     Two lines for most files, like a two-architecture binary with `--slices`; none for every tenth, like a file that
     cannot be read.
     */
    private static func lines(of index: Int) -> [Line] {
        index % 10 == 9 ? [] : [Line(text: "\(index)  /\(index)"), Line(text: "\(index)  /\(index) (arm64)")]
    }

    // MARK: - Output

    func testSortedOutputPrintsEachFileWholeInIndexOrder() throws {
        // Hash threads finish files in any order: with --sort a file's lines wait for every earlier file and come out in
        // index order, a file's lines together, whichever thread ends up printing them. A file that prints nothing still
        // lets the next one through.
        let files = 2000
        let hashers = 8
        let lines = try self.piped(STDOUT_FILENO) {
            let console = Console()
            let output = Output(sorted: true, console: console, reporter: Reporter(console: console), trap: nil)
            let hashing = self.start(hashers) { number in
                for index in stride(from: number, to: files, by: hashers).shuffled() {
                    output.started(index, path: "/\(index)")
                    output.finished(index, lines: Self.lines(of: index))
                }
            }
            // The status timer reads what is held and being hashed while that goes on.
            let ticking = self.start(1) { _ in
                while hashing.wait(timeout: .now()) == .timedOut {
                    output.showStatus()
                    usleep(100)
                }
            }
            self.finish(hashing)
            self.finish(ticking)
            XCTAssertTrue(output.printedAny)
        }
        XCTAssertEqual(lines, (0 ..< files).flatMap { Self.lines(of: $0).map(\.text) })
    }

    func testUnsortedOutputPrintsEachFileWholeAsFinished() throws {
        // Without --sort a finished file prints at once, its lines still together.
        let files = 2000
        let hashers = 8
        let lines = try self.piped(STDOUT_FILENO) {
            let console = Console()
            let output = Output(sorted: false, console: console, reporter: Reporter(console: console), trap: nil)
            XCTAssertFalse(output.printedAny)
            self.run(hashers) { number in
                for index in stride(from: number, to: files, by: hashers) {
                    output.finished(index, lines: Self.lines(of: index))
                }
            }
            XCTAssertTrue(output.printedAny)
        }
        let expected = (0 ..< files).flatMap { Self.lines(of: $0).map(\.text) }
        XCTAssertEqual(lines.count, expected.count)
        XCTAssertEqual(Set(lines), Set(expected))
        // Each file's two lines are adjacent, the whole-file line first.
        for first in stride(from: 0, to: lines.count - 1, by: 2) {
            XCTAssertEqual(lines[first + 1], lines[first] + " (arm64)")
        }
    }

    func testCallersLocksKeepLongLinesWhole() throws {
        // A hash thread prints a file's lines through Output and its diagnostics through Reporter while the others do
        // the same: Output's one printer at a time and Reporter's lock keep each stream's lines whole, well past the
        // PIPE_BUF (512 bytes) a pipe keeps a single write whole up to. The stdout lines go far past it; the stderr
        // lines stay under it, where a line the unified log copies to stderr under Xcode (OS_ACTIVITY_DT_MODE) cannot
        // cut one.
        let hashers = 8
        let files = 100
        let long = String(repeating: "x", count: 4000)
        var errors: [String] = []
        let lines = try self.piped(STDOUT_FILENO) {
            errors = try self.piped(STDERR_FILENO) {
                let console = Console()
                let reporter = Reporter(console: console)
                let output = Output(sorted: false, console: console, reporter: reporter, trap: nil)
                self.run(hashers) { number in
                    for file in 0 ..< files {
                        let path = "/\(number)/\(file)"
                        output.finished(number * files + file, lines: [Line(text: "\(long)  \(path)")])
                        reporter.emit(reporter.warn(path: path, message: "warned"))
                    }
                }
            }
        }
        var paths: Set<String> = []
        for number in 0 ..< hashers {
            for file in 0 ..< files {
                paths.insert("/\(number)/\(file)")
            }
        }
        XCTAssertEqual(lines.count, paths.count)
        XCTAssertEqual(Set(lines), Set(paths.map { "\(long)  \($0)" }))
        let diagnostics = errors.filter { $0.hasPrefix("fashion: /") }
        XCTAssertEqual(diagnostics.count, paths.count)
        XCTAssertEqual(Set(diagnostics), Set(paths.map { "fashion: \($0): warned" }))
    }

    func testDiagnosticsPrintWithTheirFileOnATerminal() throws {
        // A file's yellow or red line is queued with its own lines, so on a terminal, where stdout and stderr meet, it
        // comes out right before them, in index order with --sort, however the hash threads interleave. Every third file
        // has one; every tenth prints nothing else, like a file TLSH makes no digest of.
        let files = 500
        let hashers = 8
        let lines = try self.terminal([STDOUT_FILENO, STDERR_FILENO]) {
            let console = Console()
            let reporter = Reporter(console: console)
            let output = Output(sorted: true, console: console, reporter: reporter, trap: nil)
            // Every file's lines, warnings first, before any is printed: under Xcode the unified log is copied to
            // stderr too (OS_ACTIVITY_DT_MODE), and a copy written while a batch of lines goes out could cut one.
            let prepared = (0 ..< files).map { index in
                (index % 3 == 0 ? [reporter.warn(path: "/\(index)", message: "warned")] : []) + Self.lines(of: index)
            }
            self.run(hashers) { number in
                for index in stride(from: number, to: files, by: hashers).shuffled() {
                    output.finished(index, lines: prepared[index])
                }
            }
            XCTAssertTrue(output.printedAny)
        }
        var expected: [String] = []
        for index in 0 ..< files {
            if index % 3 == 0 {
                expected.append("fashion: /\(index): warned")
            }
            expected += Self.lines(of: index).map(\.text)
        }
        // Only fashion's own lines: the log copies under Xcode come before them, and are not among them.
        let own = Set(expected)
        XCTAssertEqual(lines.map(Self.plain).filter(own.contains), expected)
    }

    func testDiagnosticsAloneLeaveNothingPrinted() throws {
        // In match mode, files that only have diagnostics have not matched: the run exits 1 like one that printed
        // nothing. Off a terminal the diagnostic goes out at once, as it comes, through Reporter.
        let lines = try self.piped(STDERR_FILENO) {
            let console = Console()
            let reporter = Reporter(console: console)
            let output = Output(sorted: false, console: console, reporter: reporter, trap: nil)
            output.finished(0, lines: [reporter.inform(path: "/0", message: "informed")])
            output.finished(1, lines: [])
            XCTAssertFalse(output.printedAny)
        }
        XCTAssertEqual(lines.filter { $0.hasPrefix("fashion: /") }, ["fashion: /0: informed"])
    }

    func testHashersRunOnWhileTheTerminalDraws() {
        // Eight hashers, 25 µs of work and two lines per file, print to a pty whose reader stops for 8 ms after every
        // 16 ms of reading, a third of the time, as an emulator does while it draws a frame. With the output lock held
        // across the write, every hasher waited out each pause within a few lines: 3.5 s. With the lines queued they
        // run on: 1 s, most of it the pty's 1 KiB round trips. Measured, so a change to Output or Console shows what
        // it costs here. The round trips jitter by some 13% run to run, more than the 10% a baseline allows by default:
        // one recorded in Xcode needs its maximum deviation raised to hold.
        let files = 100_000
        let hashers = 8
        let expected = (0 ..< files).reduce(0) { $0 + Self.lines(of: $1).count }
        self.measure {
            do {
                let lines = try self.terminal([STDOUT_FILENO], pause: 8000) {
                    let console = Console()
                    let output = Output(sorted: false, console: console, reporter: Reporter(console: console), trap: nil)
                    self.run(hashers) { number in
                        for index in stride(from: number, to: files, by: hashers) {
                            let deadline = ContinuousClock.now + .microseconds(25)
                            while ContinuousClock.now < deadline {}
                            output.finished(index, lines: Self.lines(of: index))
                        }
                    }
                }
                XCTAssertEqual(lines.count, expected)
            } catch {
                XCTFail("\(error)")
            }
        }
    }

    // MARK: - Reporter

    func testReporterCountsAndDiagnosticsFromConcurrentThreads() throws {
        // Hash threads count files and report, warn and inform at once, while the status line reads the counts and ⌃T
        // asks for progress: every count adds up, and every line reaches stderr whole, once. The end of the run is
        // reached twice, as on a signal that arrives as the walk ends.
        let hashers = 8
        let files = 100
        var counts = (files: 0, errors: 0)
        let lines = try self.piped(STDERR_FILENO) {
            let reporter = Reporter(console: Console())
            let hashing = self.start(hashers) { number in
                for file in 0 ..< files {
                    let path = "/\(number)/\(file)"
                    reporter.fileProcessed()
                    reporter.emit(reporter.report(path: path, message: "failed"))
                    reporter.emit(reporter.warn(path: path, message: "warned"))
                    reporter.emit(reporter.inform(path: path, message: "informed"))
                    if file % 50 == 0 {
                        reporter.progress()
                    }
                }
            }
            let watching = self.start(1) { _ in
                while hashing.wait(timeout: .now()) == .timedOut {
                    // Each thread counts a file before it reports it.
                    XCTAssertLessThanOrEqual(reporter.errorCount, reporter.fileCount)
                    usleep(100)
                }
            }
            self.finish(hashing)
            self.finish(watching)
            self.run(2) { _ in
                reporter.end("Done")
            }
            counts = (reporter.fileCount, reporter.errorCount)
        }
        XCTAssertEqual(counts.files, hashers * files)
        XCTAssertEqual(counts.errors, hashers * files)

        // Under Xcode the unified log is copied to stderr too (OS_ACTIVITY_DT_MODE): only fashion's own lines count.
        var expected: Set<String> = []
        for number in 0 ..< hashers {
            for file in 0 ..< files {
                for message in ["failed", "warned", "informed"] {
                    expected.insert("fashion: /\(number)/\(file): \(message)")
                }
            }
        }
        let diagnostics = lines.filter { $0.hasPrefix("fashion: /") }
        XCTAssertEqual(diagnostics.count, expected.count)
        XCTAssertEqual(Set(diagnostics), expected)
        let progress = lines.filter { $0.hasPrefix("fashion: ") && !$0.hasPrefix("fashion: /") }
        XCTAssertEqual(progress.count, hashers * 2)
        for line in progress {
            XCTAssertNotNil(line.wholeMatch(of: /fashion: \d+ files? with \d+ errors? in .+/), line)
        }
    }

    // MARK: - Handoff

    func testHandoffHoldsFastWalkerToItsCapacity() {
        // The walker fills the queue, then waits: with nobody taking yet, it gets exactly `capacity` paths ahead. Once
        // the hashers take, slowly, every path reaches one of them, once, in walk order for each.
        let capacity = 4
        let paths = 100
        let hashers = 2
        let handoff = Handoff(capacity: capacity)
        let handed = OSAllocatedUnfairLock(initialState: 0)
        let walking = self.start(1) { _ in
            for index in 0 ..< paths {
                handoff.put(index: index, path: "/\(index)")
                handed.withLock { $0 += 1 }
            }
            handoff.close()
        }
        let deadline = Date().addingTimeInterval(5)
        while handed.withLock({ $0 }) < capacity, Date() < deadline {
            usleep(1000)
        }
        usleep(200_000)
        XCTAssertEqual(handed.withLock { $0 }, capacity, "the walker ran ahead of the room it has")

        let taken = OSAllocatedUnfairLock(initialState: [[Int]](repeating: [], count: hashers))
        let hashing = self.start(hashers) { number in
            while let (index, path) = handoff.take() {
                XCTAssertEqual(path, "/\(index)")
                usleep(1000)
                taken.withLock { $0[number].append(index) }
            }
        }
        self.finish(walking)
        self.finish(hashing)
        let lists = taken.withLock { $0 }
        for list in lists {
            XCTAssertEqual(list, list.sorted())
        }
        XCTAssertEqual(lists.flatMap(\.self).sorted(), Array(0 ..< paths))
    }

    func testHandoffWakesIdleHashersForEachPathOfSlowWalker() {
        // Hashers outnumber what a slow walker delivers: each path wakes one of them, and closing the handoff wakes every
        // one of them a last time, so none is left waiting.
        let hashers = 4
        let paths = 50
        let handoff = Handoff(capacity: 64)
        let taken = OSAllocatedUnfairLock(initialState: [[Int]](repeating: [], count: hashers))
        let hashing = self.start(hashers) { number in
            while let (index, path) = handoff.take() {
                XCTAssertEqual(path, "/\(index)")
                taken.withLock { $0[number].append(index) }
            }
        }
        // At the hashers' QoS, like the walking thread of a run: a hasher waiting on a lower thread is a priority
        // inversion, which Xcode's Thread Performance Checker reports.
        let walking = self.start(1) { _ in
            for index in 0 ..< paths {
                usleep(500)
                handoff.put(index: index, path: "/\(index)")
            }
            handoff.close()
        }
        self.finish(walking)
        self.finish(hashing)
        let lists = taken.withLock { $0 }
        for list in lists {
            XCTAssertEqual(list, list.sorted())
        }
        XCTAssertEqual(lists.flatMap(\.self).sorted(), Array(0 ..< paths))
    }

    // MARK: - Console

    func testConsoleLinesFromConcurrentThreadsStayWhole() throws {
        // Off a terminal Console takes no lock: a line is one write, so lines up to PIPE_BUF stay whole on their own, on
        // either stream, from however many threads. Longer ones rely on their caller's lock (see the Output tests).
        let threads = 8
        let rounds = 200
        let text = String(repeating: "x", count: 400)
        var errors: [String] = []
        let lines = try self.piped(STDOUT_FILENO) {
            errors = try self.piped(STDERR_FILENO) {
                let console = Console()
                self.run(threads) { number in
                    for round in 0 ..< rounds {
                        do {
                            try console.out([Line(text: "\(number).\(round) \(text)")])
                        } catch {
                            XCTFail("stdout: \(error)")
                        }
                        console.err("\(number).\(round) \(text)", tint: .error)
                    }
                }
            }
        }
        let expected = Set((0 ..< threads).flatMap { number in (0 ..< rounds).map { "\(number).\($0) \(text)" } })
        XCTAssertEqual(lines.count, expected.count)
        XCTAssertEqual(Set(lines), expected)
        XCTAssertEqual(errors.count, expected.count)
        XCTAssertEqual(Set(errors), expected)
    }

    // MARK: - Scan

    func testScanPrintsTheSameOnEveryCPU() throws {
        // The run end to end in this process, walker to Output, where the sanitizer sees it when the tests are built
        // with one: files of two sizes finish out of order on every CPU, and --sort prints what one job does.
        let directory = FileManager.default.temporaryDirectory / "fashion-runner-scan-\(UUID())"
        try FileManager.default.createDirectory(at: directory / "sub", withIntermediateDirectories: true)
        defer {
            try? FileManager.default.removeItem(at: directory)
        }
        for index in 0 ..< 300 {
            let size = index % 25 == 0 ? 1 << 20 : 1
            let name = index % 3 == 0 ? "sub/\(index)" : "f\(index)"
            try Data(repeating: UInt8(index % 256), count: size).write(to: directory / name)
        }

        func scan(_ arguments: [String]) throws -> (status: Int32, lines: [String]) {
            // On a thread of its own: scan() raises its thread's QoS to the hash threads', as the command line's main
            // thread allows; the test runner's main thread keeps its own.
            let status = OSAllocatedUnfairLock<Int32>(initialState: -1)
            let arguments = [directory.path] + arguments
            let lines = try self.piped(STDOUT_FILENO) {
                self.run(1) { _ in
                    do {
                        let code = try Fashion.parse(arguments).scan()
                        status.withLock { $0 = code }
                    } catch {
                        XCTFail("\(error)")
                    }
                }
            }
            return (status.withLock { $0 }, lines)
        }

        let one = try scan(["--sort", "-j", "1"])
        XCTAssertEqual(one.status, 0)
        XCTAssertEqual(one.lines.count, 300)
        let paths = one.lines.map { String($0.split(separator: "  ", maxSplits: 1)[1]) }
        XCTAssertEqual(paths, naturallySorted(paths))
        let all = try scan(["--sort", "-J"])
        XCTAssertEqual(all.status, 0)
        XCTAssertEqual(all.lines, one.lines)
        // Unsorted, the same lines in the order the files finished.
        let unsorted = try scan(["-J"])
        XCTAssertEqual(unsorted.status, 0)
        XCTAssertEqual(unsorted.lines.sorted(), one.lines.sorted())
    }
}
