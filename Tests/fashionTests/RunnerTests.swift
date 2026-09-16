@testable import fashion
import MachO
import XCTest

/**
 The exit-code contract: 0 when every path hashed, 2 when any path could not be hashed.
 */
final class RunnerTests: XCTestCase {
    private func run(_ url: URL, algorithm: Algorithm = .sha256, slices: Bool = false) async -> Int32 {
        let runner = Runner(
            paths: [url.path],
            algorithm: algorithm,
            quiet: true,
            slices: slices,
            exact: false,
            sortFiles: true,
            jobs: 1,
            follow: false,
            matchDigests: [],
            score: 0,
            symhash: false,
            separator: ",",
            sortSymbols: true,
            xarToc: false,
            decompress: false,
        )
        return await runner.run()
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
     A one-architecture universal binary wrapping `slice` at offset 64.
     */
    private func fat(wrapping slice: Data) -> Data {
        var data = Data()
        data.appendUInt32BE(FAT_MAGIC)
        data.appendUInt32BE(1)
        data.appendInt32BE(CPU_TYPE_ARM64)
        data.appendInt32BE(0)
        data.appendUInt32BE(64)
        data.appendUInt32BE(UInt32(slice.count))
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

    func testWellFormedMachOExitsZero() async throws {
        let url = try self.write(self.machO(), name: "ok")
        defer {
            try? FileManager.default.removeItem(at: url)
        }

        let exitCode = await self.run(url, algorithm: .cdhash)
        XCTAssertEqual(exitCode, 0)
    }

    func testMalformedMachOSetsExitCode2() async throws {
        let url = try self.write(self.machO(padding: 8), name: "bad")
        defer {
            try? FileManager.default.removeItem(at: url)
        }

        // A mode that parses the Mach-O reports it; plain hashing of the raw bytes does not care.
        let parsed = await self.run(url, algorithm: .cdhash)
        XCTAssertEqual(parsed, 2)
        let raw = await self.run(url)
        XCTAssertEqual(raw, 0)
    }

    func testSlicesRejectsMalformedSliceInsideFat() async throws {
        // --slices is a Mach-O-aware mode: a broken slice is reported whether or not --exact is set.
        let bad = try self.write(self.fat(wrapping: self.machO(padding: 8)), name: "fat-bad")
        let good = try self.write(self.fat(wrapping: self.machO()), name: "fat-ok")
        defer {
            try? FileManager.default.removeItem(at: bad)
            try? FileManager.default.removeItem(at: good)
        }

        let rejected = await self.run(bad, slices: true)
        XCTAssertEqual(rejected, 2)
        let accepted = await self.run(good, slices: true)
        XCTAssertEqual(accepted, 0)
    }
}
