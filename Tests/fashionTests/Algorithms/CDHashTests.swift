@testable import fashion
import XCTest

final class CDHashTests: XCTestCase {
    // MARK: - Thin binary (system binary)

    func testHashThinBinaryNonNil() {
        // /bin/ls is a signed Mach-O on macOS
        let results = CDHash.hash(path: "/bin/ls")
        XCTAssertFalse(results.isEmpty, "Expected CDHash for /bin/ls")

        let first = results[0]
        XCTAssertFalse(first.hash.isEmpty)
        // CDHash should be hex: SHA-1 (40 chars) or SHA-256 (64 chars)
        XCTAssertTrue(first.hash.count == 40 || first.hash.count == 64, "Unexpected CDHash length: \(first.hash.count)")
        XCTAssertTrue(first.hash.allSatisfy(\.isHexDigit), "CDHash should be hex")
    }

    func testHashDataThinBinary() throws {
        let data = try Data(contentsOf: URL(fileURLWithPath: "/bin/ls"), options: .mappedIfSafe)
        let pathResults = CDHash.hash(path: "/bin/ls")
        guard !pathResults.isEmpty else {
            XCTFail("Expected CDHash for /bin/ls")
            return
        }

        // For thin binary or first slice, hash(data:) on the slice should match
        switch MachOParser.open(data: data) {
        case .thin:
            let dataHash = CDHash.hash(data: data)
            XCTAssertEqual(dataHash, pathResults[0].hash)
        case let .fat(archs):
            // hash(data:) on first slice should match first path result
            let slice = MachOParser.sliceData(fileData: data, arch: archs[0])
            let dataHash = CDHash.hash(data: slice)
            XCTAssertEqual(dataHash, pathResults[0].hash)
        case .notMachO:
            XCTFail("/bin/ls should be Mach-O")
        }
    }

    // MARK: - Fat binary

    func testHashFatBinaryMultipleSlices() throws {
        // /usr/bin/file is often a universal binary
        let candidates = [
            "/usr/bin/file",
            "/usr/bin/lipo",
            "/usr/bin/ditto",
        ]

        for candidate in candidates {
            guard
                FileManager.default.fileExists(atPath: candidate),
                case .fat = MachOParser.open(path: candidate)
            else {
                continue
            }

            let results = CDHash.hash(path: candidate)

            // Candidate should have multiple CDHashes
            guard results.count > 1 else {
                continue
            }

            for r in results {
                XCTAssertNotNil(r.arch, "Fat binary slices should have arch names")
                XCTAssertFalse(r.hash.isEmpty)
                XCTAssertTrue(r.hash.count == 40 || r.hash.count == 64)
            }
            return
        }

        throw XCTSkip("No fat binary found — skip gracefully")
    }

    // MARK: - Non-Mach-O

    func testHashNonMachOReturnsEmpty() {
        let url = FileManager.default.temporaryDirectory / "fashion-cdhash-\(UUID()).txt"
        try? Data("Hello, World!".utf8).write(to: url)
        defer {
            try? FileManager.default.removeItem(at: url)
        }

        let results = CDHash.hash(path: url.path())
        XCTAssertTrue(results.isEmpty)
    }

    func testHashDataNonMachOReturnsNil() {
        let data = Data("Hello, World!".utf8)
        XCTAssertNil(CDHash.hash(data: data))
    }

    func testHashMissingFileReturnsEmpty() {
        let results = CDHash.hash(path: "/tmp/fashion-nonexistent-\(UUID())")
        XCTAssertTrue(results.isEmpty)
    }

    // MARK: - Determinism

    func testHashDeterministic() {
        let first = CDHash.hash(path: "/bin/ls")
        for _ in 0 ..< 5 {
            let again = CDHash.hash(path: "/bin/ls")
            XCTAssertEqual(first.count, again.count)

            for (a, b) in zip(first, again) {
                XCTAssertEqual(a.hash, b.hash)
            }
        }
    }

    // MARK: - Matching integration

    func testExactMatchWorks() throws {
        let results = CDHash.hash(path: "/bin/ls")
        let first = try XCTUnwrap(results.first)

        let match = Matching.check(digest: first.hash, against: [first.hash], algorithm: .cdhash, threshold: 0)
        XCTAssertNotNil(match)
        XCTAssertTrue(try XCTUnwrap(match?.matched))
    }

    func testExactMatchCaseInsensitive() throws {
        let results = CDHash.hash(path: "/bin/ls")
        let first = try XCTUnwrap(results.first)

        let upper = first.hash.uppercased()
        let match = Matching.check(digest: first.hash, against: [upper], algorithm: .cdhash, threshold: 0)
        XCTAssertNotNil(match)
    }

    func testTruncatedTargetMatches() throws {
        let results = CDHash.hash(path: "/bin/ls")
        let first = try XCTUnwrap(results.first)

        // 20-byte truncated CDHash (40 hex chars) should match full 32-byte hash
        let truncated = String(first.hash.prefix(40))
        XCTAssertEqual(truncated.count, 40)

        let match = Matching.check(digest: first.hash, against: [truncated], algorithm: .cdhash, threshold: 0)
        XCTAssertNotNil(match, "Truncated CDHash should match full CDHash")
    }

    func testTruncatedDigestMatchesFullTarget() throws {
        let results = CDHash.hash(path: "/bin/ls")
        let first = try XCTUnwrap(results.first)

        let truncated = String(first.hash.prefix(40))
        let match = Matching.check(digest: truncated, against: [first.hash], algorithm: .cdhash, threshold: 0)
        XCTAssertNotNil(match, "Full CDHash target should match truncated digest")
    }

    func testNoMatchOnDifferentDigest() throws {
        let results = CDHash.hash(path: "/bin/ls")
        let first = try XCTUnwrap(results.first)

        let fake = String(repeating: "0", count: first.hash.count)
        let match = Matching.check(digest: first.hash, against: [fake], algorithm: .cdhash, threshold: 0)
        XCTAssertNil(match)
    }
}
