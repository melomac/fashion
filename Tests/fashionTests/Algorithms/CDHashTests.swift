@testable import fashion
import Foundation
import XCTest

final class CDHashTests: XCTestCase {
    // MARK: - Thin binary (system binary)

    func testHashThinBinaryNonNil() throws {
        // /bin/ls is a signed Mach-O on macOS
        let results = try CDHash.hash(path: "/bin/ls")
        XCTAssertFalse(results.isEmpty, "Expected CDHash for /bin/ls")

        let first = results[0]
        XCTAssertFalse(first.hash.isEmpty)
        // CDHash should be hex: SHA-1 (40 chars) or SHA-256 (64 chars)
        XCTAssertTrue(first.hash.count == 40 || first.hash.count == 64, "Unexpected CDHash length: \(first.hash.count)")
        XCTAssertTrue(first.hash.allSatisfy(\.isHexDigit), "CDHash should be hex")
    }

    func testHashDataThinBinary() throws {
        let data = try Data(contentsOf: URL(fileURLWithPath: "/bin/ls"), options: .mappedIfSafe)
        let pathResults = try CDHash.hash(path: "/bin/ls")
        guard !pathResults.isEmpty else {
            XCTFail("Expected CDHash for /bin/ls")
            return
        }

        // For thin binary or first slice, hash(data:) on the slice should match
        switch try MachOParser.open(data: data) {
        case .thin:
            let dataHash = try CDHash.hash(data: data)
            XCTAssertEqual(dataHash, pathResults[0].hash)
        case let .fat(archs):
            // hash(data:) on first slice should match first path result
            let slice = MachOParser.sliceData(fileData: data, arch: archs[0])
            let dataHash = try CDHash.hash(data: slice)
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
                case .fat? = try? MachOParser.open(path: candidate)
            else {
                continue
            }

            let results = try CDHash.hash(path: candidate)

            // Candidate should have multiple CDHashes
            guard results.count > 1 else {
                continue
            }

            for result in results {
                XCTAssertNotNil(result.arch, "Fat binary slices should have arch names")
                XCTAssertFalse(result.hash.isEmpty)
                XCTAssertTrue(result.hash.count == 40 || result.hash.count == 64)
            }
            return
        }

        throw XCTSkip("No fat binary found — skip gracefully")
    }

    func testSignedSliceIsNotAdhoc() throws {
        // /bin/ls is signed, so every slice must use its embedded cdhash — never the ad-hoc fall-back.
        let results = try CDHash.hash(path: "/bin/ls")
        XCTAssertFalse(results.isEmpty)
        for result in results {
            XCTAssertFalse(result.adhoc, "A signed slice must not be tagged ADHOC")
        }
    }

    // MARK: - Non-Mach-O

    func testHashNonMachOReturnsEmpty() throws {
        let url = FileManager.default.temporaryDirectory / "fashion-cdhash-\(UUID()).txt"
        try? Data("Hello, World!".utf8).write(to: url)
        defer {
            try? FileManager.default.removeItem(at: url)
        }

        let results = try CDHash.hash(path: url.path())
        XCTAssertTrue(results.isEmpty)
    }

    func testHashDataNonMachOReturnsNil() throws {
        let data = Data("Hello, World!".utf8)
        XCTAssertNil(try CDHash.hash(data: data))
    }

    func testHashMissingFileThrows() {
        XCTAssertThrowsError(try CDHash.hash(path: "/tmp/fashion-nonexistent-\(UUID())"))
    }

    // MARK: - Determinism

    func testHashDeterministic() throws {
        let first = try CDHash.hash(path: "/bin/ls")
        for _ in 0 ..< 5 {
            let again = try CDHash.hash(path: "/bin/ls")
            XCTAssertEqual(first.count, again.count)

            for (a, b) in zip(first, again) {
                XCTAssertEqual(a.hash, b.hash)
            }
        }
    }

    // MARK: - Matching integration

    func testExactMatchWorks() throws {
        let results = try CDHash.hash(path: "/bin/ls")
        let first = try XCTUnwrap(results.first)

        let match = Matching.check(digest: first.hash, against: [first.hash], algorithm: .cdhash, threshold: 0)
        XCTAssertNotNil(match)
        XCTAssertTrue(try XCTUnwrap(match?.matched))
    }

    func testExactMatchCaseInsensitive() throws {
        let results = try CDHash.hash(path: "/bin/ls")
        let first = try XCTUnwrap(results.first)

        let upper = first.hash.uppercased()
        let match = Matching.check(digest: first.hash, against: [upper], algorithm: .cdhash, threshold: 0)
        XCTAssertNotNil(match)
    }

    func testTruncatedTargetMatches() throws {
        let results = try CDHash.hash(path: "/bin/ls")
        let first = try XCTUnwrap(results.first)

        // 20-byte truncated CDHash (40 hex chars) should match full 32-byte hash
        let truncated = String(first.hash.prefix(40))
        XCTAssertEqual(truncated.count, 40)

        let match = Matching.check(digest: first.hash, against: [truncated], algorithm: .cdhash, threshold: 0)
        XCTAssertNotNil(match, "Truncated CDHash should match full CDHash")
    }

    func testFullTargetDoesNotMatchTruncatedDigest() throws {
        // A truncated target is matched as a prefix of the full computed digest, but not the reverse:
        // a full-length target must not match a shorter digest, or a full sha256 target could spuriously
        // match a 40-hex sha1 CodeDirectory line on a dual-signed binary.
        let results = try CDHash.hash(path: "/bin/ls")
        let first = try XCTUnwrap(results.first)

        let truncated = String(first.hash.prefix(40))
        let match = Matching.check(digest: truncated, against: [first.hash], algorithm: .cdhash, threshold: 0)
        XCTAssertNil(match, "A longer target must not match a shorter computed digest")
    }

    func testNoMatchOnDifferentDigest() throws {
        let results = try CDHash.hash(path: "/bin/ls")
        let first = try XCTUnwrap(results.first)

        let fake = String(repeating: "0", count: first.hash.count)
        let match = Matching.check(digest: first.hash, against: [fake], algorithm: .cdhash, threshold: 0)
        XCTAssertNil(match)
    }

    // MARK: - codesign cross-check (self-contained, OS-version independent)

    func testEmbeddedCDHashMatchesCodesign() throws {
        // Every signed slice's embedded cdhash (truncated to 20 bytes) must equal codesign's CDHash.
        let path = "/bin/ls"
        let results = try CDHash.hash(path: path)
        try XCTSkipIf(results.isEmpty, "no cdhash for \(path)")
        try self.assertSliceNamesMatchCodesign(results, path: path)

        for result in results {
            XCTAssertFalse(result.adhoc, "\(result.arch ?? "thin") slice of \(path) is signed")

            let archArgs = result.arch.map { ["--arch", $0] } ?? []
            let out = try codesign(["-dvvv"] + archArgs + [path])
            Self.assertInspectedSlice(out, arch: result.arch)
            let expected = try XCTUnwrap(Self.field(out, prefix: "CDHash="), "codesign printed no CDHash")

            XCTAssertEqual(String(result.hash.prefix(40)), expected, "embedded cdhash ≠ codesign CDHash (\(result.arch ?? "thin"))")
        }
    }

    func testAdhocMatchesCodesignDetached() throws {
        // Strip a real system binary → unsigned, then each slice's synthesized ad-hoc cdhashes (SHA-256 and
        // SHA-1) must equal codesign --detached's CandidateCDHashFull for the matching algorithm. This also
        // exercises the x86_64 (4 KiB page) and multi-code-slot synthesis branches, which the synthetic
        // fixtures do not.
        let dir = FileManager.default.temporaryDirectory / "fashion-adhoc-oracle-\(UUID())"
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer {
            try? FileManager.default.removeItem(at: dir)
        }

        let bin = dir / "ls"
        try FileManager.default.copyItem(at: URL(fileURLWithPath: "/bin/ls"), to: bin)
        _ = try codesign(["--remove-signature", bin.path()])

        let results = try CDHash.hash(path: bin.path())
        try XCTSkipIf(results.isEmpty, "no cdhash after stripping the signature")

        for result in results {
            XCTAssertTrue(result.adhoc, "stripped slice \(result.arch ?? "thin") must be ADHOC")
            let alg = try XCTUnwrap(result.type, "an ad-hoc result must carry its hash type (sha256 / sha1)")

            let archArgs = result.arch.map { ["--arch", $0] } ?? []
            let sig = dir / "detached.sig"
            // Sign with both algorithms so codesign emits both CandidateCDHashFull sha256 and sha1.
            _ = try codesign(["--detached", sig.path(), "-f", "-s", "-", "-i", "ADHOC", "--digest-algorithm=sha1,sha256"] + archArgs + [bin.path()])
            let out = try codesign(["-dvvv", "--detached", sig.path()] + archArgs + [bin.path()])
            Self.assertInspectedSlice(out, arch: result.arch)
            let expected = try XCTUnwrap(Self.field(out, prefix: "CandidateCDHashFull \(alg)"), "codesign printed no CandidateCDHashFull \(alg)")

            XCTAssertEqual(result.hash, expected, "adhoc \(alg) cdhash ≠ codesign --detached (\(result.arch ?? "thin"))")
        }
    }

    // MARK: - Helpers

    /**
     Every slice codesign lists for a universal `path` must appear in `results` under the same name, the name
     `codesign --arch` resolves. A slice reported under another name (macOS 27's arm64e.x1 as `arm64`) makes
     codesign inspect a different slice, and a slice `CDHash` silently dropped would otherwise go unchecked.
     */
    private func assertSliceNamesMatchCodesign(_ results: [CDHash.SliceResult], path: String) throws {
        let names = Set(results.compactMap(\.arch))
        guard !names.isEmpty else {
            return // thin binary: nothing to cross-check
        }

        let archs = try codesignArchs(path) // outside XCTUnwrap, so a skip from the helper stays a skip
        let expected = try XCTUnwrap(archs, "codesign printed no Format line for \(path)")
        XCTAssertEqual(names, expected, "slice names must match codesign's for \(path)")
    }

    /**
     `codesign -d` output must describe the slice we asked for: `--arch` resolves a generic name (`arm64`) to
     whichever matching slice codesign prefers rather than failing, silently comparing against the wrong slice.
     */
    private static func assertInspectedSlice(_ output: String, arch: String?) {
        guard let arch else {
            return
        }

        XCTAssertEqual(Self.field(output, prefix: "Format="), "Mach-O thin (\(arch))", "codesign --arch \(arch) inspected another slice")
    }

    /// The hex value after `=` on the first line beginning with `prefix` (e.g. `CDHash=`, `CandidateCDHashFull`).
    private static func field(_ output: String, prefix: String) -> String? {
        for line in output.split(separator: "\n") where line.hasPrefix(prefix) {
            return line.split(separator: "=").last.map(String.init)
        }
        return nil
    }
}
