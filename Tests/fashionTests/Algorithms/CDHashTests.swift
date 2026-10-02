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
        // exercises the multi-code-slot synthesis branch, which the synthetic fixtures do not.
        let bin = try self.temporaryDirectory() / "ls"
        try FileManager.default.copyItem(at: URL(fileURLWithPath: "/bin/ls"), to: bin)
        _ = try codesign(["--remove-signature", bin.path()])

        try self.assertAdhocMatchesCodesignDetached(bin)
    }

    func testAdhocArm64_32MatchesCodesignDetached() throws {
        // arm64_32 (watchOS) has its own CPU type and macOS ships no such binary, so build one with the watchOS SDK.
        // It follows arm64's page-size rule, so a watchOS 8 rewrite gets 4 KiB pages.
        let dir = try self.temporaryDirectory()
        let universal = try self.compile("universal", in: dir, sdk: "watchos", ["-arch", "arm64_32", "-arch", "arm64"])
        XCTAssertEqual(try Set(CDHash.hash(path: universal.path()).compactMap(\.arch)), ["arm64_32", "arm64"])
        try self.assertAdhocMatchesCodesignDetached(universal)

        let thin = try Data(contentsOf: self.compile("thin", in: dir, sdk: "watchos", ["-arch", "arm64_32"]))
        let watchOS8 = dir / "watchos8"
        try Self.settingBuildVersion(thin, platform: PLATFORM_WATCHOS, minOS: 0x0008_0000).write(to: watchOS8)
        XCTAssertEqual(try Self.field(self.assertAdhocMatchesCodesignDetached(watchOS8), prefix: "Page size="), "4096")
    }

    func testAdhocX86_64MatchesCodesignDetached() throws {
        // A built x86_64 binary covers 4 KiB pages. Without a platform (LC_BUILD_VERSION naming platform 0) or a
        // non-empty `__TEXT` segment (renamed `__TEXX`, or its filesize zeroed), codesign writes the v0x20100
        // CodeDirectory, which has no execSeg fields.
        let dir = try self.temporaryDirectory()
        let intel = try Data(contentsOf: self.compile("intel", in: dir, ["-arch", "x86_64"]))
        let text = try XCTUnwrap(MachOParser.loadCommands(data: intel).first { $0.cmd == UInt32(LC_SEGMENT_64) && $0.data.dropFirst(8).prefix(6) == Data("__TEXT".utf8) }).data.startIndex
        var noText = intel
        noText.replaceSubrange(text + 8 ..< text + 14, with: Data("__TEXX".utf8)) // segname
        var emptyText = intel
        emptyText.replaceSubrange(text + 48 ..< text + 56, with: Data(count: 8)) // filesize

        let variants = try [
            ("original", intel, "20400"),
            ("platform0", Self.settingBuildVersion(intel, platform: 0, minOS: 0x000f_0000), "20100"),
            ("notext", noText, "20100"),
            ("emptytext", emptyText, "20100"),
        ]
        for (name, data, version) in variants {
            let bin = dir / name
            try data.write(to: bin)

            XCTAssertTrue(try self.assertAdhocMatchesCodesignDetached(bin).contains("CodeDirectory v=\(version) "), name)
        }
    }

    func testAdhocSkipsGenericObject() throws {
        // codesign signs a relocatable object as a generic file (`Format=generic`), not as Mach-O code, so an
        // unsigned `.o` has no ad-hoc cdhash: CDHash must report nothing rather than a hash matching nothing.
        let object = try self.compile("object.o", in: self.temporaryDirectory(), ["-c"])
        XCTAssertEqual(try Self.field(Self.codesignDetached(object), prefix: "Format="), "generic")
        XCTAssertTrue(try CDHash.hash(path: object.path()).isEmpty)
    }

    func testFat64SlicesMatchCodesignOnExtractedSlices() throws {
        // A universal file with 64-bit offsets (`lipo -fat64`) is only a container: codesign signs it as a generic
        // file, yet each slice is ordinary code once extracted, so its cdhashes are those codesign gives `lipo -thin`'s.
        let dir = try self.temporaryDirectory()
        let fat = dir / "fat64"
        let slices = try [self.compile("intel", in: dir, ["-arch", "x86_64"]), self.compile("arm", in: dir, ["-arch", "arm64"])]
        let merged = try Self.run("/usr/bin/xcrun", ["lipo", "-create", "-fat64"] + slices.map { $0.path() } + ["-output", fat.path()])
        try XCTSkipUnless(merged, "cannot build a 64-bit universal file with lipo")

        let results = try CDHash.hash(path: fat.path())
        for arch in ["x86_64", "arm64"] {
            let thin = dir / "thin-\(arch)"
            let extracted = try Self.run("/usr/bin/xcrun", ["lipo", fat.path(), "-thin", arch, "-output", thin.path()])
            try XCTSkipUnless(extracted, "cannot extract \(arch) with lipo")

            try self.assertAdhocMatchesCodesignDetached(thin)
            let thinHashes = try CDHash.hash(path: thin.path()).map(\.hash)
            XCTAssertEqual(results.filter { $0.arch == arch }.map(\.hash), thinHashes, arch)
        }
    }

    func testAdhocPageSizeFollowsPlatformLikeCodesign() throws {
        // codesign signs the arm64 family with 4 KiB pages on tvOS, iOS before 16 and watchOS before 9, and with
        // 16 KiB pages elsewhere: rewrite a built binary's LC_BUILD_VERSION to land on each side of each rule.
        let dir = try self.temporaryDirectory()
        let arm = try Data(contentsOf: self.compile("arm", in: dir, ["-arch", "arm64"]))
        let variants: [(name: String, platform: Int32, minOS: UInt32, pageSize: String)] = [
            ("ios15", PLATFORM_IOS, 0x000f_ffff, "4096"), // 15.255.255
            ("ios16", PLATFORM_IOS, 0x0010_0000, "16384"),
            ("tvos26", PLATFORM_TVOS, 0x001a_0000, "4096"),
            ("watchos8", PLATFORM_WATCHOS, 0x0008_ffff, "4096"), // 8.255.255
            ("watchos9", PLATFORM_WATCHOS, 0x0009_0000, "16384"),
            ("visionos1", PLATFORM_VISIONOS, 0x0001_0000, "16384"),
        ]

        for (name, platform, minOS, pageSize) in variants {
            let bin = dir / name
            try Self.settingBuildVersion(arm, platform: platform, minOS: minOS).write(to: bin)
            XCTAssertEqual(try Self.field(self.assertAdhocMatchesCodesignDetached(bin), prefix: "Page size="), pageSize, name)
        }
    }

    func testAdhocBigEndianExecSegmentMatchesCodesignDetached() throws {
        // codesign records a big-endian slice's `__TEXT` range without byte-swapping it, and the ad-hoc identity the
        // system computes carries the same quirk (walker reports codesign's cdhash): a 0x1000 range reads back reversed.
        let dir = try self.temporaryDirectory()
        let reversed32 = UInt64(UInt32(0x1000).byteSwapped) // 0x100000
        let reversed64 = UInt64(0x1000).byteSwapped // 0x10_0000_0000_0000
        let cases: [(name: String, data: Data, base: UInt64, limit: UInt64)] = [
            ("ppc", Self.makeBigEndianMachO(is64: false), 0, reversed32),
            ("ppc-text-at-0x1000", Self.makeBigEndianMachO(is64: false, textOffset: 0x1000), reversed32, reversed32),
            ("ppc64", Self.makeBigEndianMachO(is64: true), 0, reversed64),
        ]

        for (name, data, base, limit) in cases {
            let bin = dir / name
            try data.write(to: bin)
            let out = try self.assertAdhocMatchesCodesignDetached(bin)
            XCTAssertEqual(Self.field(out, prefix: "Executable Segment base="), String(base), name)
            XCTAssertEqual(Self.field(out, prefix: "Executable Segment limit="), String(limit), name)
        }
    }

    func testAdhocBindsEmbeddedInfoPlistLikeCodesign() throws {
        // codesign hashes a `__TEXT,__info_plist` section into the Info.plist special slot (-1), whatever it holds and
        // even empty; it ignores one in another segment, and finds none on a big-endian slice.
        let dir = try self.temporaryDirectory()
        let inputs = dir / "inputs" // away from the binaries: codesign signs a folder holding an Info.plist as a bundle
        try FileManager.default.createDirectory(at: inputs, withIntermediateDirectories: true)
        let plist = Data(#"<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>com.example.tool</string></dict></plist>"#.utf8)
        for (name, contents) in [("plist", plist), ("garbage", Data("not a plist".utf8)), ("empty", Data())] {
            try contents.write(to: inputs / name)
        }
        func sectcreate(_ segment: String, _ input: String) -> String {
            "-Wl,-sectcreate,\(segment),__info_plist,\((inputs / input).path())"
        }

        let variants: [(name: String, arguments: [String])] = [
            ("x86_64", ["-arch", "x86_64", sectcreate("__TEXT", "plist")]),
            ("dylib", ["-arch", "arm64", "-dynamiclib", sectcreate("__TEXT", "plist")]),
            ("garbage", ["-arch", "arm64", sectcreate("__TEXT", "garbage")]),
            ("empty", ["-arch", "arm64", sectcreate("__TEXT", "empty")]),
            ("data-segment", ["-arch", "arm64", sectcreate("__DATA", "plist")]),
        ]
        for (name, arguments) in variants {
            try self.assertAdhocMatchesCodesignDetached(self.compile(name, in: dir, arguments))
        }

        let ppc = dir / "ppc"
        try Self.makeBigEndianMachO(is64: false, infoPlist: plist).write(to: ppc)
        try self.assertAdhocMatchesCodesignDetached(ppc)
    }

    func testLogicalEndMatchesCodesignStrictValidation() throws {
        // Security's MachO ends the image at __LINKEDIT, and codesign's strict validation rejects any byte past it:
        // the bytes appended to a built binary are exactly the ones logicalEnd trims.
        let dir = try self.temporaryDirectory()
        let original = try self.compile("original", in: dir, ["-arch", "arm64"])
        var padded = try Data(contentsOf: original)
        let end = padded.count
        padded.append(Data(repeating: 0x41, count: 777))
        let paddedURL = dir / "padded"
        try padded.write(to: paddedURL)

        XCTAssertEqual(try XCTUnwrap(MachOSlice(padded)).logicalEnd(), end)
        XCTAssertNoThrow(try Self.codesignDetached(original))
        XCTAssertThrowsError(try Self.codesignDetached(paddedURL)) { error in
            XCTAssertTrue(String(describing: error).contains("strict validation"), "\(error)")
        }
    }

    // MARK: - Helpers

    /// A fresh directory, removed when the test ends.
    private func temporaryDirectory() throws -> URL {
        let dir = FileManager.default.temporaryDirectory / "fashion-cdhash-\(UUID())"
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        self.addTeardownBlock {
            try? FileManager.default.removeItem(at: dir)
        }
        return dir
    }

    /// `int main` built by `clang arguments` against the `sdk` SDK into `dir/name`, unsigned; skips the test when it cannot be built.
    private func compile(_ name: String, in dir: URL, sdk: String = "macosx", _ arguments: [String]) throws -> URL {
        let source = dir / "main.c"
        try "int main(void) { return 0; }\n".write(to: source, atomically: true, encoding: .utf8)
        let output = dir / name
        let built = try Self.run("/usr/bin/xcrun", ["-sdk", sdk, "clang"] + arguments + ["-Wl,-no_adhoc_codesign", source.path(), "-o", output.path()])
        try XCTSkipUnless(built, "cannot build \(name) with the \(sdk) SDK")
        return output
    }

    /// `data` with its first LC_BUILD_VERSION declaring `platform` and `minOS` instead.
    private static func settingBuildVersion(_ data: Data, platform: Int32, minOS: UInt32) throws -> Data {
        let command = try XCTUnwrap(MachOParser.loadCommands(data: data).first { $0.cmd == UInt32(LC_BUILD_VERSION) }, "no LC_BUILD_VERSION")
        var fields = Data()
        fields.appendUInt32(UInt32(bitPattern: platform))
        fields.appendUInt32(minOS)
        var data = data
        data.replaceSubrange(command.data.startIndex + 8 ..< command.data.startIndex + 16, with: fields)
        return data
    }

    /**
     The smallest big-endian executable codesign signs (ppc, or ppc64 when `is64`): `__TEXT` at file offset
     `textOffset`, a `__DATA` segment filling any gap before it, a final `__LINKEDIT` that ends the file, and
     `LC_VERSION_MIN_MACOSX` 10.4 so codesign records the execSeg fields. Given `infoPlist`, `__TEXT` holds it in an
     `__info_plist` section.
     */
    private static func makeBigEndianMachO(is64: Bool, textOffset: UInt32 = 0, infoPlist: Data? = nil) -> Data {
        let page: UInt32 = 0x1000
        let linkeditSize: UInt32 = 8
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

    /// Sign `file` (its `arch` slice when given) ad hoc into a detached signature, and return codesign's `-dvvvv` display of it.
    private static func codesignDetached(_ file: URL, arch: String? = nil) throws -> String {
        let sig = file.deletingLastPathComponent() / "\(file.lastPathComponent).sig"
        let archArgs = arch.map { ["--arch", $0] } ?? []
        // Sign with both algorithms so codesign displays both CandidateCDHashFull sha256 and sha1.
        _ = try codesign(["--detached", sig.path(), "-f", "-s", "-", "-i", "ADHOC", "--digest-algorithm=sha1,sha256"] + archArgs + [file.path()])
        return try codesign(["-dvvvv", "--detached", sig.path()] + archArgs + [file.path()])
    }

    /**
     Each slice of the unsigned `bin` must yield synthesized ad-hoc cdhashes (SHA-256 and SHA-1) equal to
     `codesign --detached`'s CandidateCDHashFull for the matching algorithm. Returns codesign's display of the
     last slice checked, for the caller to read other fields from.
     */
    @discardableResult
    private func assertAdhocMatchesCodesignDetached(_ bin: URL) throws -> String {
        let results = try CDHash.hash(path: bin.path())
        XCTAssertFalse(results.isEmpty, "unsigned \(bin.lastPathComponent) must yield ad-hoc cdhashes")

        var out = ""
        for (arch, sliceResults) in Dictionary(grouping: results, by: \.arch) {
            out = try Self.codesignDetached(bin, arch: arch)
            Self.assertInspectedSlice(out, arch: arch)
            for result in sliceResults {
                XCTAssertTrue(result.adhoc, "unsigned slice \(arch ?? "thin") must be ADHOC")
                let alg = try XCTUnwrap(result.type, "an ad-hoc result must carry its hash type (sha256 / sha1)")
                let expected = try XCTUnwrap(Self.field(out, prefix: "CandidateCDHashFull \(alg)"), "codesign printed no CandidateCDHashFull \(alg)")
                XCTAssertEqual(result.hash, expected, "adhoc \(alg) cdhash ≠ codesign --detached (\(arch ?? "thin"))")
            }
        }
        return out
    }

    /// Run `executable` with its output discarded; true when it exits zero.
    private static func run(_ executable: String, _ arguments: [String]) throws -> Bool {
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
