import CryptoKit
@testable import fashion
import MachO
import XCTest

/**
 Ad-hoc cdhash synthesis for unsigned slices, and the `MachO` accessors that feed it.
 */
final class AdhocCDHashTests: XCTestCase {
    /**
     A minimal native-endian thin 64-bit Mach-O with a single segment (`__TEXT` unless renamed) covering
     `[0, fileSize)`, followed by any extra load `commands`. Unsigned, so `CDHash`/`MachO` synthesize its
     ad-hoc cdhash.
     */
    private func makeMachO(cpuType: cpu_type_t = CPU_TYPE_ARM64, filetype: UInt32 = UInt32(MH_EXECUTE), segment: String = "__TEXT", commands: [Data] = [], fileSize: Int = 256) -> Data {
        var data = Data()
        data.appendUInt32(MH_MAGIC_64)
        data.appendInt32(cpuType)
        data.appendInt32(0) // cpusubtype
        data.appendUInt32(filetype)
        data.appendUInt32(UInt32(1 + commands.count)) // ncmds
        data.appendUInt32(UInt32(72 + commands.reduce(0) { $0 + $1.count })) // sizeofcmds (segment_command_64 + extras)
        data.appendUInt32(0) // flags
        data.appendUInt32(0) // reserved
        // LC_SEGMENT_64
        data.appendUInt32(UInt32(LC_SEGMENT_64))
        data.appendUInt32(72) // cmdsize
        data.append(Data(segment.utf8)); data.append(Data(repeating: 0, count: 16 - segment.utf8.count)) // segname[16]
        data.appendUInt64(0) // vmaddr
        data.appendUInt64(UInt64(fileSize)) // vmsize
        data.appendUInt64(0) // fileoff
        data.appendUInt64(UInt64(fileSize)) // filesize
        data.appendUInt32(7) // maxprot
        data.appendUInt32(5) // initprot
        data.appendUInt32(0) // nsects
        data.appendUInt32(0) // flags
        commands.forEach { data.append($0) }
        data.append(Data(repeating: 0xab, count: fileSize - data.count)) // segment content

        return data
    }

    /// An `LC_BUILD_VERSION` command with no tool entries.
    private func buildVersion(platform: Int32, minOS: UInt32 = 0x000f_0000) -> Data {
        var command = Data()
        command.appendUInt32(UInt32(LC_BUILD_VERSION))
        command.appendUInt32(24) // cmdsize
        command.appendUInt32(UInt32(platform))
        command.appendUInt32(minOS) // minos
        command.appendUInt32(minOS) // sdk
        command.appendUInt32(0) // ntools

        return command
    }

    /// An `LC_VERSION_MIN_*` command.
    private func versionMin(_ cmd: Int32, minOS: UInt32 = 0x000f_0000) -> Data {
        var command = Data()
        command.appendUInt32(UInt32(cmd))
        command.appendUInt32(16) // cmdsize
        command.appendUInt32(minOS) // version
        command.appendUInt32(minOS) // sdk

        return command
    }

    /// `makeMachO` with a 128-byte `__TEXT` and an `LC_CODE_SIGNATURE` pointing at `signature`, appended at offset 128.
    private func makeSignedMachO(signature: Data, declaredSignatureOffset: UInt32 = 128) -> Data {
        var command = Data()
        [UInt32(LC_CODE_SIGNATURE), 16, declaredSignatureOffset, UInt32(signature.count)].forEach { command.appendUInt32($0) } // cmd, cmdsize, dataoff, datasize

        return self.makeMachO(commands: [command], fileSize: 128) + signature
    }

    /**
     A minimal 50-byte CodeDirectory Security accepts: version 0x20100, the identifier "x", no code slots, and slots as wide
     as `hashType`'s hash unless `hashSize` says otherwise.
     */
    private func codeDirectory(hashType: UInt8, hashSize: UInt8? = nil) -> Data {
        var directory = Data()
        // magic, length, version, flags, hashOffset, identOffset, nSpecialSlots, nCodeSlots, codeLimit
        [0xfade_0c02, 50, 0x20100, 0, 50, 48, 0, 0, 0].forEach { directory.appendUInt32BE($0) }
        directory.append(contentsOf: [hashSize ?? [1: 20, 2: 32, 3: 20, 4: 48, 5: 64][hashType] ?? 32, hashType, 0, 0]) // hashSize, hashType, platform, pageSize
        directory.appendUInt32BE(0) // spare2
        directory.appendUInt32BE(0) // scatterOffset
        directory.append(contentsOf: Array("x\0".utf8)) // identifier

        return directory
    }

    /// A superblob indexing `blobs` in the order given, each under its slot.
    private func superblob(slots: [(slot: UInt32, blob: Data)]) -> Data {
        var offset = 12 + 8 * slots.count
        var index = Data()
        for (slot, blob) in slots {
            index.appendUInt32BE(slot)
            index.appendUInt32BE(UInt32(offset))
            offset += blob.count
        }

        var signature = Data()
        [0xfade_0cc0, UInt32(offset), UInt32(slots.count)].forEach { signature.appendUInt32BE($0) }
        return signature + index + slots.reduce(Data()) { $0 + $1.blob }
    }

    /**
     A thin arm64 Mach-O that IS signed (carries `LC_CODE_SIGNATURE`) but whose embedded signature is a
     well-formed empty superblob (magic `0xfade0cc0`, count 0) — so no code directory parses out of it.
     */
    private func makeSignedEmptySuperblob(declaredSignatureOffset: UInt32 = 128) -> Data {
        let signature = Data([0xfa, 0xde, 0x0c, 0xc0, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00])
        return self.makeSignedMachO(signature: signature, declaredSignatureOffset: declaredSignatureOffset)
    }

    /**
     A superblob whose index is inside its declared 32-byte range, while the indexed 38-byte CodeDirectory
     extends to byte 58. The enclosing `LC_CODE_SIGNATURE` includes all 58 bytes.
     */
    private func makeCodeDirectoryOutsideDeclaredSuperblob() -> Data {
        var signature = Data()
        signature.appendUInt32BE(0xfade_0cc0) // embedded-signature magic
        signature.appendUInt32BE(32) // declared superblob length
        signature.appendUInt32BE(1) // index count
        signature.appendUInt32BE(0) // primary CodeDirectory slot
        signature.appendUInt32BE(20) // CodeDirectory offset
        signature.appendUInt32BE(0xfade_0c02) // CodeDirectory magic
        signature.appendUInt32BE(38) // CodeDirectory length
        signature.append(Data(repeating: 0, count: 29))
        signature.append(2) // hashType at CodeDirectory offset 37
        return self.makeSignedMachO(signature: signature)
    }

    // MARK: - MachOBase lookups

    func testFindSegment() throws {
        let slice = try XCTUnwrap(MachO(self.makeMachO()))
        XCTAssertEqual(try slice.findSegment("__TEXT")?.cmd, UInt32(LC_SEGMENT_64))
        XCTAssertNil(try slice.findSegment("__DATA"))
        XCTAssertNil(try XCTUnwrap(MachO(self.makeMachO(segment: "__TEXX"))).findSegment("__TEXT"))
    }

    func testFindCommand() throws {
        let slice = try XCTUnwrap(MachO(self.makeMachO(commands: [self.buildVersion(platform: PLATFORM_IOS)])))
        XCTAssertEqual(slice.findCommand(UInt32(LC_BUILD_VERSION))?.data.count, 24)
        XCTAssertNil(slice.findCommand(UInt32(LC_CODE_SIGNATURE)))
    }

    func testVersionAbsentIsNil() throws {
        XCTAssertNil(try XCTUnwrap(MachO(self.makeMachO())).version())
    }

    func testPlatformFromBuildVersion() throws {
        let slice = try XCTUnwrap(MachO(self.makeMachO(commands: [self.buildVersion(platform: PLATFORM_IOS, minOS: 0x000f_0603)])))
        XCTAssertEqual(try slice.version()?.platform, PLATFORM_IOS)
        XCTAssertEqual(try slice.version()?.minOS, 0x000f_0603) // 15.6.3
    }

    func testPlatformFromVersionMin() throws {
        let pairs: [(Int32, Int32)] = [
            (LC_VERSION_MIN_MACOSX, PLATFORM_MACOS),
            (LC_VERSION_MIN_IPHONEOS, PLATFORM_IOS),
            (LC_VERSION_MIN_TVOS, PLATFORM_TVOS),
            (LC_VERSION_MIN_WATCHOS, PLATFORM_WATCHOS),
        ]
        for (cmd, platform) in pairs {
            let slice = try XCTUnwrap(MachO(self.makeMachO(commands: [self.versionMin(cmd, minOS: 0x0008_0100)])))
            XCTAssertEqual(try slice.version()?.platform, platform, "LC_VERSION_MIN 0x\(String(cmd, radix: 16))")
            XCTAssertEqual(try slice.version()?.minOS, 0x0008_0100, "LC_VERSION_MIN 0x\(String(cmd, radix: 16))") // 8.1
        }
    }

    func testPlatformPrecedenceFollowsCodesign() throws {
        // codesign reads the first LC_BUILD_VERSION, even one naming platform 0, ahead of any LC_VERSION_MIN_*.
        let buildFirst = try XCTUnwrap(MachO(self.makeMachO(commands: [self.buildVersion(platform: PLATFORM_IOS), self.buildVersion(platform: PLATFORM_MACOS)])))
        XCTAssertEqual(try buildFirst.version()?.platform, PLATFORM_IOS)

        let versionMinFirst = try XCTUnwrap(MachO(self.makeMachO(commands: [self.versionMin(LC_VERSION_MIN_IPHONEOS), self.buildVersion(platform: PLATFORM_MACOS)])))
        XCTAssertEqual(try versionMinFirst.version()?.platform, PLATFORM_MACOS)

        let platformZero = try XCTUnwrap(MachO(self.makeMachO(commands: [self.versionMin(LC_VERSION_MIN_MACOSX), self.buildVersion(platform: 0)])))
        XCTAssertEqual(try platformZero.version()?.platform, 0)
    }

    func testShortVersionCommandsThrowLikeSecurity() throws {
        // MachOBase::version refuses an LC_BUILD_VERSION under 24 bytes and an LC_VERSION_MIN_* under 16, so codesign
        // cannot sign the slice: neither can fashion synthesize its ad-hoc identity.
        var shortBuild = Data()
        [UInt32(LC_BUILD_VERSION), 16, UInt32(PLATFORM_MACOS), 0x000f_0000].forEach { shortBuild.appendUInt32($0) }
        var shortMin = Data()
        [UInt32(LC_VERSION_MIN_MACOSX), 8].forEach { shortMin.appendUInt32($0) }

        for (command, expectedSize) in [(shortBuild, 24), (shortMin, 16)] {
            let slice = try XCTUnwrap(MachO(self.makeMachO(commands: [command])))
            let cmd = command.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }
            let expected = ParserError.truncatedLoadCommand(cmd: cmd, size: command.count, expectedSize: expectedSize)
            XCTAssertThrowsError(try slice.version()) { XCTAssertEqual($0 as? ParserError, expected) }
            XCTAssertThrowsError(try slice.codeDirectoryHashes(exact: false)) { XCTAssertEqual($0 as? ParserError, expected) }
        }
    }

    func testNonMachOIsNil() {
        XCTAssertNil(try MachO(Data("Hello, World!".utf8)))
    }

    // MARK: - code signature detection

    func testFindCodeSignatureUnsignedIsNil() throws {
        XCTAssertNil(try XCTUnwrap(MachO(self.makeMachO())).findCodeSignature())
    }

    func testFindCodeSignatureSignedIsBeforeEnd() throws {
        guard let file = try? File(path: "/bin/ls") else {
            throw XCTSkip("/bin/ls not readable")
        }
        let image: MachO? = switch try Universal.open(file) {
        case let .fat(archs): try MachO(file, offset: archs[0].range.lowerBound, length: archs[0].range.count)
        case let .thin(image): image
        case .notMachO: nil
        }
        let slice = try XCTUnwrap(image)
        // A signed slice's signature starts after the code and ends within the slice.
        let signature = try XCTUnwrap(try slice.findCodeSignature())
        XCTAssertGreaterThan(signature.offset, 0)
        XCTAssertLessThanOrEqual(signature.offset + signature.size, slice.length)
    }

    func testInvalidCodeSignatureRangeThrows() throws {
        let data = self.makeSignedEmptySuperblob(declaredSignatureOffset: 4096)
        let slice = try XCTUnwrap(MachO(data))
        let expected = CDHashError.invalidCodeSignatureRange(offset: 4096, size: 12, fileSize: data.count)

        XCTAssertThrowsError(try slice.codeDirectoryHashes(exact: false).hashes) { error in
            XCTAssertEqual(error as? CDHashError, expected)
        }

        let url = FileManager.default.temporaryDirectory / "fashion-invalid-code-signature-\(UUID())"
        try data.write(to: url)
        defer {
            try? FileManager.default.removeItem(at: url)
        }

        XCTAssertThrowsError(try CDHash.hash(path: url.path())) { error in
            XCTAssertEqual(error as? CDHashError, expected)
        }
    }

    func testCodeDirectoryOutsideDeclaredSuperblobThrows() throws {
        let data = self.makeCodeDirectoryOutsideDeclaredSuperblob()
        let slice = try XCTUnwrap(MachO(data))
        let expected = CDHashError.invalidCodeSignatureBlobRange(offset: 20, size: 38, signatureSize: 32)

        XCTAssertThrowsError(try slice.codeDirectoryHashes(exact: false).hashes) { error in
            XCTAssertEqual(error as? CDHashError, expected)
        }

        let url = FileManager.default.temporaryDirectory / "fashion-invalid-superblob-\(UUID())"
        try data.write(to: url)
        defer {
            try? FileManager.default.removeItem(at: url)
        }

        XCTAssertThrowsError(try CDHash.hash(path: url.path())) { error in
            XCTAssertEqual(error as? CDHashError, expected)
        }
    }

    func testTruncatedEmbeddedSignatureThrows() throws {
        var signature = Data()
        [0xfade_0cc0, 8].forEach { signature.appendUInt32BE($0) } // a superblob too short for its own header
        let data = self.makeSignedMachO(signature: signature)

        XCTAssertThrowsError(try CDHash.hash(data: data)) { error in
            XCTAssertEqual(error as? CDHashError, .truncatedCodeSignatureSuperblob(signatureSize: 8))
        }
    }

    func testEmbeddedSignatureWithInvalidMagicThrows() throws {
        var signature = Data()
        signature.appendUInt32BE(0x1234_5678)
        signature.appendUInt32BE(12)
        signature.appendUInt32BE(0)
        let data = self.makeSignedMachO(signature: signature)

        XCTAssertThrowsError(try CDHash.hash(data: data)) { error in
            XCTAssertEqual(error as? CDHashError, .invalidCodeSignatureMagic(magic: 0x1234_5678))
        }
    }

    // MARK: - Embedded signature bounds

    private func superblob(_ words: [UInt32], tail: Data = Data()) -> Data {
        var signature = Data()
        for word in words {
            signature.appendUInt32BE(word)
        }
        signature.append(tail)
        return signature
    }

    func testEmbeddedSignatureBoundsAreEnforced() throws {
        let magic: UInt32 = 0xfade_0cc0
        let padding = Data(repeating: 0, count: 4)
        let cases: [(name: String, signature: Data, expected: CDHashError)] = [
            ("superblob longer than the signature", self.superblob([magic, 64, 0]), .invalidCodeSignatureSuperblobLength(length: 64, signatureSize: 12)),
            ("superblob shorter than its header", self.superblob([magic, 8, 0]), .truncatedCodeSignatureSuperblob(signatureSize: 8)),
            ("index table past the superblob", self.superblob([magic, 12, 1]), .invalidCodeSignatureIndexTable(count: 1, length: 12)),
            ("blob inside the index table", self.superblob([magic, 20, 1, 0, 16]), .invalidCodeSignatureBlobOffset(offset: 16, signatureSize: 20)),
            ("blob header past the superblob", self.superblob([magic, 32, 1, 0, 28], tail: padding + padding + padding), .invalidCodeSignatureBlobOffset(offset: 28, signatureSize: 32)),
            ("blob shorter than its header", self.superblob([magic, 32, 1, 0x10000, 20, 0xfade_0b01, 4], tail: padding), .invalidCodeSignatureBlobRange(offset: 20, size: 4, signatureSize: 32)),
            ("blob past the superblob", self.superblob([magic, 32, 1, 0x10000, 20, 0xfade_0b01, 16], tail: padding), .invalidCodeSignatureBlobRange(offset: 20, size: 16, signatureSize: 32)),
        ]

        for (name, signature, expected) in cases {
            XCTAssertThrowsError(try CDHash.hash(data: self.makeSignedMachO(signature: signature)), name) { error in
                XCTAssertEqual(error as? CDHashError, expected, name)
            }
        }
    }

    func testMultipleCodeDirectoriesRankStrongestFirst() throws {
        // Primary slot: SHA-1. Alternates 0x1000 and 0x1001: SHA-256 and SHA-384, which xnu prefers in that order.
        let sha1 = self.codeDirectory(hashType: 1)
        let sha256 = self.codeDirectory(hashType: 2)
        let sha384 = self.codeDirectory(hashType: 4)
        let data = self.makeSignedMachO(signature: self.superblob(slots: [(0, sha1), (0x1000, sha256), (0x1001, sha384)]))
        let slice = try XCTUnwrap(MachO(data))
        let directories = try slice.codeDirectoryHashes(exact: false).hashes

        XCTAssertEqual(directories.map(\.type), ["sha384", "sha256", "sha1"])
        XCTAssertEqual(directories.map(\.hash), [SHA384.hash(data: sha384).hexString, SHA256.hash(data: sha256).hexString, Insecure.SHA1.hash(data: sha1).hexString])
        XCTAssertFalse(directories.contains { $0.adhoc })

        // With several directories the hash type is part of each reported line.
        let url = FileManager.default.temporaryDirectory / "fashion-multi-cd-\(UUID())"
        try data.write(to: url)
        defer {
            try? FileManager.default.removeItem(at: url)
        }

        XCTAssertEqual(try CDHash.hash(path: url.path()).map(\.type), ["sha384", "sha256", "sha1"])
    }

    func testCodeDirectoriesLoadLikeSecurity() throws {
        // SecStaticCode::loadCodeDirectories reads the primary slot, then alternates from 0x1000 up to the first one
        // missing, and the magic is never checked. SHA-512, which xnu does not know, ranks last.
        let sha1 = self.codeDirectory(hashType: 1)
        let sha256 = self.codeDirectory(hashType: 2)
        var badMagic = self.codeDirectory(hashType: 2)
        badMagic.replaceSubrange(0 ..< 4, with: [0x12, 0x34, 0x56, 0x78])
        let cases: [(name: String, slots: [(UInt32, Data)], expected: [String])] = [
            ("alternate after a gap", [(0, sha1), (0x1001, sha256)], [Insecure.SHA1.hash(data: sha1).hexString]),
            ("wrong magic", [(0, badMagic)], [SHA256.hash(data: badMagic).hexString]),
            ("SHA-512 alternate", [(0, sha1), (0x1000, self.codeDirectory(hashType: 5))], [Insecure.SHA1.hash(data: sha1).hexString, SHA512.hash(data: self.codeDirectory(hashType: 5)).hexString]),
        ]

        for (name, slots, expected) in cases {
            let slice = try XCTUnwrap(MachO(self.makeSignedMachO(signature: self.superblob(slots: slots))))
            XCTAssertEqual(try slice.codeDirectoryHashes(exact: false).hashes.map(\.hash), expected, name)
        }
    }

    func testRejectedCodeDirectoriesMakeTheSliceUnsigned() throws {
        // Security calls a slice whose code directories it cannot load "not signed at all", and codesign signs it ad
        // hoc up to where the signature starts (MachORep::signingLimit).
        func field(_ directory: Data, at offset: Int, _ value: UInt32) -> Data {
            var directory = directory
            var bigEndian = value.bigEndian
            directory.replaceSubrange(offset ..< offset + 4, with: Data(bytes: &bigEndian, count: 4))
            return directory
        }
        let sha256 = self.codeDirectory(hashType: 2)
        var truncated = field(sha256, at: 4, 47) // length: one byte short of the 0x20100 header
        truncated.removeLast(3)
        var unterminated = sha256
        unterminated[unterminated.endIndex - 1] = 0x79 // identifier without its NUL
        let cases: [(name: String, slots: [(UInt32, Data)])] = [
            ("no code directory", []),
            ("no primary slot", [(0x1000, sha256)]),
            ("header shorter than its version's", [(0, truncated)]),
            ("version below 0x20001", [(0, field(sha256, at: 8, 0x20000))]),
            ("version above 0x2f000", [(0, field(sha256, at: 8, 0x2f001))]),
            ("unknown hash type", [(0, self.codeDirectory(hashType: 9))]),
            ("hash size of another type", [(0, self.codeDirectory(hashType: 2, hashSize: 20))]),
            ("identifier past the end", [(0, field(sha256, at: 20, 50))]),
            ("identifier unterminated", [(0, unterminated)]),
            ("special slots before the header", [(0, field(field(sha256, at: 24, 2), at: 16, 50))]),
            ("code slots past the end", [(0, field(sha256, at: 28, 1))]),
            ("unpaged code limit without a slot", [(0, field(sha256, at: 32, 1))]),
            ("scatter vector past the end", [(0, field(sha256, at: 44, 40))]),
            ("two directories of one hash type", [(0, sha256), (0x1000, sha256)]),
            ("one bad alternate", [(0, self.codeDirectory(hashType: 1)), (0x1000, self.codeDirectory(hashType: 9))]),
        ]

        for (name, slots) in cases {
            let slice = try XCTUnwrap(MachO(self.makeSignedMachO(signature: self.superblob(slots: slots))))
            let (hashes, skipReason) = try slice.codeDirectoryHashes(exact: false)
            XCTAssertNil(skipReason, name)
            XCTAssertEqual(hashes.map(\.adhoc), [true, true], name)
        }
    }

    // MARK: - Ad-hoc synthesis (unsigned slice)

    func testUnsignedSliceSynthesizesAdhoc() throws {
        let slice = try XCTUnwrap(MachO(self.makeMachO()))
        let directories = try slice.codeDirectoryHashes(exact: false).hashes

        // An unsigned slice yields both synthesized ad-hoc cdhashes: SHA-256 first, then SHA-1.
        XCTAssertEqual(directories.count, 2)

        let sha256 = try XCTUnwrap(directories.first)
        XCTAssertTrue(sha256.adhoc, "An unsigned slice yields the synthesized ad-hoc cdhash")
        XCTAssertEqual(sha256.type, "sha256")
        XCTAssertEqual(sha256.hash.count, 64) // full SHA-256 of the SHA-256 CodeDirectory
        XCTAssertTrue(sha256.hash.allSatisfy(\.isHexDigit))

        let sha1 = try XCTUnwrap(directories.last)
        XCTAssertTrue(sha1.adhoc)
        XCTAssertEqual(sha1.type, "sha1")
        XCTAssertEqual(sha1.hash.count, 40) // full SHA-1 of the SHA-1 CodeDirectory
        XCTAssertTrue(sha1.hash.allSatisfy(\.isHexDigit))

        // Deterministic.
        XCTAssertEqual(directories.map(\.hash), try MachO(self.makeMachO())?.codeDirectoryHashes(exact: false).hashes.map(\.hash))
    }

    func testExactStripsTrailingGarbage() throws {
        let clean = self.makeMachO(segment: "__LINKEDIT", fileSize: 256) // the image ends with __LINKEDIT
        let cleanHashes = try XCTUnwrap(try MachO(clean)?.codeDirectoryHashes(exact: false).hashes.map(\.hash))

        var dirty = clean
        dirty.append(Data(repeating: 0x41, count: 100))

        let dirtyExact = try MachO(dirty)?.codeDirectoryHashes(exact: true).hashes.map(\.hash)
        let dirtyWhole = try MachO(dirty)?.codeDirectoryHashes(exact: false).hashes.map(\.hash)
        XCTAssertEqual(dirtyExact, cleanHashes, "Exact must strip appended garbage (both cdhashes)")
        XCTAssertNotEqual(dirtyWhole, cleanHashes, "Whole-slice adhoc must include garbage")
    }

    func testOnlyCodeFiletypesSynthesizeAdhoc() throws {
        // codesign signs only these filetypes as Mach-O code. Any other one, an unknown 0x1d included, is a generic
        // file to it, so an unsigned slice of that filetype has no ad-hoc cdhash.
        let code: [Int32] = [MH_EXECUTE, MH_PRELOAD, MH_DYLIB, MH_DYLINKER, MH_BUNDLE, MH_KEXT_BUNDLE]
        for filetype in code + [MH_OBJECT, MH_FVMLIB, MH_CORE, MH_DYLIB_STUB, MH_DSYM, MH_FILESET, MH_GPU_EXECUTE, MH_GPU_DYLIB, 0x1d] {
            let slice = try XCTUnwrap(MachO(self.makeMachO(filetype: UInt32(filetype))))
            let (hashes, skipReason) = try slice.codeDirectoryHashes(exact: false)
            XCTAssertEqual(hashes.count, code.contains(filetype) ? 2 : 0, slice.filetypeName)
            XCTAssertEqual(skipReason == nil, code.contains(filetype), slice.filetypeName)
        }
    }

    func testFiletypeNames() throws {
        XCTAssertEqual(try XCTUnwrap(MachO(self.makeMachO(filetype: UInt32(MH_EXECUTE)))).filetypeName, "MH_EXECUTE")
        XCTAssertEqual(try XCTUnwrap(MachO(self.makeMachO(filetype: UInt32(MH_GPU_DYLIB)))).filetypeName, "MH_GPU_DYLIB")
        XCTAssertEqual(try XCTUnwrap(MachO(self.makeMachO(filetype: 0x1d))).filetypeName, "unknown(29)")
    }

    // MARK: - CDHash integration

    func testCDHashTagsUnsignedSliceAdhoc() throws {
        let url = FileManager.default.temporaryDirectory / "fashion-unsigned-\(UUID())"
        try self.makeMachO().write(to: url)
        defer {
            try? FileManager.default.removeItem(at: url)
        }

        let results = try CDHash.hash(path: url.path())
        XCTAssertEqual(results.count, 2, "an unsigned thin slice yields both ad-hoc cdhashes")

        for result in results {
            XCTAssertTrue(result.adhoc, "CDHash tags an unsigned slice ADHOC")
            XCTAssertNil(result.arch, "thin binary → nil arch")
        }

        XCTAssertEqual(results.map(\.hash), try MachO(self.makeMachO())?.codeDirectoryHashes(exact: false).hashes.map(\.hash))
    }

    func testSignatureWithoutCodeDirectoryIsAdhocUpToTheSignature() throws {
        // codesign calls a slice whose superblob holds no code directory unsigned, and signs it up to the signature.
        let data = self.makeSignedEmptySuperblob()
        let slice = try XCTUnwrap(MachO(data))
        let (hashes, skipReason) = try slice.codeDirectoryHashes(exact: false)
        XCTAssertNil(skipReason)
        XCTAssertEqual(hashes.map(\.adhoc), [true, true])

        // Whatever follows the signature's offset is not code; what precedes it is.
        var afterSignature = data
        afterSignature.append(Data(repeating: 0xee, count: 64))
        XCTAssertEqual(try XCTUnwrap(MachO(afterSignature)).codeDirectoryHashes(exact: false).hashes.map(\.hash), hashes.map(\.hash))

        var beforeSignature = data
        beforeSignature[127] ^= 0xff
        XCTAssertNotEqual(try XCTUnwrap(MachO(beforeSignature)).codeDirectoryHashes(exact: false).hashes.map(\.hash), hashes.map(\.hash))
    }
}
