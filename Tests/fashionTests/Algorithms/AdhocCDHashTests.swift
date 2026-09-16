import CryptoKit
@testable import fashion
import MachO
import XCTest

/**
 Ad-hoc cdhash synthesis for unsigned slices, and the `MachOSlice` accessors that feed it.
 */
final class AdhocCDHashTests: XCTestCase {
    /**
     A minimal native-endian thin 64-bit Mach-O with a single `__TEXT` segment covering `[0, fileSize)`.
     Unsigned, so `CDHash`/`MachOSlice` synthesize its ad-hoc cdhash.
     */
    private func makeMachO(cpuType: cpu_type_t = CPU_TYPE_ARM64, filetype: UInt32 = UInt32(MH_EXECUTE), fileSize: Int = 256) -> Data {
        var data = Data()
        data.appendUInt32(MH_MAGIC_64)
        data.appendInt32(cpuType)
        data.appendInt32(0) // cpusubtype
        data.appendUInt32(filetype)
        data.appendUInt32(1) // ncmds
        data.appendUInt32(72) // sizeofcmds (segment_command_64)
        data.appendUInt32(0) // flags
        data.appendUInt32(0) // reserved
        // LC_SEGMENT_64
        data.appendUInt32(UInt32(LC_SEGMENT_64))
        data.appendUInt32(72) // cmdsize
        data.append(Data("__TEXT".utf8)); data.append(Data(repeating: 0, count: 10)) // segname[16]
        data.appendUInt64(0) // vmaddr
        data.appendUInt64(UInt64(fileSize)) // vmsize
        data.appendUInt64(0) // fileoff
        data.appendUInt64(UInt64(fileSize)) // filesize
        data.appendUInt32(7) // maxprot
        data.appendUInt32(5) // initprot
        data.appendUInt32(0) // nsects
        data.appendUInt32(0) // flags
        data.append(Data(repeating: 0xab, count: fileSize - data.count)) // segment content
        return data
    }

    private func makeSignedMachO(signature: Data, declaredSignatureOffset: UInt32 = 128) -> Data {
        var data = Data()
        data.appendUInt32(MH_MAGIC_64)
        data.appendInt32(CPU_TYPE_ARM64)
        data.appendInt32(0)
        data.appendUInt32(UInt32(MH_EXECUTE))
        data.appendUInt32(2) // ncmds
        data.appendUInt32(88) // sizeofcmds (72 + 16)
        data.appendUInt32(0)
        data.appendUInt32(0)
        // LC_SEGMENT_64 __TEXT covering [0, 128)
        data.appendUInt32(UInt32(LC_SEGMENT_64))
        data.appendUInt32(72)
        data.append(Data("__TEXT".utf8)); data.append(Data(repeating: 0, count: 10))
        data.appendUInt64(0); data.appendUInt64(128); data.appendUInt64(0); data.appendUInt64(128)
        data.appendUInt32(7); data.appendUInt32(5); data.appendUInt32(0); data.appendUInt32(0)
        // LC_CODE_SIGNATURE → an empty superblob at offset 128, size 12
        data.appendUInt32(UInt32(LC_CODE_SIGNATURE))
        data.appendUInt32(16)
        data.appendUInt32(declaredSignatureOffset) // dataoff
        data.appendUInt32(UInt32(signature.count)) // datasize
        data.append(Data(repeating: 0, count: 128 - data.count)) // pad to dataoff
        data.append(signature)
        return data
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

    // MARK: - execSegment

    func testExecSegmentExecutable() throws {
        let exec = try XCTUnwrap(MachOSlice(self.makeMachO(fileSize: 256))).execSegment()
        XCTAssertEqual(exec.base, 0)
        XCTAssertEqual(exec.limit, 256)
        XCTAssertEqual(exec.flags, 1) // CS_EXECSEG_MAIN_BINARY
    }

    func testExecSegmentDylibHasNoMainFlag() throws {
        let exec = try XCTUnwrap(MachOSlice(self.makeMachO(filetype: UInt32(MH_DYLIB), fileSize: 256))).execSegment()
        XCTAssertEqual(exec.flags, 0)
    }

    func testExecSegmentNonMachOReturnsNil() {
        XCTAssertNil(try MachOSlice(Data("Hello, World!".utf8)))
    }

    // MARK: - code signature detection

    func testCodeSignatureRangeUnsignedIsNil() throws {
        XCTAssertNil(try XCTUnwrap(MachOSlice(self.makeMachO())).codeSignatureRange())
    }

    func testCodeSignatureRangeSignedIsBeforeEnd() throws {
        guard let data = try? FileReader.map(path: "/bin/ls") else {
            throw XCTSkip("/bin/ls not readable")
        }
        let sliceData: Data = switch try MachOParser.open(data: data) {
        case let .fat(archs): MachOParser.sliceData(fileData: data, arch: archs[0])
        case .thin: data
        case .notMachO: Data()
        }
        let slice = try XCTUnwrap(MachOSlice(sliceData))
        // A signed slice's signature starts after the code and ends within the slice.
        let range = try XCTUnwrap(try slice.codeSignatureRange())
        XCTAssertGreaterThan(range.lowerBound, 0)
        XCTAssertLessThanOrEqual(range.upperBound, slice.data.count)
    }

    func testInvalidCodeSignatureRangeThrows() throws {
        let data = self.makeSignedEmptySuperblob(declaredSignatureOffset: 4096)
        let slice = try XCTUnwrap(MachOSlice(data))
        let expected = ParserError.invalidCodeSignatureRange(offset: 4096, size: 12, fileSize: data.count)

        XCTAssertThrowsError(try slice.codeSignatureRange()) { error in
            XCTAssertEqual(error as? ParserError, expected)
        }
        XCTAssertThrowsError(try slice.codeDirectoryHashes(exact: false)) { error in
            XCTAssertEqual(error as? ParserError, expected)
        }

        let url = FileManager.default.temporaryDirectory / "fashion-invalid-code-signature-\(UUID())"
        try data.write(to: url)
        defer {
            try? FileManager.default.removeItem(at: url)
        }

        XCTAssertThrowsError(try CDHash.hash(path: url.path())) { error in
            XCTAssertEqual(error as? ParserError, expected)
        }
    }

    func testCodeDirectoryOutsideDeclaredSuperblobThrows() throws {
        let data = self.makeCodeDirectoryOutsideDeclaredSuperblob()
        let slice = try XCTUnwrap(MachOSlice(data))
        let expected = ParserError.invalidCodeDirectoryRange(offset: 20, size: 38, signatureSize: 32)

        XCTAssertThrowsError(try slice.codeDirectoryHashes(exact: false)) { error in
            XCTAssertEqual(error as? ParserError, expected)
        }

        let url = FileManager.default.temporaryDirectory / "fashion-invalid-superblob-\(UUID())"
        try data.write(to: url)
        defer {
            try? FileManager.default.removeItem(at: url)
        }

        XCTAssertThrowsError(try CDHash.hash(path: url.path())) { error in
            XCTAssertEqual(error as? ParserError, expected)
        }
    }

    func testTruncatedEmbeddedSignatureThrows() throws {
        let data = self.makeSignedMachO(signature: Data(repeating: 0, count: 8))

        XCTAssertThrowsError(try CDHash.hash(data: data)) { error in
            XCTAssertEqual(error as? ParserError, .truncatedCodeSignatureSuperblob(signatureSize: 8))
        }
    }

    func testEmbeddedSignatureWithInvalidMagicThrows() throws {
        var signature = Data()
        signature.appendUInt32BE(0x1234_5678)
        signature.appendUInt32BE(12)
        signature.appendUInt32BE(0)
        let data = self.makeSignedMachO(signature: signature)

        XCTAssertThrowsError(try CDHash.hash(data: data)) { error in
            XCTAssertEqual(error as? ParserError, .invalidCodeSignatureMagic(magic: 0x1234_5678))
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
        let directoryMagic: UInt32 = 0xfade_0c02
        let padding = Data(repeating: 0, count: 4)
        let cases: [(name: String, signature: Data, expected: ParserError)] = [
            ("superblob longer than the signature", self.superblob([magic, 64, 0]), .invalidCodeSignatureSuperblobLength(length: 64, signatureSize: 12)),
            ("superblob shorter than its header", self.superblob([magic, 8, 0]), .invalidCodeSignatureSuperblobLength(length: 8, signatureSize: 12)),
            ("index table past the superblob", self.superblob([magic, 12, 1]), .invalidCodeSignatureIndexTable(count: 1, length: 12)),
            ("CodeDirectory offset past the superblob", self.superblob([magic, 20, 1, 0, 16]), .invalidCodeDirectoryOffset(offset: 16, signatureSize: 20)),
            ("wrong CodeDirectory magic", self.superblob([magic, 32, 1, 0, 20, 0x1234_5678, 12], tail: padding), .invalidCodeDirectoryMagic(offset: 20, magic: 0x1234_5678)),
            ("CodeDirectory shorter than its fixed header", self.superblob([magic, 32, 1, 0, 20, directoryMagic, 12], tail: padding), .truncatedCodeDirectory(offset: 20, length: 12)),
        ]

        for (name, signature, expected) in cases {
            XCTAssertThrowsError(try CDHash.hash(data: self.makeSignedMachO(signature: signature)), name) { error in
                XCTAssertEqual(error as? ParserError, expected, name)
            }
        }
    }

    func testMultipleCodeDirectoriesRankStrongestFirst() throws {
        // Primary slot: SHA-1. Alternate slot 0x1000: SHA-256. Alternate 0x1001: an unknown hash type, dropped.
        func codeDirectory(hashType: UInt8) -> Data {
            var directory = Data()
            directory.appendUInt32BE(0xfade_0c02)
            directory.appendUInt32BE(40)
            directory.append(Data(repeating: 0, count: 29))
            directory.append(hashType) // offset 37
            directory.append(Data(repeating: 0, count: 2))
            return directory
        }
        let sha1 = codeDirectory(hashType: 1)
        let sha256 = codeDirectory(hashType: 2)
        let unknown = codeDirectory(hashType: 9)
        // 12-byte header, three 8-byte index entries, then the three 40-byte directories.
        var signature = self.superblob([0xfade_0cc0, 156, 3, 0, 36, 0x1000, 76, 0x1001, 116])
        signature.append(sha1)
        signature.append(sha256)
        signature.append(unknown)
        let data = self.makeSignedMachO(signature: signature)

        let slice = try XCTUnwrap(MachOSlice(data))
        let directories = try slice.codeDirectoryHashes(exact: false)

        XCTAssertEqual(directories.map(\.type), ["sha256", "sha1"])
        XCTAssertEqual(directories.map(\.hash), [SHA256.hash(data: sha256).hexString, Insecure.SHA1.hash(data: sha1).hexString])
        XCTAssertFalse(directories.contains { $0.adhoc })

        // With several directories the hash type is part of each reported line.
        let url = FileManager.default.temporaryDirectory / "fashion-multi-cd-\(UUID())"
        try data.write(to: url)
        defer {
            try? FileManager.default.removeItem(at: url)
        }

        XCTAssertEqual(try CDHash.hash(path: url.path()).map(\.type), ["sha256", "sha1"])
    }

    // MARK: - Ad-hoc synthesis (unsigned slice)

    func testUnsignedSliceSynthesizesAdhoc() throws {
        let slice = try XCTUnwrap(MachOSlice(self.makeMachO()))
        let directories = try slice.codeDirectoryHashes(exact: false)

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
        XCTAssertEqual(directories.map(\.hash), try MachOSlice(self.makeMachO())?.codeDirectoryHashes(exact: false).map(\.hash))
    }

    func testExactStripsTrailingGarbage() throws {
        let clean = self.makeMachO(fileSize: 256)
        let cleanHashes = try XCTUnwrap(try MachOSlice(clean)?.codeDirectoryHashes(exact: false).map(\.hash))

        var dirty = clean
        dirty.append(Data(repeating: 0x41, count: 100))

        let dirtyExact = try MachOSlice(dirty)?.codeDirectoryHashes(exact: true).map(\.hash)
        let dirtyWhole = try MachOSlice(dirty)?.codeDirectoryHashes(exact: false).map(\.hash)
        XCTAssertEqual(dirtyExact, cleanHashes, "Exact must strip appended garbage (both cdhashes)")
        XCTAssertNotEqual(dirtyWhole, cleanHashes, "Whole-slice adhoc must include garbage")
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

        XCTAssertEqual(results.map(\.hash), try MachOSlice(self.makeMachO())?.codeDirectoryHashes(exact: false).map(\.hash))
    }

    func testSignedButUnparseableSliceIsNotAdhoc() throws {
        // A slice that carries a signature but no parseable code directory is still signed: it must yield
        // no cdhash rather than be relabeled ADHOC (that identity is for unsigned code only).
        let slice = try XCTUnwrap(MachOSlice(self.makeSignedEmptySuperblob()))
        XCTAssertNotNil(try slice.codeSignatureRange(), "fixture must be recognized as signed")
        XCTAssertTrue(try slice.codeDirectoryHashes(exact: false).isEmpty, "signed-but-unreadable slice → no output, never ADHOC")
    }
}
