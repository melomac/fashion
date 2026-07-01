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
        var d = Data()
        d.append32(MH_MAGIC_64)
        d.append32i(cpuType)
        d.append32i(0) // cpusubtype
        d.append32(filetype)
        d.append32(1) // ncmds
        d.append32(72) // sizeofcmds (segment_command_64)
        d.append32(0) // flags
        d.append32(0) // reserved
        // LC_SEGMENT_64
        d.append32(UInt32(LC_SEGMENT_64))
        d.append32(72) // cmdsize
        d.append(Data("__TEXT".utf8)); d.append(Data(repeating: 0, count: 10)) // segname[16]
        d.append64(0) // vmaddr
        d.append64(UInt64(fileSize)) // vmsize
        d.append64(0) // fileoff
        d.append64(UInt64(fileSize)) // filesize
        d.append32(7) // maxprot
        d.append32(5) // initprot
        d.append32(0) // nsects
        d.append32(0) // flags
        d.append(Data(repeating: 0xab, count: fileSize - d.count)) // segment content
        return d
    }

    /**
     A thin arm64 Mach-O that IS signed (carries `LC_CODE_SIGNATURE`) but whose embedded signature is a
     well-formed empty superblob (magic `0xfade0cc0`, count 0) — so no code directory parses out of it.
     */
    private func makeSignedEmptySuperblob() -> Data {
        var d = Data()
        d.append32(MH_MAGIC_64)
        d.append32i(CPU_TYPE_ARM64)
        d.append32i(0)
        d.append32(UInt32(MH_EXECUTE))
        d.append32(2) // ncmds
        d.append32(88) // sizeofcmds (72 + 16)
        d.append32(0)
        d.append32(0)
        // LC_SEGMENT_64 __TEXT covering [0, 128)
        d.append32(UInt32(LC_SEGMENT_64))
        d.append32(72)
        d.append(Data("__TEXT".utf8)); d.append(Data(repeating: 0, count: 10))
        d.append64(0); d.append64(128); d.append64(0); d.append64(128)
        d.append32(7); d.append32(5); d.append32(0); d.append32(0)
        // LC_CODE_SIGNATURE → an empty superblob at offset 128, size 12
        d.append32(UInt32(LC_CODE_SIGNATURE))
        d.append32(16)
        d.append32(128) // dataoff
        d.append32(12) // datasize
        d.append(Data(repeating: 0, count: 128 - d.count)) // pad to dataoff
        // Embedded signature superblob (big-endian): magic 0xfade0cc0, length 12, count 0.
        d.append(Data([0xfa, 0xde, 0x0c, 0xc0, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00]))
        return d
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
        XCTAssertNil(MachOSlice(Data("Hello, World!".utf8)))
    }

    // MARK: - code signature detection

    func testCodeSignatureRangeUnsignedIsNil() throws {
        XCTAssertNil(try XCTUnwrap(MachOSlice(self.makeMachO())).codeSignatureRange())
    }

    func testCodeSignatureRangeSignedIsBeforeEnd() throws {
        guard let data = try? FileReader.map(path: "/bin/ls") else {
            throw XCTSkip("/bin/ls not readable")
        }
        let sliceData: Data = switch MachOParser.open(data: data) {
        case let .fat(archs): MachOParser.sliceData(fileData: data, arch: archs[0])
        case .thin: data
        case .notMachO: Data()
        }
        let slice = try XCTUnwrap(MachOSlice(sliceData))
        // A signed slice's signature starts after the code and ends within the slice.
        let range = try XCTUnwrap(slice.codeSignatureRange())
        XCTAssertGreaterThan(range.lowerBound, 0)
        XCTAssertLessThanOrEqual(range.upperBound, slice.data.count)
    }

    // MARK: - Ad-hoc synthesis (unsigned slice)

    func testUnsignedSliceSynthesizesAdhoc() throws {
        let slice = try XCTUnwrap(MachOSlice(self.makeMachO()))
        let directories = slice.codeDirectoryHashes(exact: false)

        XCTAssertEqual(directories.count, 1)
        let cd = try XCTUnwrap(directories.first)
        XCTAssertTrue(cd.adhoc, "An unsigned slice yields the synthesized ad-hoc cdhash")
        XCTAssertEqual(cd.type, "adhoc")
        XCTAssertEqual(cd.hash.count, 64) // full SHA-256 of the CodeDirectory
        XCTAssertTrue(cd.hash.allSatisfy(\.isHexDigit))

        // Deterministic.
        XCTAssertEqual(cd.hash, MachOSlice(self.makeMachO())?.codeDirectoryHashes(exact: false).first?.hash)
    }

    func testExactStripsTrailingGarbage() throws {
        let clean = self.makeMachO(fileSize: 256)
        let cleanHash = try XCTUnwrap(MachOSlice(clean)?.codeDirectoryHashes(exact: false).first?.hash)

        var dirty = clean
        dirty.append(Data(repeating: 0x41, count: 100))

        let dirtyExact = MachOSlice(dirty)?.codeDirectoryHashes(exact: true).first?.hash
        let dirtyWhole = MachOSlice(dirty)?.codeDirectoryHashes(exact: false).first?.hash
        XCTAssertEqual(dirtyExact, cleanHash, "Exact must strip appended garbage")
        XCTAssertNotEqual(dirtyWhole, cleanHash, "Whole-slice adhoc must include garbage")
    }

    // MARK: - CDHash integration

    func testCDHashTagsUnsignedSliceAdhoc() throws {
        let url = FileManager.default.temporaryDirectory / "fashion-unsigned-\(UUID())"
        try self.makeMachO().write(to: url)
        defer {
            try? FileManager.default.removeItem(at: url)
        }

        let first = try XCTUnwrap(CDHash.hash(path: url.path()).first)
        XCTAssertTrue(first.adhoc, "CDHash tags an unsigned slice ADHOC")
        XCTAssertNil(first.arch, "thin binary → nil arch")
        XCTAssertEqual(first.hash, MachOSlice(self.makeMachO())?.codeDirectoryHashes(exact: false).first?.hash)
    }

    func testSignedButUnparseableSliceIsNotAdhoc() throws {
        // A slice that carries a signature but no parseable code directory is still signed: it must yield
        // no cdhash rather than be relabeled ADHOC (that identity is for unsigned code only).
        let slice = try XCTUnwrap(MachOSlice(self.makeSignedEmptySuperblob()))
        XCTAssertNotNil(slice.codeSignatureRange(), "fixture must be recognized as signed")
        XCTAssertTrue(slice.codeDirectoryHashes(exact: false).isEmpty, "signed-but-unreadable slice → no output, never ADHOC")
    }
}

private extension Data {
    mutating func append32(_ value: UInt32) {
        var v = value
        append(Data(bytes: &v, count: 4))
    }

    mutating func append32i(_ value: Int32) {
        var v = value
        append(Data(bytes: &v, count: 4))
    }

    mutating func append64(_ value: UInt64) {
        var v = value
        append(Data(bytes: &v, count: 8))
    }
}
