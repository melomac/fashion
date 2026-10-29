@testable import fashion
import XCTest
import zlib

/**
 `unpack`: a Mach-O UPX packed, given back as it was before packing, as `upx -d` gives it back, and where `upx -d`
 gives up, behind a signature added after packing. The packed fixtures are made at test time by the `upx` installed,
 with --force-macos, since UPX 4.2 no longer packs for macOS by default, and signed after packing by the Developer ID
 `local.xcconfig` names, or ad hoc without one.
 */
final class PackMachTests: XCTestCase {
    /// The package, three folders up from this file.
    private static let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()

    /**
     The folder a test makes its files in, kept after it as the fuzzer keeps its own under `.build/fuzz`: the packed
     and unpacked files of the last run of each test stay in `.build/tests/PackMachTests/<name>` to look at, until the
     next run empties it.
     */
    private func directory(_ name: String) throws -> URL {
        let url = Self.root / ".build/tests/PackMachTests/\(name)"
        try? FileManager.default.removeItem(at: url)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    /**
     The `upx` installed, on `PATH` or where a build from source, Homebrew and MacPorts put it, which `xcodebuild`'s `PATH`
     may not hold, in that order, so a devel build in /usr/local/bin is found before a release; skips the test without one,
     since not everyone may install it.
     */
    private func upx() throws -> String {
        let directories = (ProcessInfo.processInfo.environment["PATH"] ?? "").split(separator: ":").map(String.init) + ["/usr/local/bin", "/opt/homebrew/bin", "/opt/local/bin"]
        guard let path = directories.map({ $0 + "/upx" }).first(where: { FileManager.default.isExecutableFile(atPath: $0) }) else {
            throw XCTSkip("upx unavailable: brew install upx")
        }
        return path
    }

    /// `file` packed by UPX with `options` into `<file>_packed` beside it, made anew; skips the test when UPX does not
    /// pack it.
    private func packed(_ file: URL, _ options: [String] = []) throws -> URL {
        let packed = URL(fileURLWithPath: file.path + "_packed")
        try? FileManager.default.removeItem(at: packed)
        try XCTSkipUnless(execute(self.upx(), ["-q", "--force-macos"] + options + ["-o", packed.path, file.path]), "upx cannot pack it")
        saveFixture(path: packed.path)
        return packed
    }

    /**
     The signing identity `local.xcconfig` names, `CODE_SIGN_IDENTITY`, the Developer ID releases are signed with on
     the user's Mac; "-", ad hoc, without the file or the line, so the tests sign everywhere.
     */
    private static let identity: String = {
        let lines = (try? String(contentsOf: PackMachTests.root / "local.xcconfig", encoding: .utf8))?.split(separator: "\n") ?? []
        let settings = lines.map { $0.split(separator: "=", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) } }
        return settings.first { $0.count == 2 && $0[0] == "CODE_SIGN_IDENTITY" }?[1] ?? "-"
    }()

    /// `file` signed into `<file><suffix>` beside it, made anew: a sample signed after packing, by `identity`, without
    /// the timestamp a Developer ID signature asks a server for.
    private func resigned(_ file: URL, by identity: String = PackMachTests.identity, as suffix: String = "_resigned") throws -> URL {
        let resigned = URL(fileURLWithPath: file.path + suffix)
        try? FileManager.default.removeItem(at: resigned)
        try FileManager.default.copyItem(at: file, to: resigned)
        _ = try codesign(["-s", identity, "--timestamp=none", resigned.path])
        saveFixture(path: resigned.path)
        return resigned
    }

    /// The `x86_64` and arm64e slices of `/bin/ls` without their signature, as thin --unsign writes them, by name.
    private func unsignedLs(in directory: URL) throws -> [(name: String, file: URL, data: Data)] {
        let ls = directory / "ls"
        try FileManager.default.copyItem(at: URL(fileURLWithPath: "/bin/ls"), to: ls)
        _ = Thinner.lines(for: ls.path, exact: false, unsign: true, unpack: false, write: false, reporter: Reporter(console: Console()))
        let slices = try ["x86_64", "arm64e"].map { ($0, directory / "ls_\($0)_unsigned") }.filter { FileManager.default.fileExists(atPath: $0.1.path) }.map { try ($0.0, $0.1, Data(contentsOf: $0.1)) }
        try XCTSkipIf(slices.isEmpty, "/bin/ls has neither an x86_64 nor an arm64e slice")
        return slices
    }

    /// The lines hash mode prints for `path` with `arguments`.
    private func hashLines(_ path: String, _ arguments: [String] = []) throws -> [String] {
        try Digester(Hasher.parse([path, "--quiet"] + arguments)).lines(for: path, reporter: Reporter(console: Console())).map(\.text)
    }

    /// Each block of `packed`, from UPX's `p_info` up to the original's size: where its bytes lie, its sizes, method
    /// and filter, as its `b_info` has them.
    private func blocks(of packed: Data) throws -> [(offset: Int, uncompressed: Int, compressed: Int, method: UInt8, filter: UInt8)] {
        let header = try XCTUnwrap(packed.ranges(of: Data("UPX!".utf8)).last).lowerBound
        func word(_ at: Int) -> Int {
            Int(packed[at ..< at + 4].withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }.littleEndian)
        }
        let overlay = word(header + 32)
        let fileSize = word(overlay + 4)
        var blocks: [(offset: Int, uncompressed: Int, compressed: Int, method: UInt8, filter: UInt8)] = []
        var cursor = overlay + 12
        var total = 0
        while total < fileSize {
            let (uncompressed, compressed) = (word(cursor), word(cursor + 4))
            blocks.append((cursor + 12, uncompressed, compressed, packed[cursor + 8], packed[cursor + 9]))
            cursor += 12 + compressed
            total += uncompressed
        }
        return blocks
    }

    /// The Adler-32 of the blocks' packed bytes of `packed`, in order, as the packer sums them into `c_adler`.
    private func cAdler(of packed: Data) throws -> UInt32 {
        var sum: uLong = 1
        for block in try self.blocks(of: packed) {
            sum = packed[block.offset ..< block.offset + block.compressed].withUnsafeBytes { adler32(sum, $0.baseAddress!.assumingMemoryBound(to: Bytef.self), uInt(block.compressed)) }
        }
        return UInt32(sum)
    }

    /// `packed` with its pack header's `c_adler` summed over its blocks' packed bytes as they are, as the packer summed
    /// them, and the header's own checksum with it.
    private func resummed(_ packed: Data) throws -> Data {
        var packed = packed
        let header = try XCTUnwrap(packed.ranges(of: Data("UPX!".utf8)).last).lowerBound
        let sum = try self.cAdler(of: packed)
        packed.replaceSubrange(header + 12 ..< header + 16, with: withUnsafeBytes(of: sum.littleEndian) { Data($0) })
        packed[header + 31] = UInt8(packed[header + 4 ..< header + 31].reduce(0) { $0 + Int($1) } % 251)
        return packed
    }

    /// `stream`, an NRV2B stream read 32 bits at a time, decompressed into `count` bytes.
    private func decompressed(_ stream: Data, count: Int) -> Data {
        var output = Data(count: count)
        let holds = (stream + Data(count: UCLBridge.slack)).withUnsafeBytes { source in
            output.withUnsafeMutableBytes { UCLBridge.decompress(source, count: stream.count, method: 2, into: $0) }
        }
        XCTAssertEqual(holds, true)
        return output
    }

    /**
     `block`, an NRV2B stream read 32 bits at a time as UPX packs `x86_64` and arm64, with each literal byte XORed with
     `key`: the stream of the block's bytes XORed with `key`, as a match copies what literals made. UCL's `n2b_d.c`,
     keeping the stream rather than decoding it.
     */
    private static func xoringLiterals(of block: Data, with key: UInt8) -> Data {
        var block = Data(block)
        var ilen = 0
        var bb: UInt32 = 0
        var bc = 0
        func getbit() -> UInt32 {
            if bc > 0 {
                bc -= 1
                return (bb >> UInt32(bc)) & 1
            }
            bc = 31
            bb = block[ilen ..< ilen + 4].withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }.littleEndian
            ilen += 4
            return (bb >> 31) & 1
        }
        while true {
            while getbit() == 1 {
                block[ilen] ^= key
                ilen += 1
            }
            var mOff: UInt32 = 1
            repeat {
                mOff = mOff &* 2 &+ getbit()
            } while getbit() == 0
            if mOff != 2 {
                mOff = (mOff &- 3) &* 256 &+ UInt32(block[ilen])
                ilen += 1
                if mOff == 0xffff_ffff {
                    break
                }
            }
            if getbit() * 2 + getbit() == 0 {
                repeat {
                    _ = getbit()
                } while getbit() == 0
            }
        }
        return block
    }

    /**
     Each compression method UPX packs Mach-O with, `x86_64` and arm64, each in a folder of its own: unpack gives
     the image back byte for byte, as upx -d does, and thin writes it out. An image UPX did not pack is left as it is.
     */
    func testUnpackRestoresWhatUPXPacked() throws {
        let directory = try self.directory("methods")
        for (name, unsigned, original) in try self.unsignedLs(in: directory) {
            let digest = try XCTUnwrap(ByteHash.sha256.digest(original))
            XCTAssertEqual(try self.hashLines(unsigned.path, ["--unpack"]), [digest])
            for method in ["--nrv2b", "--nrv2d", "--nrv2e", "--lzma"] {
                let folder = directory / String(method.dropFirst(2))
                try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
                let source = folder / unsigned.lastPathComponent
                try FileManager.default.copyItem(at: unsigned, to: source)
                let file = try self.packed(source, [method])
                XCTAssertNotEqual(try Data(contentsOf: file), original)
                XCTAssertEqual(try self.hashLines(file.path, ["--unpack"]), [digest], "\(name) \(method)")

                let artifact = URL(fileURLWithPath: file.path + "_unpacked")
                XCTAssertEqual(Thinner.lines(for: file.path, exact: false, unsign: false, unpack: true, write: false, reporter: Reporter(console: Console())).map(\.text), [artifact.path])
                XCTAssertEqual(try Data(contentsOf: artifact), original, "\(name) \(method)")
                // upx -d, the oracle, into a file of its own, where it unpacks: for a __TEXT of a single page it looks for
                // its pack header from before the file's start and gives up, where unpack starts looking at the file's
                // start.
                let upxd = URL(fileURLWithPath: file.path + "_upx-d")
                if try execute(self.upx(), ["-q", "-d", "-o", upxd.path, file.path]) {
                    XCTAssertEqual(try Data(contentsOf: upxd), original, "\(name) \(method)")
                }
            }
        }
    }

    /**
     UPX pads `__TEXT` to its page after the pack header and the overlay offset, from no zero byte to a page less
     one, and reads them back from `__LINKEDIT` in a window that spans the page and the header's object in memory;
     the window read here spanned the page and the header's 36 bytes, and gave up on a header that a page less
     3 bytes of zeros followed, as UPX gives up at its own window's start, 176 bytes earlier. Bytes appended to
     the image are packed as its last gap: the first opens the gap's block, 16 bytes at once, and each after it
     moves the padding by one, in steps of 4 as UPX aligns what it writes, so the count that pads to a page less
     one is read off the padding one byte leaves, the counts around it cover a step either way, and every one
     must unpack to the image and its appended bytes.
     */
    func testUnpackFindsThePackHeaderBehindAPageOfPadding() throws {
        let directory = try self.directory("page-padding")
        for (name, unsigned, original) in try self.unsignedLs(in: directory) {
            let page = try XCTUnwrap(MachO(File(path: unsigned.path))).segmentAlignment
            var state: UInt64 = 1
            let bytes = Data((0 ..< page + 32).map { _ in
                state = state &* 6_364_136_223_846_793_005 &+ 1_442_695_040_888_963_407
                return UInt8(truncatingIfNeeded: state >> 33)
            })
            func packed(_ count: Int) throws -> (file: URL, digest: String) {
                let source = directory / "\(name)_\(count)"
                let data = original + bytes.prefix(count)
                try data.write(to: source)
                return try (self.packed(source), XCTUnwrap(ByteHash.sha256.digest(data)))
            }
            let one = try self.padding(of: packed(1).file)
            let landing = (one + 2) % page
            var paddings: [Int] = []
            for count in max(1, landing - 8) ... landing + 16 {
                let (file, digest) = try packed(count)
                let padding = try self.padding(of: file)
                paddings.append(padding)
                XCTAssertEqual(try self.hashLines(file.path, ["--unpack"]), [digest], "\(name), \(count) bytes appended, \(padding) of padding")
                if page - 3 ... page - 1 ~= padding {
                    break
                }
            }
            XCTAssertTrue(paddings.contains { page - 3 ... page - 1 ~= $0 }, "\(name): no packing padded within 3 bytes of the page: \(paddings)")
        }
    }

    /// The zero bytes UPX wrote after the pack header and the overlay offset of `file`, up to `__LINKEDIT`.
    private func padding(of file: URL) throws -> Int {
        let data = try Data(contentsOf: file)
        let header = try XCTUnwrap(data.ranges(of: Data("UPX!".utf8)).last).lowerBound
        let image = try XCTUnwrap(MachO(File(path: file.path)))
        let linkedit = try XCTUnwrap(image.findSegment("__LINKEDIT")).load(segment_command_64.self)
        let end = Int(image.sw(linkedit.fileoff))
        XCTAssertTrue(data[header + 36 ..< end].allSatisfy { $0 == 0 }, "bytes other than zero between the pack header and __LINKEDIT")
        return end - header - 36
    }

    /**
     UPX's LZMA takes up to 8 literal context bits and 4 literal position bits, which its runtime options set
     (--crp-lzma-lc, --crp-lzma-lp): a stream with more than 4 together decodes as upx -d decodes it, where
     liblzma, which decoded LZMA for a while, refuses lc + lp past 4 and could not be told otherwise.
     */
    func testUnpackDecodesLZMAWithMoreLiteralBitsThanFour() throws {
        let directory = try self.directory("literal-bits")
        for (name, unsigned, original) in try self.unsignedLs(in: directory) {
            let digest = try XCTUnwrap(ByteHash.sha256.digest(original))
            for (lc, lp) in [(4, 1), (8, 4)] {
                let folder = directory / "lc\(lc)lp\(lp)"
                try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
                let source = folder / unsigned.lastPathComponent
                try FileManager.default.copyItem(at: unsigned, to: source)
                let file = try self.packed(source, ["--lzma", "--crp-lzma-lc=\(lc)", "--crp-lzma-lp=\(lp)"])
                XCTAssertEqual(try self.hashLines(file.path, ["--unpack"]), [digest], "\(name), lc \(lc), lp \(lp)")
            }
        }
    }

    /**
     Filter 0x53, which UPX added after 5.2.1 for arm64 and packs with when asked, takes the conditional branches
     too. An older upx packs with 0x52 when asked for it, and the test is skipped.
     */
    func testUnpackUndoesTheArm64ConditionalBranchFilter() throws {
        let directory = try self.directory("filter-0x53")
        guard let (_, unsigned, original) = try self.unsignedLs(in: directory).first(where: { $0.name == "arm64e" }) else {
            throw XCTSkip("/bin/ls has no arm64e slice")
        }
        let file = try self.packed(unsigned, ["--filter=0x53"])
        let packed = try Data(contentsOf: file)
        // The pack header's filter follows its version, format, method, level, sizes and checksums.
        let header = try XCTUnwrap(packed.ranges(of: Data("UPX!".utf8)).last).lowerBound
        try XCTSkipUnless(packed[header + 28] == 0x53, "upx packs with filter 0x\(String(packed[header + 28], radix: 16)), not 0x53")

        XCTAssertEqual(try self.hashLines(file.path, ["--unpack"]), try [XCTUnwrap(ByteHash.sha256.digest(original))])
        let upxd = URL(fileURLWithPath: file.path + "_upx-d")
        if try execute(self.upx(), ["-q", "-d", "-o", upxd.path, file.path]) {
            XCTAssertEqual(try Data(contentsOf: upxd), original)
        }
    }

    /**
     UPX's arm64 doctest instructions, filtered by UPX's own Filter as its Mach-O packer filters them (addvalue 0),
     with three bytes after the last word: 0x52 takes B and BL, the last word only with bytes after it; 0x53 takes
     the conditional branches too, and the last word always. The bytes after the last word stay as they are.
     nop, b, bl, b.ne, cbz w5, cbz x5, cbnz w7, cbnz x7, tbz, tbnz, add, b
     */
    func testUnfilterUndoesUPXsArm64BranchFilters() throws {
        let original: [UInt32] = [0xd503_201f, 0x17ff_ffff, 0x9400_0010, 0x54ff_ffe1, 0x3400_0065, 0xb4ff_ffc5, 0x35ff_ffe7, 0xb500_0047, 0x361f_fff1, 0xb7f8_0024, 0x9100_0400, 0x1400_0002]
        let filtered: [(id: UInt8, length: Int, words: [UInt32])] = [
            (0x52, 48, [0xd503_201f, 0x1400_0000, 0x9400_0012, 0x54ff_ffe1, 0x3400_0065, 0xb4ff_ffc5, 0x35ff_ffe7, 0xb500_0047, 0x361f_fff1, 0xb7f8_0024, 0x9100_0400, 0x1400_0002]),
            (0x52, 51, [0xd503_201f, 0x1400_0000, 0x9400_0012, 0x54ff_ffe1, 0x3400_0065, 0xb4ff_ffc5, 0x35ff_ffe7, 0xb500_0047, 0x361f_fff1, 0xb7f8_0024, 0x9100_0400, 0x1400_000d]),
            (0x53, 48, [0xd503_201f, 0x1400_0000, 0x9400_0012, 0x5400_0041, 0x3400_00e5, 0xb400_0065, 0x3500_00a7, 0xb500_0127, 0x3618_00f1, 0xb7f8_0144, 0x9100_0400, 0x1400_000d]),
            (0x53, 51, [0xd503_201f, 0x1400_0000, 0x9400_0012, 0x5400_0041, 0x3400_00e5, 0xb400_0065, 0x3500_00a7, 0xb500_0127, 0x3618_00f1, 0xb7f8_0144, 0x9100_0400, 0x1400_000d]),
        ]
        let block = { (words: [UInt32], length: Int) in
            Data(words.flatMap { withUnsafeBytes(of: $0.littleEndian, Array.init) } + [0xa5, 0xa5, 0xa5]).prefix(length)
        }
        for (id, length, words) in filtered {
            var unfiltered = block(words, length)
            try unfiltered.withUnsafeMutableBytes { try PackMach.unfilter($0, id: id, cto: 0) }
            XCTAssertEqual(unfiltered, block(original, length), "0x\(String(id, radix: 16)), \(length) bytes")
        }
    }

    /**
     UPX's Filter leaves a block longer than its filter takes as it is, 16 MiB less one for the x86 call trick and
     64 MiB less one for the arm64 branch tricks: a branch after the first word of a block just over is left as
     it is, where one in a block at the limit is taken.
     */
    func testUnfilterLeavesBlocksLongerThanUPXFiltersAlone() throws {
        let cases: [(id: UInt8, limit: Int, filtered: [UInt8], unfiltered: [UInt8])] = [
            (0x46, 0x00ff_ffff, [0xe8, 0x00, 0x00, 0x00, 0x20], [0xe8, 0x1b, 0x00, 0x00, 0x00]),
            (0x52, 0x03ff_ffff, [0x10, 0x00, 0x00, 0x14], [0x0f, 0x00, 0x00, 0x14]),
        ]
        for (id, limit, filtered, unfiltered) in cases {
            for (length, taken) in [(limit, true), (limit + 1, false)] {
                var block = Data(count: length)
                block.replaceSubrange(4 ..< 4 + filtered.count, with: filtered)
                try block.withUnsafeMutableBytes { try PackMach.unfilter($0, id: id, cto: 0) }
                XCTAssertEqual(Array(block[4 ..< 4 + filtered.count]), taken ? unfiltered : filtered, "0x\(String(id, radix: 16)), \(length) bytes")
            }
        }
    }

    /**
     Signed after packing, the image no longer has the 16-byte `__LINKEDIT` UPX leaves, so upx -d gives up on it;
     unpack looks past the signature. A signed image that UPX packed comes back signed, and without its signature
     too with --unsign.
     */
    func testUnpackSeesPastASignatureAddedAfterPacking() throws {
        let directory = try self.directory("signed")
        let (name, unsigned, data) = try XCTUnwrap(self.unsignedLs(in: directory).first)
        // Signed ad hoc, and by the Developer ID local.xcconfig names where it does, whose signature is the longer.
        let sample = try self.packed(unsigned)
        for identity in Set(["-", Self.identity]) {
            let file = try self.resigned(sample, by: identity, as: identity == "-" ? "_resigned_adhoc" : "_resigned")
            XCTAssertFalse(try execute(self.upx(), ["-q", "-d", "-o", file.path + "_upx-d", file.path]), identity)
            XCTAssertEqual(try self.hashLines(file.path, ["--unpack"]), try [ByteHash.sha256.digest(data)], identity)
        }

        let ls = try Data(contentsOf: URL(fileURLWithPath: "/bin/ls"))
        guard case let .fat(slices) = try Universal.open(data: ls), let slice = slices.first(where: { $0.name == name }) else {
            throw XCTSkip("/bin/ls has no \(name) slice")
        }
        let signed = Universal.sliceData(fileData: ls, arch: slice)
        let apple = directory / "ls_\(name)"
        try signed.write(to: apple)
        let packed = try self.resigned(self.packed(apple))
        XCTAssertEqual(try self.hashLines(packed.path, ["--unpack"]), try [ByteHash.sha256.digest(signed)])
        XCTAssertEqual(try self.hashLines(packed.path, ["--unpack", "--unsign"]), try [ByteHash.sha256.digest(data)])
        // thin writes the packed file without the signature that had to come out to unpack it, then Apple's slice
        // back, signature and all: codesign's strict validation is the second oracle.
        let unpacked = URL(fileURLWithPath: packed.path + "_unsigned_unpacked")
        XCTAssertEqual(Thinner.lines(for: packed.path, exact: false, unsign: false, unpack: true, write: false, reporter: Reporter(console: Console())).map(\.text), [packed.path + "_unsigned", unpacked.path])
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: packed.path + "_unsigned")), try Data(contentsOf: URL(fileURLWithPath: apple.path + "_packed")))
        XCTAssertEqual(try Data(contentsOf: unpacked), signed)
        _ = try codesign(["--verify", "--strict", unpacked.path])
        // unpack writes the file as thin leaves it, found in place; unsign over it takes Apple's signature off.
        XCTAssertEqual(Unpacker.lines(for: packed.path, write: false, reporter: Reporter(console: Console())).map(\.text), [unpacked.path])
        XCTAssertEqual(Unsigner.lines(for: unpacked.path, write: false, reporter: Reporter(console: Console())).map(\.text), [unpacked.path + "_unsigned"])
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: unpacked.path + "_unsigned")), data)
    }

    /**
     Bytes appended after a signature added after packing keep it in: hash mode's --unsign refuses the file, as
     codesign does, and its --unpack alone, which would look past the signature, finds no UPX behind it and hashes
     the file as it is, with nothing said, unless --exact drops the bytes first; unpack drops them itself, as thin
     --unpack does, the cut and the unsigned image states on the way, and names the artifacts for it.
     */
    func testUnpackCutsBytesAppendedPastASignatureAddedAfterPacking() throws {
        let directory = try self.directory("signed-padded")
        let (name, unsigned, data) = try XCTUnwrap(self.unsignedLs(in: directory).first)
        let signed = try self.resigned(self.packed(unsigned))
        let file = directory / "ls_\(name)_padded"
        let padded = try Data(contentsOf: signed) + Data(repeating: 0x4a, count: 8)
        try padded.write(to: file)

        XCTAssertEqual(try self.hashLines(file.path, ["--unpack"]), try [XCTUnwrap(ByteHash.sha256.digest(padded))])
        let (status, errors) = try runFashion(["--unpack", file.path])
        XCTAssertEqual(status, 0)
        XCTAssertEqual(errors, [])
        XCTAssertEqual(try self.hashLines(file.path, ["--unpack", "--exact"]), try [XCTUnwrap(ByteHash.sha256.digest(data))])
        XCTAssertEqual(try runFashion(["--unpack", "--unsign", file.path]).errors, ["fashion: \(file.path): LC_CODE_SIGNATURE does not point to end of file"])

        let reporter = Reporter(console: Console())
        XCTAssertEqual(Unpacker.lines(for: file.path, write: false, reporter: reporter).map(\.text), [file.path + "_exact_unsigned_unpacked"])
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: file.path + "_exact_unsigned_unpacked")), data)
        XCTAssertEqual(Thinner.lines(for: file.path, exact: false, unsign: false, unpack: true, write: false, reporter: reporter).map(\.text), ["_exact", "_exact_unsigned", "_exact_unsigned_unpacked"].map { file.path + $0 })
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: file.path + "_exact")), try Data(contentsOf: signed))
        XCTAssertFalse(FileManager.default.fileExists(atPath: file.path + "_unsigned_unpacked"))
        XCTAssertEqual(reporter.errorCount, 0)
    }

    /**
     Bytes appended to an image before packing are packed as its last gap and come back with it: unpack hashes
     them as upx -d writes them, and --exact cuts them off the unpacked image, as it cuts them off any image,
     which 1.5 did only when a signature came off it; thin writes the unpacked image, then the cut, where unpack
     keeps them, as upx -d gives them back. Signed after packing, the signature comes out first, and the states are
     named for it.
     */
    func testExactCutsBytesAppendedToTheUnpackedImage() throws {
        let directory = try self.directory("overlay")
        for (name, _, original) in try self.unsignedLs(in: directory) {
            let padded = original + Data(repeating: 0x4a, count: 8)
            let source = directory / "\(name)_padded"
            try padded.write(to: source)
            let file = try self.packed(source)
            XCTAssertEqual(try self.hashLines(file.path, ["--unpack"]), try [XCTUnwrap(ByteHash.sha256.digest(padded))], name)
            XCTAssertEqual(try self.hashLines(file.path, ["--unpack", "--exact"]), try [XCTUnwrap(ByteHash.sha256.digest(original))], name)
            let reporter = Reporter(console: Console())
            XCTAssertEqual(Thinner.lines(for: file.path, exact: true, unsign: false, unpack: true, write: false, reporter: reporter).map(\.text), [file.path + "_unpacked", file.path + "_unpacked_exact"], name)
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: file.path + "_unpacked")), padded, name)
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: file.path + "_unpacked_exact")), original, name)
            XCTAssertEqual(Unpacker.lines(for: file.path, write: false, reporter: reporter).map(\.text), [file.path + "_unpacked"], name)
            let signed = try self.resigned(file)
            XCTAssertEqual(try self.hashLines(signed.path, ["--unpack", "--exact"]), try [XCTUnwrap(ByteHash.sha256.digest(original))], name)
            XCTAssertEqual(Unpacker.lines(for: signed.path, write: false, reporter: reporter).map(\.text), [signed.path + "_unsigned_unpacked"], name)
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: signed.path + "_unsigned_unpacked")), padded, name)
            XCTAssertEqual(reporter.errorCount, 0, name)
        }
    }

    /**
     An image signed, then given appended bytes, then packed: its own signature comes back with the bytes past it,
     which keep it in, so hash mode's --unpack --unsign refuses the file, as its --unsign refuses the image, unless
     --exact cuts the unpacked image first; thin --unsign --unpack cuts it as needed, the unpacked image's own cut a
     state of its own, and the signature comes out.
     */
    func testTheUnpackedImagesOwnSignatureComesOutPastBytesAppendedBeforePacking() throws {
        let directory = try self.directory("inner-appended")
        for (name, unsigned, original) in try self.unsignedLs(in: directory) {
            let signed = try self.resigned(unsigned)
            let source = directory / "\(name)_signed_padded"
            try (Data(contentsOf: signed) + Data(repeating: 0x4a, count: 8)).write(to: source)
            let file = try self.packed(source)
            XCTAssertEqual(try runFashion(["--unpack", "--unsign", file.path]).errors, ["fashion: \(file.path): LC_CODE_SIGNATURE does not point to end of file"], name)
            XCTAssertEqual(try self.hashLines(file.path, ["--unpack", "--unsign", "--exact"]), try [XCTUnwrap(ByteHash.sha256.digest(original))], name)
            let reporter = Reporter(console: Console())
            XCTAssertEqual(Thinner.lines(for: file.path, exact: false, unsign: true, unpack: true, write: false, reporter: reporter).map(\.text), ["_unpacked", "_unpacked_exact", "_unpacked_exact_unsigned"].map { file.path + $0 }, name)
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: file.path + "_unpacked")), try Data(contentsOf: source), name)
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: file.path + "_unpacked_exact")), try Data(contentsOf: signed), name)
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: file.path + "_unpacked_exact_unsigned")), original, name)
            XCTAssertEqual(reporter.errorCount, 0, name)
        }
    }

    /**
     `fashion unpack`, parsed as the root command parses it, over a folder: the packed file gets its artifact,
     the others nothing; run again it finds the artifact in place, and --write replaces a file in its way.
     */
    func testUnpackSubcommandRunsOverATree() throws {
        let directory = try self.directory("subcommand")
        let (_, unsigned, original) = try XCTUnwrap(self.unsignedLs(in: directory).first)
        let file = try self.packed(unsigned)
        let artifact = URL(fileURLWithPath: file.path + "_unpacked")
        let command = try XCTUnwrap(Fashion.parseAsRoot(["unpack", directory.path]) as? Unpacker)
        XCTAssertEqual(command.scan(), 0)
        XCTAssertEqual(try Data(contentsOf: artifact), original)
        let (status, errors) = try runFashion(["unpack", directory.path])
        XCTAssertEqual(status, 0)
        XCTAssertEqual(errors, [])
        try Data("other".utf8).write(to: artifact)
        XCTAssertEqual(try runFashion(["unpack", file.path]).status, 2)
        XCTAssertEqual(try runFashion(["unpack", "--write", file.path]).status, 0)
        XCTAssertEqual(try Data(contentsOf: artifact), original)
    }

    /**
     A universal file with a slice UPX packed comes back as lipo made it of the originals, and thin writes them.
     */
    func testUnpackRestoresAUniversalFile() throws {
        let directory = try self.directory("universal")
        let slices = try self.unsignedLs(in: directory)
        try XCTSkipIf(slices.count < 2, "/bin/ls has no x86_64 and arm64e slices")
        let originals = slices.map(\.file)
        let packed = try self.packed(originals[0])
        let universal = directory / "universal"
        let original = directory / "original"
        try XCTSkipUnless(execute("/usr/bin/xcrun", ["lipo", "-create", packed.path, originals[1].path, "-output", universal.path]), "cannot run lipo")
        XCTAssertTrue(try execute("/usr/bin/xcrun", ["lipo", "-create"] + originals.map(\.path) + ["-output", original.path]))

        XCTAssertEqual(try self.hashLines(universal.path, ["--unpack"]), try [ByteHash.sha256.digest(Data(contentsOf: original))])
        // unpack writes the universal file whole, as lipo made it of the originals; thin writes its slices.
        XCTAssertEqual(Unpacker.lines(for: universal.path, write: false, reporter: Reporter(console: Console())).map(\.text), [universal.path + "_unpacked"])
        XCTAssertEqual(try Data(contentsOf: directory / "universal_unpacked"), try Data(contentsOf: original))
        XCTAssertEqual(Thinner.lines(for: universal.path, exact: false, unsign: false, unpack: true, write: false, reporter: Reporter(console: Console())).count, 3)
        // The slice UPX packed is written as it is and named for its unpacking; the other, as it was, keeps its name.
        XCTAssertEqual(try Data(contentsOf: directory / "universal_\(slices[0].name)"), try Data(contentsOf: packed))
        XCTAssertEqual(try Data(contentsOf: directory / "universal_\(slices[0].name)_unpacked"), slices[0].data)
        XCTAssertEqual(try Data(contentsOf: directory / "universal_\(slices[1].name)"), slices[1].data)

        // Signed after its slices were packed, which lays the universal file out again: unpack takes each slice's
        // signature out first, and with --unsign gives the file lipo made of the originals; thin writes every state of
        // both slices, the packed one unsigned then unpacked, since its signature had to come out to unpack it.
        let resigned = try self.resigned(universal)
        XCTAssertEqual(try self.hashLines(resigned.path, ["--unpack", "--unsign"]), try [ByteHash.sha256.digest(Data(contentsOf: original))])
        XCTAssertEqual(Thinner.lines(for: resigned.path, exact: false, unsign: true, unpack: true, write: false, reporter: Reporter(console: Console())).count, 5)
        XCTAssertEqual(try Data(contentsOf: directory / "universal_resigned_\(slices[0].name)_unsigned"), try Data(contentsOf: packed))
        XCTAssertEqual(try Data(contentsOf: directory / "universal_resigned_\(slices[0].name)_unsigned_unpacked"), slices[0].data)
        XCTAssertEqual(try Data(contentsOf: directory / "universal_resigned_\(slices[1].name)_unsigned"), slices[1].data)
        // unpack alone leaves the other slice signed, laid out again, named for the packed slice's way; unsign over
        // the artifact gives the originals' file.
        let reporter = Reporter(console: Console())
        let unpacked = resigned.path + "_unsigned_unpacked"
        XCTAssertEqual(Unpacker.lines(for: resigned.path, write: false, reporter: reporter).map(\.text), [unpacked])
        XCTAssertEqual(try self.hashLines(unpacked, ["--unsign"]), try [ByteHash.sha256.digest(Data(contentsOf: original))])
        XCTAssertEqual(Unsigner.lines(for: unpacked, write: false, reporter: reporter).map(\.text), [unpacked + "_unsigned"])
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: unpacked + "_unsigned")), try Data(contentsOf: original))
        XCTAssertEqual(reporter.errorCount, 0)
    }

    /**
     A pack header whose checksum does not hold is malformed UPX data: red, counted, nothing written. So is a
     header block that claims more than a block, 2 GiB less a byte, refused before any of it is made room for. Hash
     mode hashes the file packed, the refusal said in a warning.
     */
    func testCorruptPackHeaderIsReported() throws {
        let directory = try self.directory("corrupt")
        let (_, unsigned, _) = try XCTUnwrap(self.unsignedLs(in: directory).first)
        let packed = try Data(contentsOf: self.packed(unsigned))
        let header = try XCTUnwrap(packed.ranges(of: Data("UPX!".utf8)).last).lowerBound
        var corrupt = packed
        corrupt[header + 31] ^= 0xff
        // The overlay offset follows the 32-byte pack header; its p_info is 12 bytes, then the first block's b_info.
        let overlay = Int(packed.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: header + 32, as: UInt32.self) }.littleEndian)
        var huge = packed
        huge.replaceSubrange(overlay + 12 ..< overlay + 16, with: withUnsafeBytes(of: UInt32(0x7fff_ffff).littleEndian) { Data($0) })
        // A pack header claiming more than UPX packs, 4 GiB less a byte, its checksum made to hold, is refused as UPX
        // refuses it.
        var big = packed
        big.replaceSubrange(header + 16 ..< header + 20, with: [0xff, 0xff, 0xff, 0xff])
        big[header + 31] = UInt8(big[header + 4 ..< header + 31].reduce(0) { $0 + Int($1) } % 251)

        for (name, data, message) in [("corrupt", corrupt, "header corrupted 3"), ("huge", huge, "file header corrupted"), ("big", big, "header corrupted 4")] {
            let file = directory / name
            try data.write(to: file)
            let reporter = Reporter(console: Console())
            let lines = Thinner.lines(for: file.path, exact: false, unsign: false, unpack: true, write: false, reporter: reporter)
            XCTAssertEqual(lines.count, 1, name)
            XCTAssertEqual(lines.first?.tint, .malformed, name)
            XCTAssertEqual(reporter.errorCount, 1, name)
            XCTAssertFalse(FileManager.default.fileExists(atPath: (directory / "\(name)_unpacked").path), name)
            // Hash mode hashes it packed, the refusal said.
            let refusal = "fashion: \(file.path): Invalid UPX data: \(message)"
            let (status, errors) = try runFashion(["--unpack", file.path])
            XCTAssertEqual(status, 0, name)
            XCTAssertEqual(errors, [refusal + ", hashed packed"], name)
            XCTAssertEqual(try self.hashLines(file.path, ["--unpack"]), try [refusal + ", hashed packed", XCTUnwrap(ByteHash.sha256.digest(data))], name)
        }
    }

    /**
     UCL's decoders that read 32 bits at a time, the ones UPX's Mach-O packers use, fetch their next word before
     they check the input, so a block cut inside a word, which no packer writes, has them read up to 3 bytes past
     it: UPX's buffer has room after a block for it, and so has the one read here, where the decompress fuzz
     harness found the read going past an exact one. Its block, 48 bytes of NRV2B claiming 16 KiB, spliced in
     as the first block, does not hold: red, nothing written. The harness is where the sanitizer sees the read,
     its buffer exact; the block read here lands in what Foundation rounds an allocation up to.
     */
    func testBlockWhoseLastWordIsPartialIsRefused() throws {
        let directory = try self.directory("partial-word")
        let (_, unsigned, _) = try XCTUnwrap(self.unsignedLs(in: directory).first)
        var packed = try Data(contentsOf: self.packed(unsigned))
        let header = try XCTUnwrap(packed.ranges(of: Data("UPX!".utf8)).last).lowerBound
        // The overlay offset follows the 32-byte pack header; its p_info is 12 bytes, then the first block's b_info,
        // its sizes, method, filter and cto, then the block.
        let overlay = Int(packed.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: header + 32, as: UInt32.self) }.littleEndian)
        let block = try XCTUnwrap(Data(hex: "975d76cb50002e0304c0010000ff5455c9200032aaaa642a19555555958caaa3aa4a46925155250040a8a80100000000"))
        var info = Data()
        info.appendUInt32(16384)
        info.appendUInt32(UInt32(block.count))
        info.append(contentsOf: [2, 0, 0, 0])
        packed.replaceSubrange(overlay + 12 ..< overlay + 24 + block.count, with: info + block)
        let file = directory / "partial"
        try packed.write(to: file)

        let reporter = Reporter(console: Console())
        let lines = Thinner.lines(for: file.path, exact: false, unsign: false, unpack: true, write: false, reporter: reporter)
        XCTAssertEqual(lines.count, 1)
        XCTAssertEqual(lines.first?.tint, .malformed)
        XCTAssertEqual(reporter.errorCount, 1)
        let refusal = "fashion: \(file.path): Invalid UPX data: compressed data violation"
        let (status, errors) = try runFashion(["--unpack", file.path])
        XCTAssertEqual(status, 0)
        XCTAssertEqual(errors, [refusal + ", hashed packed"])
        XCTAssertEqual(try self.hashLines(file.path, ["--unpack"]), try [refusal + ", hashed packed", XCTUnwrap(ByteHash.sha256.digest(packed))])
    }

    /**
     A UPX modified to defeat upx -d writes another marker than "UPX!" everywhere it goes: the pack header, the
     `l_info` before the packed data, and the stub, which looks for it. upx -d calls the file not packed; unpack
     finds the pack header by its structure and checksum, and takes the `l_info`'s word for the marker, named in a
     warning. The pack header's marker replaced alone, the `l_info`'s left, vouches for nothing: the image is hashed
     as it is.
     */
    func testUnpackFindsThePackHeaderWithoutItsMarker() throws {
        let directory = try self.directory("marker")
        let marker = Data("UPX!".utf8)
        let other = Data("VQY\"".utf8)
        for (name, unsigned, original) in try self.unsignedLs(in: directory) {
            let packed = try Data(contentsOf: self.packed(unsigned))
            XCTAssertGreaterThanOrEqual(packed.ranges(of: marker).count, 2, name)
            let swapped = directory / "\(name)_swapped"
            try packed.replacing(marker, with: other).write(to: swapped)
            saveFixture(path: swapped.path)
            let warning = "fashion: \(swapped.path): packed by a modified UPX, its marker \"VQY\\\"\" in place of \"UPX!\""
            XCTAssertEqual(try self.hashLines(swapped.path, ["--unpack"]), try [warning, XCTUnwrap(ByteHash.sha256.digest(original))], name)
            let (status, errors) = try runFashion(["--unpack", swapped.path])
            XCTAssertEqual(status, 0, name)
            XCTAssertEqual(errors, [warning], name)
            let reporter = Reporter(console: Console())
            let lines = Thinner.lines(for: swapped.path, exact: false, unsign: false, unpack: true, write: false, reporter: reporter)
            XCTAssertEqual(lines.map(\.text), [warning, swapped.path + "_unpacked"], name)
            XCTAssertEqual(lines.map(\.diagnostic), [true, false], name)
            XCTAssertEqual(reporter.errorCount, 0, name)
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: swapped.path + "_unpacked")), original, name)
            XCTAssertFalse(try execute(self.upx(), ["-q", "-d", "-o", swapped.path + "_upx-d", swapped.path]), name)

            var header = packed
            try header.replaceSubrange(XCTUnwrap(packed.ranges(of: marker).last), with: other)
            let alone = directory / "\(name)_header-swapped"
            try header.write(to: alone)
            XCTAssertEqual(try self.hashLines(alone.path, ["--unpack"]), try [XCTUnwrap(ByteHash.sha256.digest(header))], name)
            XCTAssertEqual(Thinner.lines(for: alone.path, exact: false, unsign: false, unpack: true, write: false, reporter: reporter).count, 0, name)
            XCTAssertEqual(reporter.errorCount, 0, name)
        }
    }

    /**
     A UPX modified to name its segments otherwise, `__XHDR`, `UPX_DATA`, `__TEXT` or `__LINKEDIT`, which upx -d goes
     by to find the pack header, writes a file that runs as it is: the stub reads no segment name. upx -d calls the
     file not packed; unpack looks for the pack header around the segment lying last in the file, and names the
     renaming in a warning, with the marker when that is replaced too.
     */
    func testUnpackFindsThePackHeaderWithTheSegmentsRenamed() throws {
        let directory = try self.directory("renamed")
        for (name, unsigned, original) in try self.unsignedLs(in: directory) {
            let packed = try Data(contentsOf: self.packed(unsigned))
            let image = try XCTUnwrap(MachO(File(data: packed)))
            func renamed(_ segment: String, to other: String, in data: Data) throws -> Data {
                let command = try XCTUnwrap(image.findSegment(segment))
                var data = data
                data.replaceSubrange(command.data.startIndex + 8 ..< command.data.startIndex + 24, with: Data(other.utf8) + Data(count: 16 - other.utf8.count))
                return data
            }
            let found = "a segment renamed, its pack header found before its last segment \"__LINKEDYT\""
            let marker = "its marker \"VQY\\\"\" in place of \"UPX!\""
            for (suffix, data, modified) in try [
                ("_linkedit", renamed("__LINKEDIT", to: "__LINKEDYT", in: packed), found),
                ("_text_linkedit", renamed("__TEXT", to: "__TEXU", in: renamed("__LINKEDIT", to: "__LINKEDYT", in: packed)), found),
                ("_marker_linkedit", renamed("__LINKEDIT", to: "__LINKEDYT", in: packed.replacing(Data("UPX!".utf8), with: Data("VQY\"".utf8))), "\(marker) and \(found)"),
            ] {
                let file = directory / "\(name)\(suffix)"
                try data.write(to: file)
                saveFixture(path: file.path)
                let warning = "fashion: \(file.path): packed by a modified UPX, \(modified)"
                XCTAssertEqual(try self.hashLines(file.path, ["--unpack"]), try [warning, XCTUnwrap(ByteHash.sha256.digest(original))], name + suffix)
                let (status, errors) = try runFashion(["--unpack", file.path])
                XCTAssertEqual(status, 0, name + suffix)
                XCTAssertEqual(errors, [warning], name + suffix)
                let reporter = Reporter(console: Console())
                let lines = Thinner.lines(for: file.path, exact: false, unsign: false, unpack: true, write: false, reporter: reporter)
                XCTAssertEqual(lines.map(\.text), [warning, file.path + "_unpacked"], name + suffix)
                XCTAssertEqual(reporter.errorCount, 0, name + suffix)
                XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: file.path + "_unpacked")), original, name + suffix)
                XCTAssertFalse(try execute(self.upx(), ["-q", "-d", "-o", file.path + "_upx-d", file.path]), name + suffix)
            }
        }
    }

    /**
     Test the UPX 3.91 XOR behind OSX/Keydnap's backdoor.

     ```text
     8d2bd504125d815339af52558a38f804048a56a213424378af83fd3c0d4c131c  icloudsyncd
     ```

     Use "ASS7" for its marker and XORed each filtered block with 0x01 before it is unfiltered, in its stub and during
     `upx -d`. Marc-Étienne Léveillé shared the [patch](https://github.com/eset/malware-research/blob/master/keydnap/keydnap_upx.patch)
     to decompress the backdoor.

     Stock `upx -d`, the marker restored, unfilters the blocks as they are and writes a wrong image, with nothing
     said, as it checks no Mach-O against the pack header's checksum of the original.

     A test sample, "ESE7" for marker and 0xe7 for XOR key, is made from what UPX packed with NRV2B by XORing the
     literals of each filtered block: `unpack` finds the key by the checksum, warns with the marker and the key, and
     gives the original back.

     With the key alone, the marker left as "UPX!", the warning names the key alone, and stock `upx -d`, which takes the
     file for its own, writes a wrong image of it without a word.
     */
    func testUnpackSeesThroughTheXORAModifiedUPXAddsBeforeUnfiltering() throws {
        let directory = try self.directory("xor")
        let key: UInt8 = 0xe7
        for (name, unsigned, original) in try self.unsignedLs(in: directory) {
            var packed = try Data(contentsOf: self.packed(unsigned, ["--nrv2b"]))
            XCTAssertEqual(try self.resummed(packed), packed, "\(name): c_adler is the packer's sum of the blocks' packed bytes in order")
            var filtered = 0
            for block in try self.blocks(of: packed) where block.compressed < block.uncompressed && block.filter != 0 {
                XCTAssertEqual(block.method, 2, "\(name): NRV2B, 32 bits at a time")
                let stream = packed[block.offset ..< block.offset + block.compressed]
                let xored = Self.xoringLiterals(of: stream, with: key)
                XCTAssertEqual(self.decompressed(xored, count: block.uncompressed), Data(self.decompressed(stream, count: block.uncompressed).map { $0 ^ key }), name)
                packed.replaceSubrange(block.offset ..< block.offset + block.compressed, with: xored)
                filtered += 1
            }
            XCTAssertGreaterThan(filtered, 0, name)
            // The literals changed, c_adler is set as the packer would have set it over them.
            packed = try self.resummed(packed)
            let xor = "its filtered blocks XORed with 0xe7 before they are unfiltered"
            for (suffix, marker, modified) in [("_xor", "UPX!", "packed by a modified UPX, \(xor)"), ("_xor_swapped", "ESE7", "packed by a modified UPX, its marker \"ESE7\" in place of \"UPX!\" and \(xor)")] {
                let file = directory / "\(name)\(suffix)"
                try packed.replacing(Data("UPX!".utf8), with: Data(marker.utf8)).write(to: file)
                saveFixture(path: file.path)
                let warning = "fashion: \(file.path): \(modified)"
                XCTAssertEqual(try self.hashLines(file.path, ["--unpack"]), try [warning, XCTUnwrap(ByteHash.sha256.digest(original))], name)
                let (status, errors) = try runFashion(["--unpack", file.path])
                XCTAssertEqual(status, 0, name)
                XCTAssertEqual(errors, [warning], name)
                let reporter = Reporter(console: Console())
                let lines = Thinner.lines(for: file.path, exact: false, unsign: false, unpack: true, write: false, reporter: reporter)
                XCTAssertEqual(lines.map(\.text), [warning, file.path + "_unpacked"], name)
                XCTAssertEqual(reporter.errorCount, 0, name)
                XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: file.path + "_unpacked")), original, name)
                let upxd = file.path + "_upx-d"
                if marker == "UPX!" {
                    XCTAssertTrue(try execute(self.upx(), ["-q", "-d", "-o", upxd, file.path]), name)
                    XCTAssertNotEqual(try Data(contentsOf: URL(fileURLWithPath: upxd)), original, name)
                } else {
                    XCTAssertFalse(try execute(self.upx(), ["-q", "-d", "-o", upxd, file.path]), name)
                }
            }
        }
    }

    /**
     The pack header's `c_adler`, the packer's sum of the packed bytes, is checked before the image is: a literal of
     an NRV2B block changed decompresses all the same, to another image, and is refused for it in red by thinr and
     unpack, in UPX's words with both sums, before any key is tried; a `c_adler` that is not the packer's, as much.
     Hash mode hashes the file packed, the refusal said in a warning, as --unpack hashes every file. Under --keep,
     what decompressed is written as it is before the refusal, `_decompressed`: the other image for the changed
     literals, the original for the header that lies.
     */
    func testPackedBytesThatFailTheirChecksumAreRefused() throws {
        let directory = try self.directory("c-adler")
        for (name, unsigned, _) in try self.unsignedLs(in: directory) {
            let packed = try Data(contentsOf: self.packed(unsigned, ["--nrv2b"]))
            let block = try XCTUnwrap(self.blocks(of: packed).first { $0.compressed < $0.uncompressed && $0.filter != 0 })
            var damaged = packed
            damaged.replaceSubrange(block.offset ..< block.offset + block.compressed, with: Self.xoringLiterals(of: packed[block.offset ..< block.offset + block.compressed], with: 0x01))
            var header = packed
            let at = try XCTUnwrap(packed.ranges(of: Data("UPX!".utf8)).last).lowerBound
            header[at + 12] ^= 0xff
            header[at + 31] = UInt8(header[at + 4 ..< at + 31].reduce(0) { $0 + Int($1) } % 251)
            for (suffix, data) in [("_damaged", damaged), ("_header", header)] {
                let file = directory / "\(name)\(suffix)"
                try data.write(to: file)
                saveFixture(path: file.path)
                let sum = try self.cAdler(of: data)
                let said = data[at + 12 ..< at + 16].withUnsafeBytes { $0.loadUnaligned(as: UInt32.self).littleEndian }
                let refusal = "fashion: \(file.path): Invalid UPX data: checksum error: the packed bytes sum to \(sum.hex), the pack header says \(said.hex)"
                let (status, errors) = try runFashion(["--unpack", file.path])
                XCTAssertEqual(status, 0, name)
                XCTAssertEqual(errors, [refusal + ", hashed packed"], name)
                XCTAssertEqual(try self.hashLines(file.path, ["--unpack"]), try [refusal + ", hashed packed", XCTUnwrap(ByteHash.sha256.digest(data))], name)
                let reporter = Reporter(console: Console())
                let lines = Thinner.lines(for: file.path, exact: false, unsign: false, unpack: true, write: false, reporter: reporter)
                XCTAssertEqual(lines.map(\.tint), [.malformed], name)
                XCTAssertEqual(reporter.errorCount, 1, name)
                XCTAssertFalse(FileManager.default.fileExists(atPath: file.path + "_unpacked"), name)
                XCTAssertFalse(FileManager.default.fileExists(atPath: file.path + "_decompressed"), name)

                let keeping = Reporter(console: Console())
                let kept = Thinner.lines(for: file.path, exact: false, unsign: false, unpack: true, write: false, keep: true, reporter: keeping)
                XCTAssertEqual(kept.map(\.text), [file.path + "_decompressed", refusal], name)
                XCTAssertEqual(kept.last?.tint, .malformed, name)
                XCTAssertEqual(keeping.errorCount, 1, name)
                let decompressed = try Data(contentsOf: URL(fileURLWithPath: file.path + "_decompressed"))
                let original = try Data(contentsOf: unsigned)
                XCTAssertEqual(decompressed.count, original.count, name)
                XCTAssertEqual(decompressed == original, suffix == "_header", name)
            }
        }
    }

    /**
     The pack header's `u_adler`, the Adler-32 of the original, is the word on an unpacked image, which upx -d does
     not check for Mach-O: one that fails it under every key is refused in red, both sums and the packer named, written
     nowhere and hashed packed, like packed bytes that fail theirs. Under --keep, thinr and unpack write what
     decompressed as it is, `_decompressed`, which is the original here, since only the header lies, and report the
     refusal all the same.
     */
    func testAnUnpackedImageThatFailsThePackersChecksumIsRefused() throws {
        let directory = try self.directory("checksum")
        for (name, unsigned, _) in try self.unsignedLs(in: directory) {
            var packed = try Data(contentsOf: self.packed(unsigned))
            let header = try XCTUnwrap(packed.ranges(of: Data("UPX!".utf8)).last).lowerBound
            let sum = packed[header + 8 ..< header + 12].withUnsafeBytes { $0.loadUnaligned(as: UInt32.self).littleEndian }
            packed[header + 8] ^= 0xff
            packed[header + 31] = UInt8(packed[header + 4 ..< header + 31].reduce(0) { $0 + Int($1) } % 251)
            let file = directory / name
            try packed.write(to: file)
            saveFixture(path: file.path)
            let filtered = try self.blocks(of: packed).contains { $0.filter != 0 && $0.compressed < $0.uncompressed }
            let refusal = "fashion: \(file.path): Invalid UPX data: checksum error on the unpacked image, packed by UPX: it sums to \(sum.hex), the pack header says \((sum ^ 0xff).hex)\(filtered ? ", under no XOR key" : "")"
            let (status, errors) = try runFashion(["--unpack", file.path])
            XCTAssertEqual(status, 0, name)
            XCTAssertEqual(errors, [refusal + ", hashed packed"], name)
            XCTAssertEqual(try self.hashLines(file.path, ["--unpack"]), try [refusal + ", hashed packed", XCTUnwrap(ByteHash.sha256.digest(packed))], name)
            let reporter = Reporter(console: Console())
            let lines = Thinner.lines(for: file.path, exact: false, unsign: false, unpack: true, write: false, reporter: reporter)
            XCTAssertEqual(lines.map(\.tint), [.malformed], name)
            XCTAssertEqual(reporter.errorCount, 1, name)
            XCTAssertFalse(FileManager.default.fileExists(atPath: file.path + "_unpacked"), name)
            XCTAssertFalse(FileManager.default.fileExists(atPath: file.path + "_decompressed"), name)

            let artifact = file.path + "_decompressed"
            for kept in [
                Thinner.lines(for: file.path, exact: false, unsign: false, unpack: true, write: false, keep: true, reporter: reporter),
                Unpacker.lines(for: file.path, write: false, keep: true, reporter: reporter),
            ] {
                XCTAssertEqual(kept.map(\.text), [artifact, refusal], name)
                XCTAssertEqual(kept.last?.tint, .malformed, name)
                XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: artifact)), try Data(contentsOf: unsigned), name)
            }
            XCTAssertEqual(reporter.errorCount, 3, name)
            try FileManager.default.removeItem(atPath: artifact)
            let (kept, said) = try runFashion(["thinr", "--unpack", "--keep", file.path])
            XCTAssertEqual(kept, 2, name)
            XCTAssertEqual(said, [refusal], name)
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: artifact)), try Data(contentsOf: unsigned), name)
        }
    }

    /**
     UPX 3.91 laid an `x86_64` file out with `__TEXT` ending just past the pack header and an empty `__LINKEDIT` at the
     page after it, the file padded with zeros up to there; one that lost that padding has the segment past its end,
     which the kernel refuses to load, and the parser refuses as the kernel does: reported in red like any malformed
     Mach-O, hashed nowhere, written nowhere, unless --exact gives it its page back, which unpack does as needed, the
     pack header then where UPX looks for it, and unsign for nothing.
     */
    func testAPackedFileCutShortOfItsLinkeditIsMalformed() throws {
        let directory = try self.directory("cut-short")
        for (name, unsigned, data) in try self.unsignedLs(in: directory) {
            var packed = try Data(contentsOf: self.packed(unsigned))
            func store(_ value: some FixedWidthInteger, at offset: Int) {
                packed.replaceSubrange(offset ..< offset + MemoryLayout.size(ofValue: value), with: withUnsafeBytes(of: value.littleEndian) { Data($0) })
            }
            // Today's UPX pads __TEXT to its page and writes 16 bytes of __LINKEDIT after it, where 3.91 ended __TEXT
            // just past the pack header and put an empty __LINKEDIT at the page after it, laid out so here. Its
            // __PAGEZERO comes out too: three segments read as 3.92's layout, which keeps the pack header in
            // __LINKEDIT, where 3.91's, which has another segment, is read back from before __LINKEDIT.
            let pagezero = try XCTUnwrap(XCTUnwrap(MachO(File(data: packed))).findSegment("__PAGEZERO"))
            let ncmds = packed.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 16, as: UInt32.self) }
            let sizeofcmds = packed.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 20, as: UInt32.self) }
            packed.insert(contentsOf: Data(count: pagezero.data.count), at: MemoryLayout<mach_header_64>.size + Int(sizeofcmds))
            packed.removeSubrange(pagezero.data.indices)
            store(ncmds - 1, at: 16)
            store(sizeofcmds - UInt32(pagezero.data.count), at: 20)
            let image = try XCTUnwrap(MachO(File(data: packed)))
            let linkedit = try XCTUnwrap(image.findSegment("__LINKEDIT"))
            let text = try XCTUnwrap(image.findSegment("__TEXT"))
            let end = try (XCTUnwrap(packed.lastIndex { $0 != 0 }) + 16) & ~15
            let pageSize = name == "x86_64" ? 0x1000 : 0x4000
            let page = (end / pageSize + 1) * pageSize
            func field(_ segment: MachO.LoadCommand, _ field: PartialKeyPath<segment_command_64>) throws -> Int {
                try segment.data.startIndex + XCTUnwrap(MemoryLayout<segment_command_64>.offset(of: field))
            }
            try store(UInt64(end), at: field(text, \.filesize))
            try store(UInt64(page), at: field(linkedit, \.fileoff))
            try store(UInt64(0), at: field(linkedit, \.filesize))
            packed = packed.prefix(end)
            let file = directory / name
            try packed.write(to: file)
            saveFixture(path: file.path)
            let message = "Invalid Mach-O: segment __LINKEDIT at offset \(page.hex) with size 0x0 is outside the \(end.hex)-byte slice"
            let (status, errors) = try runFashion(["--unpack", file.path])
            XCTAssertEqual(status, 2, name)
            XCTAssertEqual(errors, ["fashion: \(file.path): \(message)"], name)
            // thin --unsign pads it as needed, finds no signature, and has padded it for nothing: the file as it is.
            let reporter = Reporter(console: Console())
            let lines = Thinner.lines(for: file.path, exact: false, unsign: true, unpack: false, write: false, reporter: reporter)
            XCTAssertEqual(lines.count, 1, name)
            XCTAssertTrue(lines.first?.text.hasSuffix(message) ?? false, name)
            XCTAssertEqual(lines.first?.tint, .malformed, name)
            XCTAssertEqual(reporter.errorCount, 1, name)
            XCTAssertFalse(FileManager.default.fileExists(atPath: file.path + "_exact"), name)

            // With --exact, the page comes back and the file is named for it: hashed as its headers lay it out, padded,
            // and written so as _exact, where the image ends at __LINKEDIT; cut back to the bytes the segments
            // reference, __TEXT's, the file as it is, where every range counts, and written so as _exact.
            let caveat = "fashion: \(file.path): cut short of its last page, \((page - end).hex) bytes before __LINKEDIT at \(page.hex): padded with zeros"
            let padded = Reporter(console: Console())
            let exacted = Thinner.lines(for: file.path, exact: true, unsign: false, unpack: false, write: false, reporter: padded).map(\.text)
#if SECURITY_STRICT_VALIDATION
            let exact = packed + Data(count: page - end)
#else
            let exact = packed
#endif
            XCTAssertEqual(try self.hashLines(file.path, ["--exact"]), try [caveat, XCTUnwrap(ByteHash.sha256.digest(exact))], name)
            XCTAssertEqual(exacted, [caveat, file.path + "_exact"], name)
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: file.path + "_exact")), exact, name)
            XCTAssertEqual(padded.errorCount, 0, name)
            XCTAssertEqual(try self.hashLines(file.path, ["--unpack", "--exact"]), try [caveat, XCTUnwrap(ByteHash.sha256.digest(data))], name)

            // Without the flag, unpack pads the file as needed to read it, as thin --unpack does, --exact's _exact
            // found in place and the padding said; unsign, finding no signature, has padded it for nothing: the file
            // as it is is malformed, with no word of the padding.
            let asNeeded = Reporter(console: Console())
            XCTAssertEqual(Unpacker.lines(for: file.path, write: false, reporter: asNeeded).map(\.text), [caveat, file.path + "_exact_unpacked"], name)
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: file.path + "_exact_unpacked")), data, name)
            XCTAssertEqual(Thinner.lines(for: file.path, exact: false, unsign: false, unpack: true, write: false, reporter: asNeeded).map(\.text), [caveat, file.path + "_exact", file.path + "_exact_unpacked"], name)
            XCTAssertEqual(asNeeded.errorCount, 0, name)
            let forNothing = Reporter(console: Console())
            let left = Unsigner.lines(for: file.path, write: false, reporter: forNothing)
            XCTAssertEqual(left.count, 1, name)
            XCTAssertTrue(left.first?.text.hasSuffix(message) ?? false, name)
            XCTAssertEqual(forNothing.errorCount, 1, name)
        }
    }

    /**
     A universal file whose first slice a modified UPX packed and whose second slice's packed data does not hold:
     the warning about the first is printed, then the error about the second, each after its architecture, as hash
     mode prints them, before the digest of the file as it is, packed.
     */
    func testACaveatOutlivesALaterSlicesError() throws {
        let directory = try self.directory("caveat-then-error")
        let slices = try self.unsignedLs(in: directory)
        try XCTSkipIf(slices.count < 2, "/bin/ls has no x86_64 and arm64e slices")
        let marker = Data("UPX!".utf8)
        let swapped = directory / "swapped"
        try Data(contentsOf: self.packed(slices[0].file)).replacing(marker, with: Data("VQY\"".utf8)).write(to: swapped)
        var corrupted = try Data(contentsOf: self.packed(slices[1].file))
        let block = try XCTUnwrap(corrupted.firstRange(of: marker)).lowerBound + 64
        for index in block ..< block + 64 {
            corrupted[index] ^= 0xff
        }
        let corrupt = directory / "corrupt"
        try corrupted.write(to: corrupt)
        let file = directory / "fat"
        try XCTSkipUnless(execute("/usr/bin/xcrun", ["lipo", "-create", swapped.path, corrupt.path, "-output", file.path]), "cannot run lipo")

        let warning = "fashion: \(file.path) (\(slices[0].name)): packed by a modified UPX, its marker \"VQY\\\"\" in place of \"UPX!\""
        let error = "fashion: \(file.path) (\(slices[1].name)): Invalid UPX data: "
        let hashed = try self.hashLines(file.path, ["--unpack"])
        XCTAssertEqual(hashed.count, 3)
        XCTAssertEqual(hashed.first, warning)
        XCTAssertTrue(try XCTUnwrap(hashed.dropFirst().first).hasPrefix(error))
        XCTAssertTrue(try XCTUnwrap(hashed.dropFirst().first).hasSuffix(", hashed packed"))
        XCTAssertEqual(hashed.last, try XCTUnwrap(ByteHash.sha256.digest(Data(contentsOf: file))))
        let reporter = Reporter(console: Console())
        for lines in [Thinner.lines(for: file.path, exact: false, unsign: false, unpack: true, write: false, reporter: reporter), Unpacker.lines(for: file.path, write: false, reporter: reporter)] {
            XCTAssertEqual(lines.map(\.diagnostic), [true, true])
            XCTAssertEqual(lines.first?.text, warning)
            XCTAssertTrue(try XCTUnwrap(lines.last).text.hasPrefix(error))
            XCTAssertEqual(lines.last?.tint, .malformed)
        }
        XCTAssertEqual(reporter.errorCount, 2)
    }

    /**
     unpack meets every Mach-O. One of three segments, `__DATA`, `__TEXT` and a `__LINKEDIT` too short for a block
     header, is where UPX gives up ("bad offLINK") though it never packed it: hashed as it is, nothing to write.
     */
    func testImagesUPXDidNotPackAreLeftAlone() throws {
        let directory = try self.directory("not-packed")
        let image = makeBigEndianMachO(is64: false, textOffset: 0x1000, linkeditSize: 8, infoPlist: Data("<plist/>".utf8))
        let file = directory / "ppc"
        try image.write(to: file)

        let reporter = Reporter(console: Console())
        XCTAssertEqual(try self.hashLines(file.path, ["--unpack"]), try [ByteHash.sha256.digest(image)])
        XCTAssertEqual(Thinner.lines(for: file.path, exact: false, unsign: false, unpack: true, write: false, reporter: reporter).count, 0)
        XCTAssertEqual(reporter.errorCount, 0)
    }

    /**
     UPX still packs a ppc executable, `macho/ppc32`, big-endian pack header and all, and `upx -d` calls what it
     packed not packed by UPX (`packmast.cpp`: "this works with upx 3.91..3.94 but got broken in 3.95"): the
     smallest big-endian executable is given back byte for byte. UPX has no ppc64 Mach-O packer, `upx --help` lists
     none and `packmast.cpp` visits none, so `PackMach`'s ppc64 classes meet nothing.
     */
    func testUnpackRestoresAPPCExecutableUPXPacked() throws {
        let directory = try self.directory("ppc")
        let original = makeBigEndianMachO(is64: false, textOffset: 0x1000, linkeditSize: 8, infoPlist: Data("<plist/>".utf8))
        let file = directory / "ppc"
        try original.write(to: file)
        let packed = try self.packed(file)
        XCTAssertNotEqual(try Data(contentsOf: packed), original)

        XCTAssertEqual(try self.hashLines(packed.path, ["--unpack"]), try [XCTUnwrap(ByteHash.sha256.digest(original))])
        let reporter = Reporter(console: Console())
        XCTAssertEqual(Thinner.lines(for: packed.path, exact: false, unsign: false, unpack: true, write: false, reporter: reporter).map(\.text), [packed.path + "_unpacked"])
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: packed.path + "_unpacked")), original)
        XCTAssertEqual(reporter.errorCount, 0)
    }

    /**
     The whole chain over every slice of /bin/ls: thin --unsign writes each beside each without its signature, UPX
     packs each, codesign signs each again, and thin --unpack takes that signature out and gives each back.
     --match, given the digests of the fat file's slices with --unsign, finds every unpacked artifact, and the
     packed files themselves only with --unpack.
     */
    func testUnpackedSlicesMatchTheFatFilesUnsignedSlices() throws {
        let directory = try self.directory("chain")
        let ls = directory / "ls"
        try FileManager.default.copyItem(at: URL(fileURLWithPath: "/bin/ls"), to: ls)
        guard case let .fat(slices) = try Universal.open(path: ls.path) else {
            throw XCTSkip("/bin/ls is not universal")
        }
        let reporter = Reporter(console: Console())
        XCTAssertEqual(Thinner.lines(for: ls.path, exact: false, unsign: true, unpack: false, write: false, reporter: reporter).count, 2 * slices.count)

        // ls_x86_64_unsigned packed into ls_x86_64_unsigned_packed, signed into ls_x86_64_unsigned_packed_resigned, then
        // unsigned into ls_x86_64_unsigned_packed_resigned_unsigned, the packed file again, and unpacked into
        // ls_x86_64_unsigned_packed_resigned_unsigned_unpacked.
        let packed = try slices.map { slice in
            try self.resigned(self.packed(directory / "ls_\(slice.name)_unsigned"))
        }
        for file in packed {
            XCTAssertEqual(Thinner.lines(for: file.path, exact: false, unsign: false, unpack: true, write: false, reporter: reporter).map(\.text), [file.path + "_unsigned", file.path + "_unsigned_unpacked"])
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: file.path + "_unsigned")), try Data(contentsOf: URL(fileURLWithPath: String(file.path.dropLast("_resigned".count)))))
        }
        XCTAssertEqual(reporter.errorCount, 0)

        // Hash mode prints the whole file's digest before its slices'.
        let targets = try self.hashLines(ls.path, ["--slices", "--unsign"]).dropFirst()
        XCTAssertEqual(targets.count, slices.count)
        let match = targets.flatMap { ["--match", $0] }
        for file in packed {
            XCTAssertEqual(try self.hashLines(file.path + "_unsigned_unpacked", match), [file.path + "_unsigned_unpacked"])
            XCTAssertEqual(try self.hashLines(file.path, match), [])
            XCTAssertEqual(try self.hashLines(file.path, match + ["--unpack"]), [file.path])
        }
        let (status, errors) = try runFashion(match + packed.map { $0.path + "_unsigned_unpacked" })
        XCTAssertEqual(status, 0)
        XCTAssertEqual(errors, [])
    }
}
