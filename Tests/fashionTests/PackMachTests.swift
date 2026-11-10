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
        _ = try Thinner.lines(for: ls.path, exact: false, unsign: true, unpack: false, write: true, reporter: Reporter(console: Console()))
        let slices = try ["x86_64", "arm64e"].map { ($0, directory / "ls_\($0)_unsigned") }.filter { FileManager.default.fileExists(atPath: $0.1.path) }.map { try ($0.0, $0.1, Data(contentsOf: $0.1)) }
        try XCTSkipIf(slices.isEmpty, "/bin/ls has neither an x86_64 nor an arm64e slice")
        return slices
    }

    /// The lines hash mode prints for `path` with `arguments`. The file seeds the fuzzer's corpora.
    private func hashLines(_ path: String, _ arguments: [String] = []) throws -> [String] {
        saveFixture(path: path)
        return try Digester(Hasher.parse([path, "--quiet"] + arguments)).lines(for: path, reporter: Reporter(console: Console())).map(\.text)
    }

    /// Each block of `packed`, from UPX's `p_info` up to the original's size, or up to the padding after the blocks
    /// of a dylib, whose first segment alone is in blocks: where its bytes lie, its sizes, method and filter, as its
    /// `b_info` has them.
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
        while total < fileSize, cursor + 12 <= packed.count, word(cursor) != 0 {
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
                XCTAssertEqual(try self.hashLines(file.path, ["--unpack"]).last, digest, "\(name) \(method)")

                let artifact = URL(fileURLWithPath: file.path + "_unpacked")
                XCTAssertEqual(try Thinner.lines(for: file.path, exact: false, unsign: false, unpack: true, write: true, reporter: Reporter(console: Console())).map(\.text), [artifact.path])
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
                XCTAssertEqual(try self.hashLines(file.path, ["--unpack"]).last, digest, "\(name), \(count) bytes appended, \(padding) of padding")
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
                XCTAssertEqual(try self.hashLines(file.path, ["--unpack"]).last, digest, "\(name), lc \(lc), lp \(lp)")
            }
        }
    }

    /**
     Filter 0x53, which UPX 5.3.0 added for arm64 and packs with when asked, takes the conditional branches
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

        XCTAssertEqual(try self.hashLines(file.path, ["--unpack"]).last, try XCTUnwrap(ByteHash.sha256.digest(original)))
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
            XCTAssertEqual(try self.hashLines(file.path, ["--unpack"]).last, try ByteHash.sha256.digest(data), identity)
        }

        let ls = try Data(contentsOf: URL(fileURLWithPath: "/bin/ls"))
        guard case let .fat(slices) = try Universal.open(data: ls), let slice = slices.first(where: { $0.name == name }) else {
            throw XCTSkip("/bin/ls has no \(name) slice")
        }
        let signed = Universal.sliceData(fileData: ls, arch: slice)
        let apple = directory / "ls_\(name)"
        try signed.write(to: apple)
        let packed = try self.resigned(self.packed(apple))
        XCTAssertEqual(try self.hashLines(packed.path, ["--unpack"]).last, try ByteHash.sha256.digest(signed))
        XCTAssertEqual(try self.hashLines(packed.path, ["--unpack", "--unsign"]).last, try ByteHash.sha256.digest(data))
        // thin writes the packed file without the signature that had to come out to unpack it, then Apple's slice
        // back, signature and all: codesign's strict validation is the second oracle.
        let unpacked = URL(fileURLWithPath: packed.path + "_unsigned_unpacked")
        XCTAssertEqual(try Thinner.lines(for: packed.path, exact: false, unsign: false, unpack: true, write: true, reporter: Reporter(console: Console())).map(\.text), [packed.path + "_unsigned", unpacked.path])
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: packed.path + "_unsigned")), try Data(contentsOf: URL(fileURLWithPath: apple.path + "_packed")))
        XCTAssertEqual(try Data(contentsOf: unpacked), signed)
        _ = try codesign(["--verify", "--strict", unpacked.path])
        // unpack writes the file as thin leaves it, found in place; with --unsign it takes Apple's signature off too,
        // as unsign over the artifact does, into the same name.
        XCTAssertEqual(try Unpacker.lines(for: packed.path, write: false, reporter: Reporter(console: Console())).map(\.text), [unpacked.path])
        XCTAssertEqual(try Unpacker.lines(for: packed.path, write: false, unsign: true, reporter: Reporter(console: Console())).map(\.text), [unpacked.path + "_unsigned"])
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: unpacked.path + "_unsigned")), data)
        XCTAssertEqual(try Unsigner.lines(for: unpacked.path, write: false, reporter: Reporter(console: Console())).map(\.text), [unpacked.path + "_unsigned"])
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

        // Hash mode cuts the bytes as needed too, as unpack does: the file as it is, then the unpacked state.
        XCTAssertEqual(try self.hashLines(file.path, ["--unpack"]).first, try XCTUnwrap(ByteHash.sha256.digest(padded)))
        XCTAssertEqual(try self.hashLines(file.path, ["--unpack"]).last, try XCTUnwrap(ByteHash.sha256.digest(data)))
        let (status, errors) = try runFashion(["--unpack", file.path])
        XCTAssertEqual(status, 0)
        XCTAssertEqual(errors, [])
        XCTAssertEqual(try self.hashLines(file.path, ["--unpack", "--exact"]).last, try XCTUnwrap(ByteHash.sha256.digest(data)))
        XCTAssertEqual(try runFashion(["--unpack", "--unsign", file.path]).errors, [])

        let reporter = Reporter(console: Console())
        XCTAssertEqual(try Unpacker.lines(for: file.path, write: false, reporter: reporter).map(\.text), [file.path + "_exact_unsigned_unpacked"])
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: file.path + "_exact_unsigned_unpacked")), data)
        XCTAssertEqual(try Thinner.lines(for: file.path, exact: false, unsign: false, unpack: true, write: true, reporter: reporter).map(\.text), ["_exact", "_exact_unsigned", "_exact_unsigned_unpacked"].map { file.path + $0 })
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
            XCTAssertEqual(try self.hashLines(file.path, ["--unpack"]).last, try XCTUnwrap(ByteHash.sha256.digest(padded)), name)
            XCTAssertEqual(try self.hashLines(file.path, ["--unpack", "--exact"]).last, try XCTUnwrap(ByteHash.sha256.digest(original)), name)
            let reporter = Reporter(console: Console())
            XCTAssertEqual(try Thinner.lines(for: file.path, exact: true, unsign: false, unpack: true, write: true, reporter: reporter).map(\.text), [file.path + "_unpacked", file.path + "_unpacked_exact"], name)
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: file.path + "_unpacked")), padded, name)
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: file.path + "_unpacked_exact")), original, name)
            XCTAssertEqual(try Unpacker.lines(for: file.path, write: false, reporter: reporter).map(\.text), [file.path + "_unpacked"], name)
            let signed = try self.resigned(file)
            XCTAssertEqual(try self.hashLines(signed.path, ["--unpack", "--exact"]).last, try XCTUnwrap(ByteHash.sha256.digest(original)), name)
            XCTAssertEqual(try Unpacker.lines(for: signed.path, write: false, reporter: reporter).map(\.text), [signed.path + "_unsigned_unpacked"], name)
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
            XCTAssertEqual(try runFashion(["--unpack", "--unsign", file.path]).errors, [], name)
            XCTAssertEqual(try self.hashLines(file.path, ["--unpack", "--unsign"]).last, try XCTUnwrap(ByteHash.sha256.digest(original)), name)
            XCTAssertEqual(try self.hashLines(file.path, ["--unpack", "--unsign", "--exact"]).last, try XCTUnwrap(ByteHash.sha256.digest(original)), name)
            let reporter = Reporter(console: Console())
            XCTAssertEqual(try Thinner.lines(for: file.path, exact: false, unsign: true, unpack: true, write: true, reporter: reporter).map(\.text), ["_unpacked", "_unpacked_exact", "_unpacked_exact_unsigned"].map { file.path + $0 }, name)
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

        XCTAssertEqual(try self.hashLines(universal.path, ["--unpack"]).last, try ByteHash.sha256.digest(Data(contentsOf: original)))
        // unpack writes the universal file whole, as lipo made it of the originals; thin writes its slices.
        XCTAssertEqual(try Unpacker.lines(for: universal.path, write: false, reporter: Reporter(console: Console())).map(\.text), [universal.path + "_unpacked"])
        XCTAssertEqual(try Data(contentsOf: directory / "universal_unpacked"), try Data(contentsOf: original))
        XCTAssertEqual(try Thinner.lines(for: universal.path, exact: false, unsign: false, unpack: true, write: true, reporter: Reporter(console: Console())).count, 3)
        // The slice UPX packed is written as it is and named for its unpacking; the other, as it was, keeps its name.
        XCTAssertEqual(try Data(contentsOf: directory / "universal_\(slices[0].name)"), try Data(contentsOf: packed))
        XCTAssertEqual(try Data(contentsOf: directory / "universal_\(slices[0].name)_unpacked"), slices[0].data)
        XCTAssertEqual(try Data(contentsOf: directory / "universal_\(slices[1].name)"), slices[1].data)

        // Signed after its slices were packed, which lays the universal file out again: unpack takes each slice's
        // signature out first, and with --unsign gives the file lipo made of the originals; thin writes every state of
        // both slices, the packed one unsigned then unpacked, since its signature had to come out to unpack it.
        let resigned = try self.resigned(universal)
        XCTAssertEqual(try self.hashLines(resigned.path, ["--unpack", "--unsign"]).last, try ByteHash.sha256.digest(Data(contentsOf: original)))
        XCTAssertEqual(try Thinner.lines(for: resigned.path, exact: false, unsign: true, unpack: true, write: true, reporter: Reporter(console: Console())).count, 5)
        XCTAssertEqual(try Data(contentsOf: directory / "universal_resigned_\(slices[0].name)_unsigned"), try Data(contentsOf: packed))
        XCTAssertEqual(try Data(contentsOf: directory / "universal_resigned_\(slices[0].name)_unsigned_unpacked"), slices[0].data)
        XCTAssertEqual(try Data(contentsOf: directory / "universal_resigned_\(slices[1].name)_unsigned"), slices[1].data)
        // unpack alone leaves the other slice signed, laid out again, named for the packed slice's way; unsign over
        // the artifact gives the originals' file.
        let reporter = Reporter(console: Console())
        let unpacked = resigned.path + "_unsigned_unpacked"
        XCTAssertEqual(try Unpacker.lines(for: resigned.path, write: false, reporter: reporter).map(\.text), [unpacked])
        XCTAssertEqual(try self.hashLines(unpacked, ["--unsign"]).last, try ByteHash.sha256.digest(Data(contentsOf: original)))
        XCTAssertEqual(try Unsigner.lines(for: unpacked, write: false, reporter: reporter).map(\.text), [unpacked + "_unsigned"])
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: unpacked + "_unsigned")), try Data(contentsOf: original))
        XCTAssertEqual(reporter.errorCount, 0)
    }

    /**
     A pack header whose checksum does not hold is malformed UPX data: red, counted, nothing written. So is a
     header block that claims more than a block, 2 GiB less a byte, refused before any of it is made room for, and
     a packed file with a byte written into the zero padding after its pack header, which moves the last non-zero
     byte the scan steps back from: the stub runs it, and upx -d gives it up, "file corrupted", by the 16-byte
     `__LINKEDIT` only UPX writes. Hash mode hashes the file packed, the refusal said in a warning.
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

        // A format UPX never numbered, its checksum made to hold, is refused by its number before any field is read.
        var unknown = packed
        unknown[header + 5] = 200
        unknown[header + 31] = UInt8(unknown[header + 4 ..< header + 31].reduce(0) { $0 + Int($1) } % 251)
        // A p_filesize past what this tool unpacks in memory, which UPX, bounding each block alone, would unpack.
        var large = packed
        large.replaceSubrange(overlay + 4 ..< overlay + 8, with: withUnsafeBytes(of: UInt32(0x7fff_ffff).littleEndian) { Data($0) })
        var padded = packed
        XCTAssertEqual(padded[header + 40], 0)
        padded[header + 40] = 1
        XCTAssertFalse(try execute(self.upx(), ["-q", "-d", "-o", (directory / "padded_upx-d").path, { try padded.write(to: directory / "padded_upx"); return directory / "padded_upx" }().path]))

        for (name, data, message) in [("padded", padded, "Invalid UPX data: file corrupted: no pack header before the 16-byte __LINKEDIT UPX writes"), ("corrupt", corrupt, "Invalid UPX data: header corrupted 3"), ("huge", huge, "Invalid UPX data: file header corrupted"), ("big", big, "Invalid UPX data: header corrupted 4"), ("unknown", unknown, "Invalid UPX data: unknown format 200"), ("large", large, "Mach-O too large: the image UPX packed would be 2147483647 bytes, more than the 805306368 this tool unpacks in memory")] {
            let file = directory / name
            try data.write(to: file)
            let reporter = Reporter(console: Console())
            let lines = try Thinner.lines(for: file.path, exact: false, unsign: false, unpack: true, write: true, reporter: reporter)
            XCTAssertEqual(lines.count, 1, name)
            XCTAssertEqual(lines.first?.tint, .malformed, name)
            XCTAssertEqual(reporter.errorCount, 1, name)
            XCTAssertFalse(FileManager.default.fileExists(atPath: (directory / "\(name)_unpacked").path), name)
            // Hash mode hashes it packed, the refusal said.
            let refusal = "fashion: \(file.path): \(message)"
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
        let lines = try Thinner.lines(for: file.path, exact: false, unsign: false, unpack: true, write: true, reporter: reporter)
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
     warning. The pack header's marker replaced alone, the `l_info`'s left as UPX wrote it, is confirmed by that word
     all the same, as OSX/Keydnap's "ASS7" header was.
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
            XCTAssertEqual(try self.hashLines(swapped.path, ["--unpack"]).first, warning, name)
            XCTAssertEqual(try self.hashLines(swapped.path, ["--unpack"]).last, try XCTUnwrap(ByteHash.sha256.digest(original)), name)
            let (status, errors) = try runFashion(["--unpack", swapped.path])
            XCTAssertEqual(status, 0, name)
            XCTAssertEqual(errors, [warning], name)
            let reporter = Reporter(console: Console())
            let lines = try Thinner.lines(for: swapped.path, exact: false, unsign: false, unpack: true, write: true, reporter: reporter)
            XCTAssertEqual(lines.map(\.text), [warning, swapped.path + "_unpacked"], name)
            XCTAssertEqual(lines.map(\.diagnostic), [true, false], name)
            XCTAssertEqual(reporter.errorCount, 0, name)
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: swapped.path + "_unpacked")), original, name)
            XCTAssertFalse(try execute(self.upx(), ["-q", "-d", "-o", swapped.path + "_upx-d", swapped.path]), name)

            // The header's marker alone replaced, l_info left as UPX wrote it: the header is confirmed by it all the same,
            // as OSX/Keydnap's "ASS7" was, and upx -d gives up on the file.
            var header = packed
            try header.replaceSubrange(XCTUnwrap(packed.ranges(of: marker).last), with: other)
            let alone = directory / "\(name)_header-swapped"
            try header.write(to: alone)
            let aloneWarning = "fashion: \(alone.path): packed by a modified UPX, its marker \"VQY\\\"\" in place of \"UPX!\""
            XCTAssertEqual(try self.hashLines(alone.path, ["--unpack"]).first, aloneWarning, name)
            XCTAssertEqual(try self.hashLines(alone.path, ["--unpack"]).last, try XCTUnwrap(ByteHash.sha256.digest(original)), name)
            XCTAssertEqual(try Thinner.lines(for: alone.path, exact: false, unsign: false, unpack: true, write: true, reporter: reporter).map(\.text), [aloneWarning, alone.path + "_unpacked"], name)
            XCTAssertEqual(reporter.errorCount, 0, name)
            XCTAssertFalse(try execute(self.upx(), ["-q", "-d", "-o", alone.path + "_upx-d", alone.path]), name)
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
                XCTAssertEqual(try self.hashLines(file.path, ["--unpack"]).first, warning, name + suffix)
                XCTAssertEqual(try self.hashLines(file.path, ["--unpack"]).last, try XCTUnwrap(ByteHash.sha256.digest(original)), name + suffix)
                let (status, errors) = try runFashion(["--unpack", file.path])
                XCTAssertEqual(status, 0, name + suffix)
                XCTAssertEqual(errors, [warning], name + suffix)
                let reporter = Reporter(console: Console())
                let lines = try Thinner.lines(for: file.path, exact: false, unsign: false, unpack: true, write: true, reporter: reporter)
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
     literals of each filtered block. `unpack` reads the key off the first filtered block, which starts with the
     header padding XORed, finds that the checksum holds under it, warns with the marker and the key, and gives the
     original back.

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
                XCTAssertEqual(try self.hashLines(file.path, ["--unpack"]).first, warning, name)
                XCTAssertEqual(try self.hashLines(file.path, ["--unpack"]).last, try XCTUnwrap(ByteHash.sha256.digest(original)), name)
                let (status, errors) = try runFashion(["--unpack", file.path])
                XCTAssertEqual(status, 0, name)
                XCTAssertEqual(errors, [warning], name)
                let reporter = Reporter(console: Console())
                let lines = try Thinner.lines(for: file.path, exact: false, unsign: false, unpack: true, write: true, reporter: reporter)
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
     The pack header's `c_adler`, the packer's sum of the packed bytes, refuses nothing, as neither UPX's stub nor
     upx -d reads it for a Mach-O. Two files:

     - a literal of an NRV2B block XORed with 0x01 decompresses to another image. Its filtered block shows 0x01 for
       its key, which gives the original back, the key and the sums named in a warning;
     - a `c_adler` that is not the packer's leaves the original as it is, the sums named.

     Hash mode hashes the image unpacked, the warning on stderr, exit 0. Under --keep, what decoded under no key is
     written as it is, `_decompressed`, where a key was applied: the other image for the changed literals, nothing
     for the header that lies.
     */
    func testPackedBytesThatFailTheirChecksumAreUnpackedAllTheSame() throws {
        let directory = try self.directory("c-adler")
        for (name, unsigned, original) in try self.unsignedLs(in: directory) {
            let packed = try Data(contentsOf: self.packed(unsigned, ["--nrv2b"]))
            let block = try XCTUnwrap(self.blocks(of: packed).first { $0.compressed < $0.uncompressed && $0.filter != 0 })
            var damaged = packed
            damaged.replaceSubrange(block.offset ..< block.offset + block.compressed, with: Self.xoringLiterals(of: packed[block.offset ..< block.offset + block.compressed], with: 0x01))
            var header = packed
            let at = try XCTUnwrap(packed.ranges(of: Data("UPX!".utf8)).last).lowerBound
            header[at + 12] ^= 0xff
            header[at + 31] = UInt8(header[at + 4 ..< at + 31].reduce(0) { $0 + Int($1) } % 251)
            for (suffix, data, keyed) in [("_damaged", damaged, true), ("_header", header, false)] {
                let file = directory / "\(name)\(suffix)"
                try data.write(to: file)
                saveFixture(path: file.path)
                let sum = try self.cAdler(of: data)
                let said = data[at + 12 ..< at + 16].withUnsafeBytes { $0.loadUnaligned(as: UInt32.self).littleEndian }
                let key = keyed ? "packed by a modified UPX, its filtered blocks XORed with 0x01 before they are unfiltered; " : ""
                let warning = "fashion: \(file.path): \(key)checksums neither UPX nor its stub reads: the packed bytes sum to \(sum.hex), the pack header says \(said.hex)"
                let (status, errors) = try runFashion(["--unpack", file.path])
                XCTAssertEqual(status, 0, name)
                XCTAssertEqual(errors, [warning], name)
                XCTAssertEqual(try self.hashLines(file.path, ["--unpack"]).first, warning, name)
                XCTAssertEqual(try self.hashLines(file.path, ["--unpack"]).last, try XCTUnwrap(ByteHash.sha256.digest(original)), name)
                let reporter = Reporter(console: Console())
                let lines = try Thinner.lines(for: file.path, exact: false, unsign: false, unpack: true, write: true, reporter: reporter)
                XCTAssertEqual(lines.map(\.text), [warning, file.path + "_unpacked"], name)
                XCTAssertEqual(reporter.errorCount, 0, name)
                XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: file.path + "_unpacked")), original, name)
                XCTAssertFalse(FileManager.default.fileExists(atPath: file.path + "_decompressed"), name)

                let keeping = Reporter(console: Console())
                let kept = try Thinner.lines(for: file.path, exact: false, unsign: false, unpack: true, write: true, keep: true, reporter: keeping)
                XCTAssertEqual(Set(kept.map(\.text)), Set([warning, file.path + "_unpacked"] + (keyed ? [file.path + "_decompressed"] : [])), name)
                XCTAssertEqual(keeping.errorCount, 0, name)
                XCTAssertEqual(FileManager.default.fileExists(atPath: file.path + "_decompressed"), keyed, name)
                if keyed {
                    let decompressed = try Data(contentsOf: URL(fileURLWithPath: file.path + "_decompressed"))
                    XCTAssertEqual(decompressed.count, original.count, name)
                    XCTAssertNotEqual(decompressed, original, name)
                }
            }
        }
    }

    /**
     The pack header's `u_adler`, the Adler-32 of the original, is the packer's word on an unpacked image, which
     upx -d does not check for a Mach-O. An image that fails it, under the keys read off its filtered blocks too,
     is unpacked as UPX unpacks it. The warning names both sums and, where blocks were filtered, that no key was
     found. The image is the original here, since only the header lies.

     Hash mode hashes it unpacked, the warning on stderr, exit 0. --keep writes nothing of it, no key having been
     applied.
     */
    func testAnUnpackedImageThatFailsThePackersChecksumIsUnpackedAndSaid() throws {
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
            let warning = "fashion: \(file.path): checksums neither UPX nor its stub reads: the image sums to \(sum.hex), the pack header says \((sum ^ 0xff).hex)\(filtered ? Self.noKey : "")"
            let original = try Data(contentsOf: unsigned)
            let (status, errors) = try runFashion(["--unpack", file.path])
            XCTAssertEqual(status, 0, name)
            XCTAssertEqual(errors, [warning], name)
            XCTAssertEqual(try self.hashLines(file.path, ["--unpack"]).first, warning, name)
            XCTAssertEqual(try self.hashLines(file.path, ["--unpack"]).last, try XCTUnwrap(ByteHash.sha256.digest(original)), name)

            let reporter = Reporter(console: Console())
            let lines = try Thinner.lines(for: file.path, exact: false, unsign: false, unpack: true, write: true, reporter: reporter)
            XCTAssertEqual(lines.map(\.text), [warning, file.path + "_unpacked"], name)
            XCTAssertEqual(reporter.errorCount, 0, name)
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: file.path + "_unpacked")), original, name)
            XCTAssertFalse(FileManager.default.fileExists(atPath: file.path + "_decompressed"), name)

            for kept in try [
                Thinner.lines(for: file.path, exact: false, unsign: false, unpack: true, write: true, keep: true, reporter: reporter),
                Unpacker.lines(for: file.path, write: false, keep: true, reporter: reporter),
            ] {
                XCTAssertEqual(kept.map(\.text), [warning, file.path + "_unpacked"], name)
            }
            XCTAssertEqual(reporter.errorCount, 0, name)
            XCTAssertFalse(FileManager.default.fileExists(atPath: file.path + "_decompressed"), name)
            let (status2, said) = try runFashion(["thinr", "--unpack", "--keep", file.path])
            XCTAssertEqual(status2, 0, name)
            XCTAssertEqual(said, [warning], name)
        }
    }

    /**
     A packed image has no symbol table, the stub's: --symhash prints nothing for it and says so on standard error,
     "no external symbol table", under --quiet too; with --unpack the symhash of the image, labeled by the state,
     `(unpacked)`; --unsign and --exact are taken along, as the flags
     of one run, and change neither the symbols nor the label of a file they do nothing to.
     */
    func testSymHashOfAnUnpackedImage() throws {
        let directory = try self.directory("symhash")
        for (name, unsigned, _) in try self.unsignedLs(in: directory) {
            let packed = try self.packed(unsigned)
            let reporter = Reporter(console: Console())
            func symhash(_ path: String, _ arguments: [String] = []) throws -> [String] {
                try Digester(Hasher.parse([path, "--symhash"] + arguments)).lines(for: path, reporter: reporter).map { $0.diagnostic ? $0.text : $0.text.components(separatedBy: "  ").last ?? "" }
            }
            let original = try self.hashLines(unsigned.path, ["--symhash"])
            XCTAssertEqual(original.count, 1, name)
            XCTAssertEqual(try symhash(unsigned.path), [unsigned.path], name)
            XCTAssertEqual(try symhash(packed.path), ["fashion: \(packed.path): no external symbol table"], name)
            XCTAssertEqual(try self.hashLines(packed.path, ["--symhash"]), ["fashion: \(packed.path): no external symbol table"], name)

            // The packed file as it is comes first, with no symbols to show, then the unpacked state.
            let said = "fashion: \(packed.path): no external symbol table"
            XCTAssertEqual(try symhash(packed.path, ["--unpack"]), [said, "\(packed.path) (unpacked)"], name)
            XCTAssertEqual(try symhash(packed.path, ["--unpack", "--unsign", "--exact"]), [said, "\(packed.path) (unpacked)"], name)
            // --quiet shortens standard output alone: the file's missing table is said all the same.
            XCTAssertEqual(try self.hashLines(packed.path, ["--symhash", "--unpack", "--unsign", "--exact"]), [said] + original, name)
            XCTAssertEqual(try self.hashLines(packed.path, ["--symhash", "--match", original[0]]), [said], name)
            XCTAssertEqual(try self.hashLines(packed.path, ["--symhash", "--unpack", "--match", original[0]]), [said, packed.path], name)
            XCTAssertEqual(reporter.errorCount, 0, name)
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
            // Hash mode pads it as needed, as thinr does, and says so: the file as it is, then the unpacked state.
            let (status, errors) = try runFashion(["--unpack", file.path])
            XCTAssertEqual(status, 0, name)
            XCTAssertEqual(errors, ["fashion: \(file.path): cut short of its last page, \((page - end).hex) bytes before __LINKEDIT at \(page.hex): padded with zeros"], name)
            XCTAssertEqual(try self.hashLines(file.path, ["--unpack"]).last, try XCTUnwrap(ByteHash.sha256.digest(data)), name)
            // thin --unsign pads it as needed, finds no signature, and has padded it for nothing: the file as it is.
            let reporter = Reporter(console: Console())
            let lines = try Thinner.lines(for: file.path, exact: false, unsign: true, unpack: false, write: true, reporter: reporter)
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
            let exacted = try Thinner.lines(for: file.path, exact: true, unsign: false, unpack: false, write: true, reporter: padded).map(\.text)
#if SECURITY_STRICT_VALIDATION
            let exact = packed + Data(count: page - end)
#else
            let exact = packed
#endif
            XCTAssertEqual(try self.hashLines(file.path, ["--exact"]).first, caveat, name)
            XCTAssertEqual(try self.hashLines(file.path, ["--exact"]).last, try XCTUnwrap(ByteHash.sha256.digest(exact)), name)
            XCTAssertEqual(exacted, [caveat, file.path + "_exact"], name)
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: file.path + "_exact")), exact, name)
            XCTAssertEqual(padded.errorCount, 0, name)
            XCTAssertEqual(try self.hashLines(file.path, ["--unpack", "--exact"]).first, caveat, name)
            XCTAssertEqual(try self.hashLines(file.path, ["--unpack", "--exact"]).last, try XCTUnwrap(ByteHash.sha256.digest(data)), name)

            // Without the flag, unpack pads the file as needed to read it, as thin --unpack does, --exact's _exact
            // found in place and the padding said; unsign, finding no signature, has padded it for nothing: the file
            // as it is is malformed, with no word of the padding.
            let asNeeded = Reporter(console: Console())
            XCTAssertEqual(try Unpacker.lines(for: file.path, write: false, reporter: asNeeded).map(\.text), [caveat, file.path + "_exact_unpacked"], name)
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: file.path + "_exact_unpacked")), data, name)
            XCTAssertEqual(try Thinner.lines(for: file.path, exact: false, unsign: false, unpack: true, write: true, reporter: asNeeded).map(\.text), [caveat, file.path + "_exact", file.path + "_exact_unpacked"], name)
            XCTAssertEqual(asNeeded.errorCount, 0, name)
            let forNothing = Reporter(console: Console())
            let left = try Unsigner.lines(for: file.path, write: false, reporter: forNothing)
            XCTAssertEqual(left.count, 1, name)
            XCTAssertTrue(left.first?.text.hasSuffix(message) ?? false, name)
            XCTAssertEqual(forNothing.errorCount, 1, name)

            // The padding is said before what the edit then says: the packed bytes' sum the pack header does not hold.
            var damaged = packed
            let at = try XCTUnwrap(damaged.ranges(of: Data("UPX!".utf8)).last).lowerBound
            damaged[at + 12] ^= 0xff
            damaged[at + 31] = UInt8(damaged[at + 4 ..< at + 31].reduce(0) { $0 + Int($1) } % 251)
            let damagedFile = directory / "\(name)_damaged"
            try damaged.write(to: damagedFile)
            let saidFirst = Reporter(console: Console())
            let said = try Unpacker.lines(for: damagedFile.path, write: false, reporter: saidFirst)
            XCTAssertEqual(said.map(\.text).first, "fashion: \(damagedFile.path): cut short of its last page, \((page - end).hex) bytes before __LINKEDIT at \(page.hex): padded with zeros", name)
            XCTAssertEqual(said.count, 3, name)
            XCTAssertTrue(said[1].text.hasPrefix("fashion: \(damagedFile.path): checksums neither UPX nor its stub reads: the packed bytes sum to"), name)
            XCTAssertEqual(said.last?.text, damagedFile.path + "_exact_unpacked", name)
            XCTAssertEqual(saidFirst.errorCount, 0, name)
        }
    }

    /**
     `data` as an NRV2B stream read 32 bits at a time, as UCL's `n2b_d.c` reads it: each byte a literal, a run of one
     byte a literal and a match of the run at distance 1, then UPX's end marker; the bit words, top bit first, lie
     where the decoder reads them, before the bytes they tell of. For packed files made by hand.

     With `within` past 1, a stretch that repeats at any distance up to it is a match too, the longest there is:
     what a run becomes once XORed with a key of that many bytes.
     */
    private static func nrv2b(_ data: Data, within: Int = 1) -> Data {
        var stream = Data()
        var bits: UInt32 = 0
        var count = 0
        var word = 0
        func put(_ bit: Int) {
            if count == 0 {
                word = stream.count
                stream.append(Data(count: 4))
            }
            bits = bits << 1 | UInt32(bit)
            count += 1
            if count == 32 {
                stream.replaceSubrange(word ..< word + 4, with: withUnsafeBytes(of: bits.littleEndian) { Data($0) })
                (bits, count) = (0, 0)
            }
        }
        /// `value`, its leading 1 understood, bit by bit from the top, each but the last followed by 0 to go on.
        func putVarying(_ value: Int) {
            for shift in stride(from: value.bitWidth - value.leadingZeroBitCount - 2, through: 0, by: -1) {
                put((value >> shift) & 1)
                put(shift == 0 ? 1 : 0)
            }
        }
        var index = data.startIndex
        while index < data.endIndex {
            // The longest stretch from here that repeats what lies `distance` bytes back, the nearest first.
            var (copied, distance) = (0, 0)
            for back in 1 ... within where index - back >= data.startIndex {
                var count = 0
                while index + count < data.endIndex, data[index + count] == data[index + count - back] {
                    count += 1
                }
                if count > copied {
                    (copied, distance) = (count, back)
                }
            }
            guard copied >= 2 else {
                put(1)
                stream.append(data[index])
                index += 1
                continue
            }
            // A match: m_off 3 and the byte after it make the distance, less 1, then m_len, the count less 1.
            put(0)
            putVarying(3)
            stream.append(UInt8(distance - 1))
            let length = copied - 1
            if length <= 3 {
                put(length >> 1)
                put(length & 1)
            } else {
                put(0)
                put(0)
                putVarying(length - 2)
            }
            index += copied
        }
        put(0)
        putVarying(0x0100_0002) // then 0xff: an offset of 0xffffffff, the end
        stream.append(0xff)
        if count > 0 {
            stream.replaceSubrange(word ..< word + 4, with: withUnsafeBytes(of: (bits << UInt32(32 - count)).littleEndian) { Data($0) })
        }
        return stream
    }

    /// What the warning adds for an image with filtered blocks that matches the packer's sum under no key read
    /// off them.
    private static let noKey = ", under no filtered XOR key"

    /**
     A file UPX packed, made by hand as UPX 5 lays one out: an `x86_64` executable of a page, one `__TEXT` segment over
     it, its headers in an NRV2B block and the rest stored; with `overlapping` more segments in its headers laid
     over the same page, each wanting the page's worth of blocks again, stored, where UPX writes each byte of an
     original once. The pack header's sums are the packer's.

     `editing` rewrites the original's headers before they are packed, for a test of what the unpacker makes of
     them. `commands` are load commands put after its segments'. With `filtered`, the rest of the page is `body`,
     in an NRV2B block under filter 0x49, its bytes XORed with `key`, repeated from the block's start, before it is
     packed, as a modified UPX does. `body` must hold runs for the encoder to pack, and no call or jump for the
     filter to rewrite.
     */
    private func packedByHand(overlapping: Int, filtered: (body: Data, key: [UInt8])? = nil, commands: [Data] = [], editing: (inout Data) -> Void = { _ in }) throws -> (packed: Data, original: Data) {
        let size = 0x1000
        var original = Data()
        [MH_MAGIC_64, UInt32(CPU_TYPE_X86_64), UInt32(CPU_SUBTYPE_X86_64_ALL), UInt32(MH_EXECUTE), UInt32(1 + overlapping + commands.count), UInt32(72 * (1 + overlapping) + commands.reduce(0) { $0 + $1.count }), 0, 0].forEach { original.appendUInt32($0) }
        for _ in 0 ... overlapping {
            original.appendUInt32(UInt32(LC_SEGMENT_64)); original.appendUInt32(72)
            original.append(Data("__TEXT".utf8) + Data(count: 10))
            [UInt64(0x1_0000_0000), UInt64(size), 0, UInt64(size)].forEach { original.appendUInt64($0) }
            [5, 5, 0, 0].forEach { original.appendUInt32(UInt32($0)) }
        }
        commands.forEach { original += $0 }
        let headers = original.count
        if let filtered {
            XCTAssertEqual(filtered.body.count, size - headers, "the body fills the page after the headers")
            original.append(filtered.body)
        } else {
            original.append(Data((headers ..< size).map { UInt8(truncatingIfNeeded: $0 * 7 + 1) }))
        }
        editing(&original)

        var blocks = Data()
        func block(_ unpacked: Data, as packed: Data, filter: UInt8 = 0) {
            blocks.appendUInt32(UInt32(unpacked.count)); blocks.appendUInt32(UInt32(packed.count)); blocks.append(contentsOf: [2, filter, 0, 0]) // sz_unc, sz_cpr, NRV2B_LE32, b_ftid, b_cto8
            blocks += packed
        }
        let first = Self.nrv2b(original.prefix(headers))
        XCTAssertEqual(self.decompressed(first, count: headers), original.prefix(headers), "the headers, as the encoder packs them, decode back")
        XCTAssertLessThan(first.count, headers)
        block(original.prefix(headers), as: first)
        if let filtered {
            let xored = Data(original[headers...].enumerated().map { $1 ^ filtered.key[$0 % filtered.key.count] })
            let stream = Self.nrv2b(xored, within: filtered.key.count)
            XCTAssertEqual(self.decompressed(stream, count: xored.count), xored, "the body, as the encoder packs it, decodes back")
            XCTAssertLessThan(stream.count, xored.count, "a block that does not pack is stored, and UPX filters none it stores")
            block(original[headers...], as: stream, filter: 0x49)
        } else {
            block(original[headers...], as: original[headers...])
        }
        for _ in 0 ..< overlapping {
            block(original, as: original)
        }

        var packed = Data()
        let overlay = 32 + 144 + 12 // the header, two segment commands, l_info
        let text = (overlay + 12 + blocks.count + 36 + 0xfff) & ~0xfff
        [MH_MAGIC_64, UInt32(CPU_TYPE_X86_64), UInt32(CPU_SUBTYPE_X86_64_ALL), UInt32(MH_EXECUTE), 2, 144, 0, 0].forEach { packed.appendUInt32($0) }
        for (name, offset, count, prot) in [("__TEXT", 0, text, 5), ("__LINKEDIT", text, 16, 1)] {
            packed.appendUInt32(UInt32(LC_SEGMENT_64)); packed.appendUInt32(72)
            packed.append(Data(name.utf8) + Data(count: 16 - name.utf8.count))
            [UInt64(0x1_0000_0000 + offset), UInt64(count), UInt64(offset), UInt64(count)].forEach { packed.appendUInt64($0) }
            [prot, prot, 0, 0].forEach { packed.appendUInt32(UInt32($0)) }
        }
        packed.appendUInt32(0); packed.append(Data("UPX!".utf8)); packed.append(contentsOf: [0, 0, 13, 34]) // l_info: checksum, magic, size, version, format
        [0, UInt32(size), UInt32(size)].forEach { packed.appendUInt32($0) } // p_info: progid, filesize, blocksize
        packed += blocks
        packed.append(Data(count: text - 36 - packed.count))
        packed.append(Data("UPX!".utf8)); packed.append(contentsOf: [13, 34, 2, 8]) // version, format, method, level
        let adler = original.withUnsafeBytes { UInt32(adler32(1, $0.baseAddress!.assumingMemoryBound(to: Bytef.self), uInt(original.count))) }
        [adler, 0, UInt32(size), UInt32(size - 1), UInt32(size)].forEach { packed.appendUInt32($0) } // u_adler, c_adler, u_len, c_len, u_file_size
        packed.append(contentsOf: [0, 0, 0, 0]) // filter, cto, n_mru, checksum
        packed.appendUInt32(UInt32(overlay)) // overlay_offset
        packed.append(Data(count: 16)) // __LINKEDIT
        return try (self.resummed(packed), original)
    }

    /**
     The byte a modified UPX XORs its filtered blocks with is read off the blocks as they decompress, with no
     search. Three files made by hand, the key 0x5a:

     - a filtered block that starts in the header padding, zeros, starts with the key, repeated, whatever else it
       holds: the key is its lead byte;
     - one that does not, and holds more zeros than anything else, holds the key more than anything else: the key
       is its commonest byte;
     - one with neither, no run at its start and another byte its commonest, gives no key that holds.

     The first two give the original back, the key named. The third comes out as UPX unpacks it, its blocks
     unfiltered as they are, the warning naming the sums and that no key was found.
     */
    func testTheXORKeyIsReadFromTheFilteredBlocksWithoutASearch() throws {
        let directory = try self.directory("key")
        let key: UInt8 = 0x5a
        let count = 0x1000 - 104
        /// Runs of seven `byte`, a byte that varies after each, behind `lead`: what the encoder packs.
        func body(lead: Data, of byte: UInt8) -> Data {
            Data((lead + Data((0 ..< count).map { $0 % 8 == 7 ? UInt8(0x10 + $0 / 8 % 32) : byte })).prefix(count))
        }

        let distinct = Data((0x10 ..< 0x20).map { UInt8($0) })
        for (name, body, found) in [
            ("padded", body(lead: Data(count: 64), of: 0x41), true),
            ("common", body(lead: distinct, of: 0x00), true),
            ("neither", body(lead: distinct, of: 0x41), false),
        ] {
            let (packed, original) = try self.packedByHand(overlapping: 0, filtered: (body, [key]))
            let file = directory / name
            try packed.write(to: file)

            let lines = try self.hashLines(file.path, ["--unpack"])
            let keyed = "fashion: \(file.path): packed by a modified UPX, its filtered blocks XORed with 0x5a before they are unfiltered"
            if found {
                XCTAssertEqual(lines.first, keyed, name)
                XCTAssertEqual(lines.last, try XCTUnwrap(ByteHash.sha256.digest(original)), name)
            } else {
                let unpacked = original.prefix(104) + Data(body.map { $0 ^ key })
                XCTAssertEqual(lines.first?.hasPrefix("fashion: \(file.path): checksums neither UPX nor its stub reads: the image sums to "), true, name)
                XCTAssertEqual(lines.first?.hasSuffix(Self.noKey), true, name)
                XCTAssertEqual(lines.last, try XCTUnwrap(ByteHash.sha256.digest(unpacked)), name)
            }

            let (status, _) = try runFashion(["--unpack", file.path])
            XCTAssertEqual(status, 0, name)
        }
    }

    /**
     A key of several bytes is read off the first filtered block as a key of one byte is. The block starts in the
     header padding, zeros, so it starts with the key, repeated, and the key is the shortest stretch of it that
     repeats. Three files made by hand, their filtered block XORed with the key from its start, behind 64 bytes
     of padding:

     - "Hello" and "Hello, World!" give the original back, the key named;
     - a key of 40 bytes does not show twice in the padding, so no key is read: the image comes out as UPX unpacks
       it, its block unfiltered as it is, the warning naming the sums and that no key was found.
     */
    func testAKeyOfSeveralBytesIsReadFromTheHeaderPadding() throws {
        let directory = try self.directory("long-key")
        let count = 0x1000 - 104 - 64
        // Runs of 255 bytes, a byte that varies after each, behind the padding: under a key, a run repeats with it.
        let body = Data(count: 64) + Data((0 ..< count).map { $0 % 256 == 255 ? UInt8(0x10 + $0 / 256 % 32) : 0x41 })

        for (name, key, said) in [("hello", Array("Hello".utf8), "\"Hello\""), ("hello-world", Array("Hello, World!".utf8), "\"Hello, World!\""), ("long", (1 ... 40).map { UInt8($0) }, nil)] {
            let (packed, original) = try self.packedByHand(overlapping: 0, filtered: (body, key))
            let file = directory / name
            try packed.write(to: file)

            let lines = try self.hashLines(file.path, ["--unpack"])
            if let said {
                XCTAssertEqual(lines.first, "fashion: \(file.path): packed by a modified UPX, its filtered blocks XORed with \(said) before they are unfiltered", name)
                XCTAssertEqual(lines.last, try XCTUnwrap(ByteHash.sha256.digest(original)), name)
            } else {
                let unpacked = original.prefix(104) + Data(body.enumerated().map { $1 ^ key[$0 % key.count] })
                XCTAssertEqual(lines.first?.hasPrefix("fashion: \(file.path): checksums neither UPX nor its stub reads: the image sums to "), true, name)
                XCTAssertEqual(lines.first?.hasSuffix(Self.noKey), true, name)
                XCTAssertEqual(lines.last, try XCTUnwrap(ByteHash.sha256.digest(unpacked)), name)
            }

            let (status, _) = try runFashion(["--unpack", file.path])
            XCTAssertEqual(status, 0, name)
        }
    }

    /**
     The unpacked images of a universal file are held in memory together, so they share one image's limit, the
     unpacker's 768 MiB. A table of two entries over one packed image of a page, made by hand, unpacks twice under
     the limit. Under a limit of a page and a half, the second is refused as an image too large is: after its
     architecture, for what is left of the limit. A thin image past the limit is refused the same way.
     */
    func testTheImagesOfAUniversalFileShareOneUnpackLimit() throws {
        let directory = try self.directory("limit")
        let (packed, original) = try self.packedByHand(overlapping: 0)
        var fat = Data()
        [FAT_MAGIC, 2].forEach { fat.appendUInt32BE($0) }
        for _ in 0 ..< 2 {
            [UInt32(CPU_TYPE_X86_64), UInt32(CPU_SUBTYPE_X86_64_ALL), 0x1000, UInt32(packed.count), 12].forEach { fat.appendUInt32BE($0) }
        }
        fat.append(Data(count: 0x1000 - fat.count))
        fat += packed
        let file = directory / "fat"
        try fat.write(to: file)
        saveFixture(path: file.path)

        let edit = try MachOEditor.edit(File(path: file.path), exact: .never, unsign: false, unpack: true)
        XCTAssertEqual(edit.states.map { $0.map(\.edits) }, [[.unpacked], [.unpacked]])
        XCTAssertEqual(try self.hashLines(file.path, ["--unpack", "--slices"]).suffix(4), try [packed, original, packed, original].map { try XCTUnwrap(ByteHash.sha256.digest($0)) })

        XCTAssertThrowsError(try MachOEditor.edit(File(path: file.path), exact: .never, unsign: false, unpack: true, unpackLimit: 0x1800)) { error in
            let slice = error as? SliceError
            XCTAssertEqual(slice?.arch, "x86_64_2")
            XCTAssertEqual(slice?.error as? UnpackError, .imageTooLarge(size: 0x1000, limit: 0x800))
            XCTAssertEqual(File.message(for: error), "Mach-O too large: the image UPX packed would be 4096 bytes, more than the 2048 left of the \(768 << 20) this tool unpacks of one file in memory")
        }

        let thin = directory / "thin"
        try packed.write(to: thin)
        XCTAssertThrowsError(try MachOEditor.edit(File(path: thin.path), exact: .never, unsign: false, unpack: true, unpackLimit: 0x800)) { error in
            XCTAssertEqual(error as? UnpackError, .imageTooLarge(size: 0x1000, limit: 0x800))
        }
        XCTAssertEqual(File.message(for: UnpackError.imageTooLarge(size: 1 << 30, limit: 768 << 20)), "Mach-O too large: the image UPX packed would be \(1 << 30) bytes, more than the \(768 << 20) this tool unpacks in memory")
    }

    /**
     UPX refuses a packed file whose original headers hold a load command it does not know, or one of another size
     than it expects: "bad packed Mach load_command" (`is_bad_linker_command`). Two such commands here: a number
     past UPX's table, and an `LC_UUID` of 32 bytes. The bytes are the original's, whichever packer kept them, so
     the image is unpacked all the same, and the warning names the refusal UPX would give and where the command
     lies. A sound `LC_UUID` brings no warning.
     */
    func testALoadCommandUPXRefusesIsSaidAndUnpacked() throws {
        let directory = try self.directory("refused-command")
        /// A load command `number` of `size` bytes, zeros after its two words.
        func command(_ number: UInt32, _ size: Int) -> Data {
            var command = Data()
            [number, UInt32(size)].forEach { command.appendUInt32($0) }
            return command + Data(count: size - 8)
        }

        for (name, extra, refused) in [("unknown", command(0x7f, 8), true), ("sized", command(UInt32(LC_UUID), 32), true), ("sound", command(UInt32(LC_UUID), 24), false)] {
            let (packed, original) = try self.packedByHand(overlapping: 0, commands: [extra])
            let file = directory / name
            try packed.write(to: file)
            let lines = try self.hashLines(file.path, ["--unpack"])
            XCTAssertEqual(lines.last, try XCTUnwrap(ByteHash.sha256.digest(original)), name)
            XCTAssertEqual(lines.filter { $0.hasPrefix("fashion: ") }, refused ? ["fashion: \(file.path): its headers hold a load command UPX refuses to unpack, at 0x68"] : [], name)
            if let upx = try? self.upx() {
                XCTAssertEqual(try execute(upx, ["-q", "-d", "-o", file.path + "_upx-d", file.path]), !refused, "\(name): upx -d")
            }
        }
    }

    /**
     A dylib UPX packed, made by hand as UPX lays one out (the installed UPX packs none): an `x86_64` dylib of a
     `__TEXT` page, a `__DATA_CONST` of 64 bytes, a `__LINKEDIT` of 32 and an `LC_UUID` (canUnpack wants three
     segments' worth of commands and an entry's, whatever the filetype), the headers in an NRV2B block and the rest
     of `__TEXT` stored, the other two segments copied page-aligned after the blocks, every command kept, the pack
     header at the file's end; `p_info` says `fileSize` for the original's size. With `modInit`, the second segment
     is a `__DATA` with a `__mod_init_func` section, whose offset the packed headers place outside the segment, in
     the padding after the blocks, where 8 bytes point into the file.
     */
    private func packedDylibByHand(fileSize: Int, modInit: Bool = false) throws -> (packed: Data, original: Data) {
        let page = 0x1000
        let sizeofcmds = UInt32(modInit ? 320 : 240)
        var original = Data()
        [MH_MAGIC_64, UInt32(CPU_TYPE_X86_64), UInt32(CPU_SUBTYPE_X86_64_ALL), UInt32(MH_DYLIB), 4, sizeofcmds, 0, 0].forEach { original.appendUInt32($0) }
        func segment(_ name: String, _ offset: Int, _ count: Int, _ prot: Int, into data: inout Data, vmaddr: Int, section: Int? = nil) {
            data.appendUInt32(UInt32(LC_SEGMENT_64)); data.appendUInt32(section == nil ? 72 : 152)
            data.append(Data(name.utf8) + Data(count: 16 - name.utf8.count))
            [UInt64(vmaddr), UInt64(max(page, (count + 0xfff) & ~0xfff)), UInt64(offset), UInt64(count)].forEach { data.appendUInt64($0) }
            [prot, prot, section == nil ? 0 : 1, 0].forEach { data.appendUInt32(UInt32($0)) }
            if let section {
                data.append(Data("__mod_init_func".utf8) + Data(count: 1)); data.append(Data(name.utf8) + Data(count: 16 - name.utf8.count))
                [UInt64(vmaddr), 8].forEach { data.appendUInt64($0) }
                [UInt32(section), 3, 0, 0, 0x9, 0, 0, 0].forEach { data.appendUInt32($0) } // offset, align, reloff, nreloc, S_MOD_INIT_FUNC_POINTERS, reserved
            }
        }
        var uuid = Data()
        uuid.appendUInt32(UInt32(LC_UUID)); uuid.appendUInt32(24); uuid.append(Data((1 ... 16).map { UInt8($0) }))
        segment("__TEXT", 0, page, 5, into: &original, vmaddr: 0)
        segment(modInit ? "__DATA" : "__DATA_CONST", page, 64, 3, into: &original, vmaddr: page, section: modInit ? page : nil)
        segment("__LINKEDIT", page + 64, 32, 1, into: &original, vmaddr: 2 * page)
        original += uuid
        let headers = original.count
        original.append(Data((headers ..< page + 96).map { UInt8(truncatingIfNeeded: $0 * 7 + 1) }))

        var blocks = Data()
        func block(_ unpacked: Data, as packed: Data) {
            blocks.appendUInt32(UInt32(unpacked.count)); blocks.appendUInt32(UInt32(packed.count)); blocks.append(contentsOf: [2, 0, 0, 0])
            blocks += packed
        }
        block(original.prefix(headers), as: Self.nrv2b(original.prefix(headers)))
        block(original[headers ..< page], as: original[headers ..< page])

        var packed = Data()
        let overlay = 32 + Int(sizeofcmds) + 12
        let data = (overlay + 12 + blocks.count + 16 + 0xfff) & ~0xfff
        [MH_MAGIC_64, UInt32(CPU_TYPE_X86_64), UInt32(CPU_SUBTYPE_X86_64_ALL), UInt32(MH_DYLIB), 4, sizeofcmds, 0, 0].forEach { packed.appendUInt32($0) }
        segment("__TEXT", 0, data, 5, into: &packed, vmaddr: 0)
        segment(modInit ? "__DATA" : "__DATA_CONST", data, 64, 3, into: &packed, vmaddr: data, section: modInit ? data - 16 : nil)
        segment("__LINKEDIT", data + 64, 32, 1, into: &packed, vmaddr: data + page)
        packed += uuid
        packed.appendUInt32(0); packed.append(Data("UPX!".utf8)); packed.append(contentsOf: [0, 0, 13, 35]) // l_info: checksum, magic, size, version, format
        [0, UInt32(fileSize), UInt32(page)].forEach { packed.appendUInt32($0) } // p_info: progid, filesize, blocksize
        packed += blocks
        packed.append(Data(count: data - 16 - packed.count))
        packed.appendUInt64(0x40); packed.appendUInt64(0) // the pointer the misplaced section holds, into the headers
        packed += original[page ..< page + 96]
        packed.append(Data("UPX!".utf8)); packed.append(contentsOf: [13, 35, 2, 8]) // version, format, method, level
        let adler = original.prefix(page).withUnsafeBytes { UInt32(adler32(1, $0.baseAddress!.assumingMemoryBound(to: Bytef.self), uInt(page))) }
        [adler, 0, UInt32(page), UInt32(page - 1), UInt32(fileSize)].forEach { packed.appendUInt32($0) } // u_adler, c_adler, u_len, c_len, u_file_size
        packed.append(contentsOf: [0, 0, 0, 0]) // filter, cto, n_mru, checksum
        packed.appendUInt32(UInt32(overlay)) // overlay_offset
        return try (self.resummed(packed), original)
    }

    /**
     A packed dylib's first segment comes out of the blocks, bounded by `p_filesize`; the others are copied to where
     the original headers place them, which UPX does by seeking its output file there and writing, so a segment
     placed past `p_filesize` grows the file, and the file ends at the last segment whatever `p_filesize` claims
     past it. Said with `p_filesize` as the original's size, understated to the first segment's, and overstated by
     64 MiB, which the unpack fuzz harness found cost that much to hash, all three unpack to the original, as
     `upx -d` unpacks them when it is there.
     */
    func testADylibsCopiedSegmentsLieWhereTheHeadersPlaceThem() throws {
        let directory = try self.directory("dylib")
        for (name, fileSize) in [("sound", 0x1060), ("understated", 0x1000), ("overstated", 0x1060 + (64 << 20))] {
            let (packed, original) = try self.packedDylibByHand(fileSize: fileSize)
            let file = directory / name
            try packed.write(to: file)
            saveFixture(path: file.path)
            XCTAssertEqual(try self.hashLines(file.path, ["--unpack"]).last, try XCTUnwrap(ByteHash.sha256.digest(original)), name)
            let reporter = Reporter(console: Console())
            XCTAssertEqual(try Unpacker.lines(for: file.path, write: false, reporter: reporter).map(\.text), [file.path + "_unpacked"], name)
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: file.path + "_unpacked")), original, name)
            XCTAssertEqual(reporter.errorCount, 0, name)
            if let upx = try? self.upx() {
                let upxd = directory / "\(name)_upx-d"
                XCTAssertTrue(try execute(upx, ["-q", "-d", "-o", upxd.path, file.path]), name)
                XCTAssertEqual(try Data(contentsOf: upxd), original, name)
            }
        }
    }

    /**
     What the unpacker refuses, in UPX's words, each from a sound file changed in one place:

     - an overlay offset outside the file: `file corrupted`;
     - decompressed headers with no load command, with more than they hold, or one of no size: `bad packed Mach load_command`;
     - a block whose method UPX has not got: `corrupt b_info`;
     - a block whose filter it has not got;
     - a pack header cut short of its sizes: `header corrupted 1`;
     - a pack header cut short of its sums: `header corrupted 7`;
     - a pack header whose compressed size exceeds its uncompressed one;
     - a pack header of a version after 13 or before 8, or of the 0xff version;
     - a pack header whose compression method it has not got;
     - a dylib whose `__mod_init_func` section lies outside its `__DATA`.

     Hash mode hashes each packed and says the refusal; unpack refuses it, red, nothing written.
     */
    func testTheUnpackersRefusalsAreNamed() throws {
        let directory = try self.directory("refusals")
        let (sound, _) = try self.packedByHand(overlapping: 0)
        let header = try XCTUnwrap(sound.ranges(of: Data("UPX!".utf8)).last).lowerBound
        let blocks = try self.blocks(of: sound)

        /// `sound` with its pack header's byte at `index` set to `value`, the header's checksum made to hold.
        func headerByte(_ index: Int, _ value: UInt8) -> Data {
            var edited = sound
            edited[header + index] = value
            edited[header + 31] = UInt8(edited[header + 4 ..< header + 31].reduce(0) { $0 + Int($1) } % 251)
            return edited
        }

        /// `sound` with `__TEXT` ending and `__LINKEDIT` placed `cut` bytes into the pack header, where the window
        /// UPX reads ends.
        func linkeditAt(_ cut: Int) throws -> Data {
            var edited = sound
            let image = try XCTUnwrap(MachO(File(data: sound)))
            try edited.store(UInt64(header + cut), at: XCTUnwrap(image.findSegment("__TEXT")).data.startIndex + 48)
            try edited.store(UInt64(header + cut), at: XCTUnwrap(image.findSegment("__LINKEDIT")).data.startIndex + 40)
            return edited
        }

        var outside = sound
        outside.store(UInt32(sound.count), at: header + 32)
        var method = sound
        method[blocks[1].offset - 4] = 15 // the second block's b_info: its method, past LZMA's 14
        var filter = sound
        filter[blocks[0].offset - 3] = 0x51 // the first block's filter, one UPX has not got: a stored block is not unfiltered
        let cases: [(String, Data, String)] = try [
            ("outside", outside, "file corrupted"),
            ("nocmds", self.packedByHand(overlapping: 0) { $0.store(UInt32(0), at: 16) }.packed, "bad Mach_header.ncmds = 0"),
            ("morecmds", self.packedByHand(overlapping: 0) { $0.store(UInt32(3), at: 16) }.packed, "bad packed Mach load_command"),
            ("nosize", self.packedByHand(overlapping: 0) { $0.store(UInt32(0), at: 36) }.packed, "bad packed Mach load_command @0x20"),
            ("method", method, "corrupt b_info"),
            ("filter", filter, "unknown filter 0x51"),
            ("sizes", linkeditAt(12), "header corrupted 1"),
            ("sums", linkeditAt(24), "header corrupted 7"),
            ("larger", headerByte(22, 0x20), "header corrupted"),
            ("newer", headerByte(4, 14), "need a newer version of UPX"),
            ("older", headerByte(4, 7), "I am not compatible with older versions of UPX"),
            ("joke", headerByte(4, 0xff), "cannot unpack UPX ;-)"),
            ("compression", headerByte(6, 12), "unknown compression method (try a newer version of UPX)"),
            ("modinit", self.packedDylibByHand(fileSize: 0x1060, modInit: true).packed, "bad __mod_init_func"),
        ]

        for (name, data, message) in cases {
            let file = directory / name
            try data.write(to: file)
            let refusal = "fashion: \(file.path): Invalid UPX data: \(message)"
            XCTAssertEqual(try self.hashLines(file.path, ["--unpack"]), try [refusal + ", hashed packed", XCTUnwrap(ByteHash.sha256.digest(data))], name)

            let reporter = Reporter(console: Console())
            let lines = try Unpacker.lines(for: file.path, write: false, reporter: reporter)
            XCTAssertEqual(lines.map(\.text), [refusal], name)
            XCTAssertEqual(lines.first?.tint, .malformed, name)
            XCTAssertEqual(reporter.errorCount, 1, name)
            XCTAssertFalse(FileManager.default.fileExists(atPath: file.path + "_unpacked"), name)
        }
    }

    /**
     The blocks of every extent add up to the image, `p_filesize`, as UPX writes each byte of an original once: a
     file made by hand so unpacks, and one whose headers lay more segments over the same bytes, each asking for the
     image's worth of blocks again, is refused before they are decoded, in red, and hashed packed.
     */
    func testBlocksThatMakeMoreThanTheImageAreRefused() throws {
        let directory = try self.directory("overlapping")
        let (sound, original) = try self.packedByHand(overlapping: 0)
        let file = directory / "sound"
        try sound.write(to: file)
        saveFixture(path: file.path)
        XCTAssertEqual(try self.hashLines(file.path, ["--unpack"]).last, try XCTUnwrap(ByteHash.sha256.digest(original)))
        let reporter = Reporter(console: Console())
        XCTAssertEqual(try Unpacker.lines(for: file.path, write: false, reporter: reporter).map(\.text), [file.path + "_unpacked"])
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: file.path + "_unpacked")), original)
        XCTAssertEqual(reporter.errorCount, 0)

        let (overlapping, _) = try self.packedByHand(overlapping: 2)
        let laid = directory / "overlapping"
        try overlapping.write(to: laid)
        saveFixture(path: laid.path)
        let refusal = "fashion: \(laid.path): Invalid UPX data: the blocks make more than p_filesize bytes"
        XCTAssertEqual(try self.hashLines(laid.path, ["--unpack"]), try [refusal + ", hashed packed", XCTUnwrap(ByteHash.sha256.digest(overlapping))])
        let lines = try Unpacker.lines(for: laid.path, write: false, reporter: reporter)
        XCTAssertEqual(lines.map(\.text), [refusal])
        XCTAssertEqual(lines.first?.tint, .malformed)
        XCTAssertEqual(reporter.errorCount, 1)
        XCTAssertFalse(FileManager.default.fileExists(atPath: laid.path + "_unpacked"))
    }

    /**
     "UPX!" followed by what no pack header holds, in the page before an image's last segment: where the segments'
     names lead UPX there, it is refused as upx -d refuses it; where they do not, in a window UPX never reads, it is
     no pack header, an image of its own carrying the four bytes.
     */
    func testAMarkerThatHoldsNothingIsNoPackHeaderWhereNoSegmentNameLeads() throws {
        let directory = try self.directory("marker")
        let (name, _, data) = try XCTUnwrap(self.unsignedLs(in: directory).first)
        let image = try XCTUnwrap(MachO(File(data: data)))
        let linkedit = try XCTUnwrap(image.findSegment("__LINKEDIT")).load(segment_command_64.self)
        let at = Int(linkedit.fileoff) - 40
        try XCTSkipUnless(data[at ..< at + 40].allSatisfy { $0 == 0 }, "\(name): no zeros before __LINKEDIT")
        var marked = data
        marked.replaceSubrange(at ..< at + 5, with: Data("UPX!".utf8) + [0xff]) // a version no UPX wrote, a format it never numbered
        XCTAssertThrowsError(try PackMach(XCTUnwrap(MachO(File(data: marked)))), name) { error in
            XCTAssertEqual(error as? UnpackError, .cantUnpack("unknown format 0"), name)
        }
        var renamed = marked
        for (segment, other) in [("__TEXT", "__TEXU"), ("__LINKEDIT", "__LINKEDYT")] {
            let command = try XCTUnwrap(image.findSegment(segment))
            renamed.replaceSubrange(command.data.startIndex + 8 ..< command.data.startIndex + 24, with: Data(other.utf8) + Data(count: 16 - other.utf8.count))
        }
        XCTAssertNil(try PackMach(XCTUnwrap(MachO(File(data: renamed)))), name)
    }

    /**
     A universal file whose first slice a modified UPX packed and whose second slice's packed data does not hold:
     the warning about the first is printed, then the error about the second, each after its architecture, as hash
     mode prints them, before the digest of the file as it is, packed, the first slice included, as the warning says.
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
        XCTAssertTrue(try XCTUnwrap(hashed.dropFirst().first).hasSuffix(", the file hashed packed"))
        XCTAssertEqual(hashed.last, try XCTUnwrap(ByteHash.sha256.digest(Data(contentsOf: file))))
        let reporter = Reporter(console: Console())
        for lines in try [Thinner.lines(for: file.path, exact: false, unsign: false, unpack: true, write: true, reporter: reporter), Unpacker.lines(for: file.path, write: false, reporter: reporter)] {
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
        XCTAssertEqual(try Thinner.lines(for: file.path, exact: false, unsign: false, unpack: true, write: true, reporter: reporter).count, 0)
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
        XCTAssertEqual(try self.hashLines(packed.path, ["--unpack"]).last, try XCTUnwrap(ByteHash.sha256.digest(original)))

        let reporter = Reporter(console: Console())
        XCTAssertEqual(try Thinner.lines(for: packed.path, exact: false, unsign: false, unpack: true, write: true, reporter: reporter).map(\.text), [packed.path + "_unpacked"])
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: packed.path + "_unpacked")), original)
        // --quiet names the packed file once for its artifact, found in place; the original has none.
        XCTAssertEqual(try Unpacker.lines(for: packed.path, write: false, quiet: true, reporter: reporter).map(\.text), [packed.path])
        XCTAssertEqual(try Unpacker.lines(for: file.path, write: false, quiet: true, reporter: reporter).count, 0)
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
        XCTAssertEqual(try Thinner.lines(for: ls.path, exact: false, unsign: true, unpack: false, write: true, reporter: reporter).count, 2 * slices.count)

        // ls_x86_64_unsigned packed into ls_x86_64_unsigned_packed, signed into ls_x86_64_unsigned_packed_resigned, then
        // unsigned into ls_x86_64_unsigned_packed_resigned_unsigned, the packed file again, and unpacked into
        // ls_x86_64_unsigned_packed_resigned_unsigned_unpacked.
        let packed = try slices.map { slice in
            try self.resigned(self.packed(directory / "ls_\(slice.name)_unsigned"))
        }
        for file in packed {
            XCTAssertEqual(try Thinner.lines(for: file.path, exact: false, unsign: false, unpack: true, write: true, reporter: reporter).map(\.text), [file.path + "_unsigned", file.path + "_unsigned_unpacked"])
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: file.path + "_unsigned")), try Data(contentsOf: URL(fileURLWithPath: String(file.path.dropLast("_resigned".count)))))
        }
        XCTAssertEqual(reporter.errorCount, 0)

        // Hash mode prints the file as it is and unsigned whole before its slices', each slice signed then unsigned.
        let targets = try self.hashLines(ls.path, ["--slices", "--unsign"]).dropFirst(2)
        XCTAssertEqual(targets.count, 2 * slices.count)
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
