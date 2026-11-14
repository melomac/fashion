import CryptoKit
@testable import fashion
import System
import XCTest

final class FileTests: XCTestCase {
    func testSizeIsTheSizeWhenOpened() throws {
        XCTAssertEqual(try File(data: Data(repeating: 0, count: 4242)).size, 4242)
    }

    func testOpenThrowsForMissingFile() {
        XCTAssertThrowsError(try File(path: "/tmp/fashion-missing-\(UUID())")) { error in
            XCTAssertEqual(error as? Errno, .noSuchFileOrDirectory)
        }
    }

    /**
     A FIFO put in place of a walked file would block `open(2)` until a writer came: it is refused at once instead,
     like a directory or a device.
     */
    func testOpenRefusesWhatIsNotARegularFile() throws {
        let fifo = FileManager.default.temporaryDirectory / "fashion-fifo-\(UUID())"
        XCTAssertEqual(mkfifo(fifo.path(), 0o600), 0)
        defer {
            try? FileManager.default.removeItem(at: fifo)
        }

        for path in [fifo.path(), FileManager.default.temporaryDirectory.path(), "/dev/null"] {
            XCTAssertThrowsError(try File(path: path), path) { error in
                XCTAssertEqual(error as? FileError, .notRegularFile)
            }
        }
    }

    func testReadAtOffset() throws {
        let file = try File(data: Data((0 ..< 1000).map { UInt8($0 & 0xff) }))

        XCTAssertEqual(try file.read(at: 10, count: 5), Data([10, 11, 12, 13, 14]))
        XCTAssertEqual(try file.read(at: 1000, count: 0), Data())
    }

    /**
     The bytes checked against the size at open are no longer there: the sizes then and now say so.
     */
    func testReadReportsAFileThatShrank() throws {
        let url = FileManager.default.temporaryDirectory / "fashion-shrinking-\(UUID())"
        try Data(repeating: 0xab, count: 1000).write(to: url)
        defer {
            try? FileManager.default.removeItem(at: url)
        }
        let file = try File(path: url.path())
        XCTAssertEqual(truncate(url.path(), 990), 0)

        XCTAssertThrowsError(try file.read(at: 980, count: 20)) { error in
            XCTAssertEqual(error as? FileError, .sizeChanged(opened: 1000, now: 990))
        }
    }

    /**
     The one opened was cut short, and the path names another file by the time the read comes up short.
     */
    func testReadReportsAFileReplaced() throws {
        let url = FileManager.default.temporaryDirectory / "fashion-replaced-\(UUID())"
        try Data(repeating: 0xab, count: 1000).write(to: url)
        defer {
            try? FileManager.default.removeItem(at: url)
        }
        let file = try File(path: url.path())
        XCTAssertEqual(truncate(url.path(), 10), 0)
        try Data(repeating: 0xcd, count: 1000).write(to: url, options: .atomic)

        XCTAssertThrowsError(try file.read(at: 0, count: 1000)) { error in
            XCTAssertEqual(error as? FileError, .replaced)
        }
    }

    func testStreamsFullContentAcrossChunks() throws {
        let content = Data((0 ..< 3_000_000).map { UInt8($0 & 0xff) }) // > chunkSize, multiple reads
        let file = try File(data: content)

        var collected = Data()
        try file.stream(0 ..< content.count) { collected.append(contentsOf: $0) }
        XCTAssertEqual(collected, content)
    }

    func testStreamsARange() throws {
        let file = try File(data: Data((0 ..< 1000).map { UInt8($0 & 0xff) }))

        var collected = Data()
        try file.stream(10 ..< 110) { collected.append(contentsOf: $0) }
        XCTAssertEqual(collected, Data((10 ..< 110).map { UInt8($0) }))
    }

    /**
     A piece of zeros reads as zeros and takes no memory. The edit here is 16 bytes in memory, a hole of 256 MiB, and
     16 bytes of the file it edits. A read across each end of the hole returns the bytes and the zeros beside them.
     A stream of the whole edit gives the same digest as the bytes fed one by one, and does not grow the process.
     */
    func testAPieceOfZerosReadsAsZerosAndTakesNoMemory() throws {
        let hole = 256 << 20
        let (head, tail) = (Data((1 ... 16).map { UInt8($0) }), Data((17 ... 32).map { UInt8($0) }))
        let file = try File(editing: File(data: Data(count: 64) + tail), pieces: [.bytes(head), .zeros(hole), .range(64 ..< 80)])
        XCTAssertEqual(file.size, hole + 32)
        XCTAssertEqual(try file.read(at: 8, count: 16), head.suffix(8) + Data(count: 8))
        XCTAssertEqual(try file.read(at: hole + 8, count: 16), Data(count: 8) + tail.prefix(8))

        let resident = residentBytes()
        var streamed = SHA256()
        try file.stream(0 ..< file.size) { streamed.update(bufferPointer: $0) }
        XCTAssertLessThan(residentBytes() - resident, 64 << 20, "the hole was held in memory")

        var expected = SHA256()
        expected.update(data: head)
        let megabyte = Data(count: 1 << 20)
        for _ in 0 ..< hole >> 20 {
            expected.update(data: megabyte)
        }
        expected.update(data: tail)
        XCTAssertEqual(streamed.finalize(), expected.finalize())
    }

    /**
     `File.Piece.slice` cuts a list of pieces at a range of bytes. Each kind of piece is cut here, at its start, at
     its end and in the middle: the pieces left make the same bytes as that range of the whole edit.

     ```
     pieces           | bytes, 100 | zeros, 1000 | range, 50 |
     range                   60 ..<                1120
     result                  | 40  | zeros, 1000 | 20 |
     ```
     */
    func testPiecesAreSlicedAtARangeOfBytes() throws {
        let base = try File(data: Data((0 ..< 200).map { UInt8($0) }))
        let pieces: [File.Piece] = [.bytes(Data((100 ..< 200).map { UInt8($0) })), .zeros(1000), .range(50 ..< 100)]
        let whole = File(editing: base, pieces: pieces)
        let content = try whole.read(at: 0, count: whole.size)
        XCTAssertEqual(content, Data((100 ..< 200).map { UInt8($0) }) + Data(count: 1000) + Data((50 ..< 100).map { UInt8($0) }))

        for range in [0 ..< 1150, 60 ..< 1120, 100 ..< 1100, 0 ..< 100, 99 ..< 101, 1099 ..< 1101, 500 ..< 600, 1120 ..< 1150, 40 ..< 40, 1150 ..< 1150] {
            let sliced = File.Piece.slice(pieces, range)
            XCTAssertEqual(sliced.reduce(0) { $0 + $1.count }, range.count, "\(range)")
            let file = File(editing: base, pieces: sliced)
            XCTAssertEqual(try file.read(at: 0, count: file.size), content.subdata(in: range), "\(range)")
        }

        let sliced = File.Piece.slice(pieces, 60 ..< 1120)
        guard
            sliced.count == 3,
            case let .bytes(head) = sliced[0],
            case let .zeros(hole) = sliced[1],
            case let .range(tail) = sliced[2]
        else {
            return XCTFail("pieces of \(sliced.map(\.count)) bytes")
        }
        XCTAssertEqual(head, Data((160 ..< 200).map { UInt8($0) }))
        XCTAssertEqual(hole, 1000)
        XCTAssertEqual(tail, 50 ..< 70)
    }

    /**
     `File.Piece.write` writes bytes over a list of pieces as a write to a file does it: inside the pieces, across
     their end, at their end and past it, where a hole of zeros comes before the bytes. Each result makes the same
     bytes as the same write done in memory.

     ```
     pieces           | bytes, 100   |        | bytes, 100 |
     write            40 bytes at 30          40 bytes at 500
     result           | 30 | 40 | 30 |        | bytes, 100 | zeros, 400 | 40 |
     ```
     */
    func testBytesAreWrittenOverPiecesAsOverAFile() throws {
        let base = try File(data: Data((0 ..< 200).map { UInt8($0) }))
        let data = Data(repeating: 0xbb, count: 40)
        func content(_ pieces: [File.Piece]) throws -> Data {
            let file = File(editing: base, pieces: pieces)
            return try file.read(at: 0, count: file.size)
        }
        let lists: [[File.Piece]] = [
            [],
            [.bytes(Data(repeating: 0xaa, count: 100))],
            [.bytes(Data(repeating: 0xaa, count: 100)), .zeros(1000), .range(50 ..< 100)],
        ]
        for pieces in lists {
            let before = try content(pieces)
            for offset in [0, 30, 60, 80, 100, 500, 1090, 1120, 1150, 2000] {
                var expected = before
                if offset > expected.count {
                    expected.append(Data(count: offset - expected.count))
                }
                expected.replaceSubrange(offset ..< min(offset + data.count, expected.count), with: data)
                XCTAssertEqual(try content(File.Piece.write(data, at: offset, over: pieces)), expected, "\(before.count) bytes, write at \(offset)")
            }
        }

        let past = File.Piece.write(data, at: 500, over: lists[1])
        guard
            past.count == 3,
            case let .bytes(head) = past[0],
            case let .zeros(hole) = past[1],
            case let .bytes(tail) = past[2]
        else {
            return XCTFail("pieces of \(past.map(\.count)) bytes")
        }
        XCTAssertEqual(head.count, 100)
        XCTAssertEqual(hole, 400)
        XCTAssertEqual(tail, data)
    }

    func testStreamReportsAFileThatShrank() throws {
        let url = FileManager.default.temporaryDirectory / "fashion-shrinking-\(UUID())"
        try Data(repeating: 0xab, count: 1000).write(to: url)
        defer {
            try? FileManager.default.removeItem(at: url)
        }
        let file = try File(path: url.path())
        XCTAssertEqual(truncate(url.path(), 900), 0)

        XCTAssertThrowsError(try file.stream(0 ..< 1000) { _ in }) { error in
            XCTAssertEqual(error as? FileError, .sizeChanged(opened: 1000, now: 900))
        }
    }

    /**
     An I/O error reads as strerror says it, not as Errno's localizedDescription does.
     */
    func testMessagesLeaveOutFoundationsPrefix() {
        XCTAssertEqual(File.message(for: Errno.permissionDenied), "Permission denied")
        XCTAssertNotEqual(Errno.permissionDenied.localizedDescription, "Permission denied")
        XCTAssertEqual(File.message(for: FileError.sizeChanged(opened: 2, now: 1)), "File changed size while hashing (2 bytes when opened, 1 now)")
    }
}
