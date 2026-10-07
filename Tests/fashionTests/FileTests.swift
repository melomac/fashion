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

    func testOpenRefusesWhatIsNotARegularFile() throws {
        // A FIFO put in place of a walked file would block open(2) until a writer came: it is refused at once instead,
        // like a directory or a device.
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

    func testReadReportsAFileThatShrank() throws {
        // The bytes checked against the size at open are no longer there: the sizes then and now say so.
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

    func testReadReportsAFileReplaced() throws {
        // The one opened was cut short, and the path names another file by the time the read comes up short.
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

    func testMessagesLeaveOutFoundationsPrefix() {
        // An I/O error reads as strerror says it, not as Errno's localizedDescription does.
        XCTAssertEqual(File.message(for: Errno.permissionDenied), "Permission denied")
        XCTAssertNotEqual(Errno.permissionDenied.localizedDescription, "Permission denied")
        XCTAssertEqual(File.message(for: FileError.sizeChanged(opened: 2, now: 1)), "File changed size while hashing (2 bytes when opened, 1 now)")
    }
}
