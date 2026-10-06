@testable import fashion
import System
import XCTest

final class FileTests: XCTestCase {
    private func tempFile(_ data: Data) throws -> URL {
        let url = FileManager.default.temporaryDirectory / "fashion-file-\(UUID())"
        try data.write(to: url)
        return url
    }

    func testSizeIsTheSizeWhenOpened() throws {
        XCTAssertEqual(try File(data: Data(repeating: 0, count: 4242)).size, 4242)
    }

    func testOpenThrowsForMissingFile() {
        XCTAssertThrowsError(try File(path: "/tmp/fashion-missing-\(UUID())")) { error in
            XCTAssertEqual(error as? Errno, .noSuchFileOrDirectory)
        }
    }

    func testReadAtOffset() throws {
        let file = try File(data: Data((0 ..< 1000).map { UInt8($0 & 0xff) }))

        XCTAssertEqual(try file.read(at: 10, count: 5), Data([10, 11, 12, 13, 14]))
        XCTAssertEqual(try file.read(at: 1000, count: 0), Data())
    }

    func testReadPastTheEndThrows() throws {
        // Like a file that shrank since it was opened: the bytes checked against its size are no longer there.
        let file = try File(data: Data(repeating: 0xab, count: 1000))

        XCTAssertThrowsError(try file.read(at: 990, count: 20)) { error in
            XCTAssertEqual(error as? FileError, .sizeChanged(expected: 20, actual: 10))
        }
    }

    func testStreamsFullContentAcrossChunks() throws {
        let content = Data((0 ..< 3_000_000).map { UInt8($0 & 0xff) }) // > chunkSize, multiple reads
        let file = try File(data: content)

        var collected = Data()
        XCTAssertEqual(try file.stream(0 ..< content.count) { collected.append(contentsOf: $0) }, content.count)
        XCTAssertEqual(collected, content)
    }

    func testStreamsARange() throws {
        let file = try File(data: Data((0 ..< 1000).map { UInt8($0 & 0xff) }))

        var collected = Data()
        XCTAssertEqual(try file.stream(10 ..< 110) { collected.append(contentsOf: $0) }, 100)
        XCTAssertEqual(collected, Data((10 ..< 110).map { UInt8($0) }))
    }

    func testStreamStopsAtTheEnd() throws {
        let file = try File(data: Data(repeating: 0xab, count: 1000))

        XCTAssertEqual(try file.stream(900 ..< 1900) { _ in }, 100)
    }

    func testHeadReturnsLeadingBytes() throws {
        let url = try self.tempFile(Data([1, 2, 3, 4, 5, 6, 7, 8]))
        defer {
            try? FileManager.default.removeItem(at: url)
        }

        XCTAssertEqual(try FileReader.head(path: url.path(), count: 4), [1, 2, 3, 4])
    }

    func testHeadShortFileReturnsFewerBytes() throws {
        let url = try self.tempFile(Data([1, 2, 3]))
        defer {
            try? FileManager.default.removeItem(at: url)
        }

        XCTAssertEqual(try FileReader.head(path: url.path(), count: 8), [1, 2, 3])
    }
}
