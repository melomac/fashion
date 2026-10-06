@testable import fashion
import XCTest

final class FileReaderTests: XCTestCase {
    private func tempFile(_ data: Data) throws -> URL {
        let url = FileManager.default.temporaryDirectory / "fashion-fr-\(UUID())"
        try data.write(to: url)
        return url
    }

    func testReadStreamsFullContentAcrossChunks() throws {
        let content = Data((0 ..< 3_000_000).map { UInt8($0 & 0xff) }) // > chunkSize, multiple reads
        let url = try self.tempFile(content)
        defer {
            try? FileManager.default.removeItem(at: url)
        }

        let fd = try FileReader.open(path: url.path())
        defer {
            try? fd.close()
        }

        var collected = Data()
        XCTAssertEqual(try FileReader.read(fd, offset: 0, length: content.count) { collected.append(contentsOf: $0) }, content.count)

        XCTAssertEqual(collected, content)
    }

    func testReadHonorsOffsetAndLength() throws {
        let url = try self.tempFile(Data((0 ..< 1000).map { UInt8($0 & 0xff) }))
        defer {
            try? FileManager.default.removeItem(at: url)
        }
        let fd = try FileReader.open(path: url.path())
        defer {
            try? fd.close()
        }

        var collected = Data()
        XCTAssertEqual(try FileReader.read(fd, offset: 10, length: 100) { collected.append(contentsOf: $0) }, 100)

        XCTAssertEqual(collected, Data((10 ..< 110).map { UInt8($0) }))
    }

    func testReadStopsAtTheEnd() throws {
        let url = try self.tempFile(Data(repeating: 0xab, count: 1000))
        defer {
            try? FileManager.default.removeItem(at: url)
        }
        let fd = try FileReader.open(path: url.path())
        defer {
            try? fd.close()
        }

        XCTAssertEqual(try FileReader.read(fd, offset: 900, length: 1000) { _ in }, 100)
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

    func testSizeReturnsByteCount() throws {
        let url = try self.tempFile(Data(repeating: 0, count: 4242))
        defer {
            try? FileManager.default.removeItem(at: url)
        }

        let fd = try FileReader.open(path: url.path())
        defer {
            try? fd.close()
        }

        XCTAssertEqual(try FileReader.size(fd), 4242)
    }

    func testOpenThrowsForMissingFile() {
        XCTAssertThrowsError(try FileReader.open(path: "/tmp/fashion-missing-\(UUID())"))
    }
}
