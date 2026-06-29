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
        defer { try? FileManager.default.removeItem(at: url) }

        var collected = Data()
        try FileReader.read(path: url.path()) { collected.append(contentsOf: $0) }

        XCTAssertEqual(collected, content)
    }

    func testReadHonorsLimit() throws {
        let url = try self.tempFile(Data(repeating: 0xab, count: 1000))
        defer { try? FileManager.default.removeItem(at: url) }

        var count = 0
        try FileReader.read(path: url.path(), limit: 100) { count += $0.count }

        XCTAssertEqual(count, 100)
    }

    func testHeadReturnsLeadingBytes() throws {
        let url = try self.tempFile(Data([1, 2, 3, 4, 5, 6, 7, 8]))
        defer { try? FileManager.default.removeItem(at: url) }

        XCTAssertEqual(try FileReader.head(path: url.path(), count: 4), [1, 2, 3, 4])
    }

    func testHeadShortFileReturnsFewerBytes() throws {
        let url = try self.tempFile(Data([1, 2, 3]))
        defer { try? FileManager.default.removeItem(at: url) }

        XCTAssertEqual(try FileReader.head(path: url.path(), count: 8), [1, 2, 3])
    }

    func testSizeReturnsByteCount() throws {
        let url = try self.tempFile(Data(repeating: 0, count: 4242))
        defer { try? FileManager.default.removeItem(at: url) }

        XCTAssertEqual(try FileReader.size(path: url.path()), 4242)
    }

    func testReadThrowsForMissingFile() {
        XCTAssertThrowsError(try FileReader.read(path: "/tmp/fashion-missing-\(UUID())") { _ in })
    }

    func testSizeThrowsForMissingFile() {
        XCTAssertThrowsError(try FileReader.size(path: "/tmp/fashion-missing-\(UUID())"))
    }
}
