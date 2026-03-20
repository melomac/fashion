@testable import fashion
import XCTest

final class CryptoDigestTests: XCTestCase {
    func testMD5Empty() throws {
        let data = Data()
        let result = try CryptoDigest.hash(data: data, algorithm: .md5)
        XCTAssertEqual(result, "d41d8cd98f00b204e9800998ecf8427e")
    }

    func testMD5Hello() throws {
        let data = Data("hello".utf8)
        let result = try CryptoDigest.hash(data: data, algorithm: .md5)
        XCTAssertEqual(result, "5d41402abc4b2a76b9719d911017c592")
    }

    func testSHA1Empty() throws {
        let data = Data()
        let result = try CryptoDigest.hash(data: data, algorithm: .sha1)
        XCTAssertEqual(result, "da39a3ee5e6b4b0d3255bfef95601890afd80709")
    }

    func testSHA1Hello() throws {
        let data = Data("hello".utf8)
        let result = try CryptoDigest.hash(data: data, algorithm: .sha1)
        XCTAssertEqual(result, "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d")
    }

    func testSHA256Empty() throws {
        let data = Data()
        let result = try CryptoDigest.hash(data: data, algorithm: .sha256)
        XCTAssertEqual(result, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    }

    func testSHA256Hello() throws {
        let data = Data("hello".utf8)
        let result = try CryptoDigest.hash(data: data, algorithm: .sha256)
        XCTAssertEqual(result, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
    }

    func testSHA384Empty() throws {
        let data = Data()
        let result = try CryptoDigest.hash(data: data, algorithm: .sha384)
        XCTAssertEqual(result, "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b")
    }

    func testSHA512Empty() throws {
        let data = Data()
        let result = try CryptoDigest.hash(data: data, algorithm: .sha512)
        XCTAssertEqual(result, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e")
    }

    // MARK: - Streaming (file path)

    private func tmpFile(_ content: Data) throws -> URL {
        let url = FileManager.default.temporaryDirectory / "fashion-digest-\(UUID())"
        try content.write(to: url)
        return url
    }

    func testFileHashMD5() throws {
        let url = try tmpFile(Data("hello".utf8))
        defer { try? FileManager.default.removeItem(at: url) }

        let result = try CryptoDigest.hash(path: url.path(), algorithm: .md5)
        XCTAssertEqual(result, "5d41402abc4b2a76b9719d911017c592")
    }

    func testFileHashSHA1() throws {
        let url = try tmpFile(Data("hello".utf8))
        defer { try? FileManager.default.removeItem(at: url) }

        let result = try CryptoDigest.hash(path: url.path(), algorithm: .sha1)
        XCTAssertEqual(result, "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d")
    }

    func testFileHashSHA256() throws {
        let url = try tmpFile(Data("hello".utf8))
        defer { try? FileManager.default.removeItem(at: url) }

        let result = try CryptoDigest.hash(path: url.path(), algorithm: .sha256)
        XCTAssertEqual(result, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
    }

    func testFileHashSHA384() throws {
        let url = try tmpFile(Data("hello".utf8))
        defer { try? FileManager.default.removeItem(at: url) }

        let result = try CryptoDigest.hash(path: url.path(), algorithm: .sha384)
        XCTAssertEqual(result, try CryptoDigest.hash(data: Data("hello".utf8), algorithm: .sha384))
    }

    func testFileHashSHA512() throws {
        let url = try tmpFile(Data("hello".utf8))
        defer { try? FileManager.default.removeItem(at: url) }

        let result = try CryptoDigest.hash(path: url.path(), algorithm: .sha512)
        XCTAssertEqual(result, try CryptoDigest.hash(data: Data("hello".utf8), algorithm: .sha512))
    }

    func testFileHashEmptyFile() throws {
        let url = try tmpFile(Data())
        defer { try? FileManager.default.removeItem(at: url) }

        let result = try CryptoDigest.hash(path: url.path(), algorithm: .sha256)
        XCTAssertEqual(result, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    }

    func testFileHashMissingFileThrows() {
        XCTAssertThrowsError(try CryptoDigest.hash(path: "/tmp/fashion-nonexistent-\(UUID())", algorithm: .sha256))
    }

    // MARK: - Multi-chunk streaming

    /// File larger than chunkSize (65536) forces multiple iterations of the update loop.
    func testFileHashMultiChunkSHA256() throws {
        let size = 65536 + 1024
        let data = Data(repeating: 0x41, count: size)
        let url = try tmpFile(data)
        defer { try? FileManager.default.removeItem(at: url) }

        let streaming = try CryptoDigest.hash(path: url.path(), algorithm: .sha256)
        let oneshot = try CryptoDigest.hash(data: data, algorithm: .sha256)
        XCTAssertEqual(streaming, oneshot)
    }

    func testFileHashMultiChunkMD5() throws {
        let size = 65536 * 3
        let data = Data(repeating: 0xbb, count: size)
        let url = try tmpFile(data)
        defer { try? FileManager.default.removeItem(at: url) }

        let streaming = try CryptoDigest.hash(path: url.path(), algorithm: .md5)
        let oneshot = try CryptoDigest.hash(data: data, algorithm: .md5)
        XCTAssertEqual(streaming, oneshot)
    }

    func testFileHashMultiChunkSHA512() throws {
        let size = 65536 * 2 + 100
        let data = Data(repeating: 0xcc, count: size)
        let url = try tmpFile(data)
        defer { try? FileManager.default.removeItem(at: url) }

        let streaming = try CryptoDigest.hash(path: url.path(), algorithm: .sha512)
        let oneshot = try CryptoDigest.hash(data: data, algorithm: .sha512)
        XCTAssertEqual(streaming, oneshot)
    }

    /// Streaming and oneshot must agree for every algorithm on the same content.
    func testFileHashConsistencyAllAlgorithms() throws {
        let data = Data("the quick brown fox jumps over the lazy dog".utf8)
        let url = try tmpFile(data)
        defer { try? FileManager.default.removeItem(at: url) }

        for algo: Algorithm in [.md5, .sha1, .sha256, .sha384, .sha512] {
            let streaming = try CryptoDigest.hash(path: url.path(), algorithm: algo)
            let oneshot = try CryptoDigest.hash(data: data, algorithm: algo)
            XCTAssertEqual(streaming, oneshot, "Mismatch for \(algo)")
        }
    }
}
