@testable import fashion
import XCTest

final class ByteHashTests: XCTestCase {
    private func tmpFile(_ content: Data) throws -> URL {
        let url = FileManager.default.temporaryDirectory / "fashion-bytehash-\(UUID())"
        try content.write(to: url)
        return url
    }

    func testEveryAlgorithmButCDHashHashesBytes() {
        for algorithm in Algorithm.allCases {
            XCTAssertEqual(ByteHash(algorithm)?.rawValue, algorithm == .cdhash ? nil : algorithm.rawValue)
        }
    }

    // MARK: - Bytes in memory

    func testMD5Empty() throws {
        XCTAssertEqual(try ByteHash.md5.digest(Data()), "d41d8cd98f00b204e9800998ecf8427e")
    }

    func testMD5Hello() throws {
        XCTAssertEqual(try ByteHash.md5.digest(Data("hello".utf8)), "5d41402abc4b2a76b9719d911017c592")
    }

    func testSHA1Empty() throws {
        XCTAssertEqual(try ByteHash.sha1.digest(Data()), "da39a3ee5e6b4b0d3255bfef95601890afd80709")
    }

    func testSHA1Hello() throws {
        XCTAssertEqual(try ByteHash.sha1.digest(Data("hello".utf8)), "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d")
    }

    func testSHA256Empty() throws {
        XCTAssertEqual(try ByteHash.sha256.digest(Data()), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    }

    func testSHA256Hello() throws {
        XCTAssertEqual(try ByteHash.sha256.digest(Data("hello".utf8)), "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
    }

    func testSHA384Empty() throws {
        XCTAssertEqual(try ByteHash.sha384.digest(Data()), "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b")
    }

    func testSHA512Empty() throws {
        XCTAssertEqual(try ByteHash.sha512.digest(Data()), "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e")
    }

    func testGitBlobSHA1Empty() throws {
        // git hash-object of an empty file: the hash of "blob 0\0".
        XCTAssertEqual(try ByteHash.git.digest(Data()), "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391")
    }

    func testGitBlobSHA1Hello() throws {
        // "blob 5\0hello"
        XCTAssertEqual(try ByteHash.git.digest(Data("hello".utf8)), "b6fc4c620b67d95f953a5c1c1230aaab5db5a1b0")
    }

    func testGitBlobSHA256Empty() throws {
        // git hash-object --object-format=sha256 of an empty file.
        XCTAssertEqual(try ByteHash.git256.digest(Data()), "473a0f4c3be8a93681a267e3b1e9a7dcda1185436fe141f7749120a303721813")
    }

    // MARK: - Files

    func testFileMatchesBytesForEveryAlgorithm() throws {
        let data = Data("the quick brown fox jumps over the lazy dog".utf8)
        let url = try self.tmpFile(data)
        defer {
            try? FileManager.default.removeItem(at: url)
        }

        for hash: ByteHash in [.md5, .sha1, .sha256, .sha384, .sha512, .git, .git256, .ssdeep] {
            XCTAssertEqual(try hash.digest(File(path: url.path())), try hash.digest(data), "Mismatch for \(hash)")
        }
    }

    func testFileHashEmptyFile() throws {
        let url = try self.tmpFile(Data())
        defer {
            try? FileManager.default.removeItem(at: url)
        }

        XCTAssertEqual(try ByteHash.sha256.digest(File(path: url.path())), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    }

    func testFileHashMissingFileThrows() {
        XCTAssertThrowsError(try ByteHash.sha256.digest(File(path: "/tmp/fashion-nonexistent-\(UUID())")))
        XCTAssertThrowsError(try ByteHash.git.digest(File(path: "/tmp/fashion-nonexistent-\(UUID())")))
    }

    /// A file larger than a read chunk is hashed across several reads.
    func testFileHashAcrossChunks() throws {
        let data = Data((0 ..< File.chunkSize * 2 + 1024).map { UInt8($0 & 0xff) })
        let url = try self.tmpFile(data)
        defer {
            try? FileManager.default.removeItem(at: url)
        }

        for hash: ByteHash in [.md5, .sha256, .sha512, .git, .ssdeep, .tlsh] {
            XCTAssertEqual(try hash.digest(File(path: url.path())), try hash.digest(data), "Mismatch for \(hash)")
        }
    }

    func testRangeHashesOnlyThoseBytes() throws {
        let url = try self.tmpFile(Data("xxhelloyy".utf8))
        defer {
            try? FileManager.default.removeItem(at: url)
        }

        for hash: ByteHash in [.md5, .sha256, .git, .ssdeep] {
            XCTAssertEqual(try hash.digest(File(path: url.path()), range: 2 ..< 7), try hash.digest(Data("hello".utf8)), "Mismatch for \(hash)")
        }
    }

    func testShrunkFileThrows() throws {
        // A file that no longer holds the range by the time it is read fails closed, whatever the hash.
        let url = try self.tmpFile(Data("hello".utf8))
        defer {
            try? FileManager.default.removeItem(at: url)
        }

        for hash: ByteHash in [.md5, .sha256, .git, .ssdeep, .tlsh] {
            try Data("hello".utf8).write(to: url)
            let file = try File(path: url.path())
            XCTAssertEqual(truncate(url.path(), 2), 0)
            XCTAssertThrowsError(try hash.digest(file)) { error in
                XCTAssertEqual(error as? FileError, .sizeChanged(opened: 5, now: 2), "\(hash)")
            }
        }
    }

    func testSizeChangedDescriptionAgreesWithCount() {
        XCTAssertEqual(
            FileError.sizeChanged(opened: 1, now: 2).localizedDescription,
            "File changed size while hashing (1 byte when opened, 2 now)",
        )
        XCTAssertEqual(
            FileError.sizeChanged(opened: 2, now: 1).localizedDescription,
            "File changed size while hashing (2 bytes when opened, 1 now)",
        )
    }
}
