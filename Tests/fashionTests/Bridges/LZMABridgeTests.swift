@testable import fashion
import XCTest

/**
 liblzma's decoder as UPX's stream needs it: a stream after UPX's two bytes of properties decompresses to the text it
 was made from, consumed whole. Properties out of range, or whose first byte does not hold lc + lp, a stream cut short or
 followed by more, and another size, do not hold.
 */
final class LZMABridgeTests: XCTestCase {
    private let text = Data("fashion unpacks what UPX packed, block by block; fashion unpacks what UPX packed, block by block.\n".utf8)

    /// The text compressed with lc 3, lp 0 and pb 2, after UPX's properties: (lc + lp) << 3 | pb, then lp << 4 | lc.
    /// liblzma's LZMA1 encoder made the stream for a known size, flushed without the end marker, as UPX's encoder does.
    private let stream = "1a030033184acd2c085daf94501343f98993f8408b93f1a389cba51e87d233b978c4de4005ad4f9b70132932c9125228c57ed1d9542c00"

    /// `stream` decompressed into `count` bytes: the bridge's verdict, and the bytes when it holds.
    private func decompress(_ stream: Data, count: Int) -> (Bool, Data) {
        var output = Data(count: count)
        let result = stream.withUnsafeBytes { source in
            output.withUnsafeMutableBytes { LZMABridge.decompress(source, into: $0) }
        }
        return (result, output)
    }

    func testStreamDecompresses() throws {
        let (result, output) = try self.decompress(XCTUnwrap(Data(hex: self.stream)), count: self.text.count)
        XCTAssertTrue(result)
        XCTAssertEqual(output, self.text)
    }

    func testPropertiesThatDoNotHoldAreRefused() throws {
        let stream = try XCTUnwrap(Data(hex: self.stream))
        func with(_ first: UInt8, _ second: UInt8) -> Data {
            Data([first, second]) + stream.dropFirst(2)
        }
        XCTAssertFalse(self.decompress(with(0x1d, 0x03), count: self.text.count).0, "pb 5")
        XCTAssertFalse(self.decompress(with(0x42, 0x53), count: self.text.count).0, "lp 5")
        XCTAssertFalse(self.decompress(with(0x4a, 0x09), count: self.text.count).0, "lc 9")
        XCTAssertFalse(self.decompress(with(0x22, 0x03), count: self.text.count).0, "lc + lp of 4 where they make 3")
        XCTAssertFalse(self.decompress(stream.prefix(2), count: self.text.count).0, "no stream")
    }

    func testStreamsThatDoNotHoldAreRefused() throws {
        let stream = try XCTUnwrap(Data(hex: self.stream))
        XCTAssertFalse(self.decompress(stream.dropLast(4), count: self.text.count).0, "cut short")
        XCTAssertFalse(self.decompress(stream + Data([0]), count: self.text.count).0, "followed by more")
        XCTAssertFalse(self.decompress(stream, count: self.text.count - 1).0, "into fewer bytes")
        XCTAssertFalse(self.decompress(stream, count: self.text.count + 1).0, "into more bytes")
    }
}
