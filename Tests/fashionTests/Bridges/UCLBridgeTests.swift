@testable import fashion
import XCTest

/**
 UCL's NRV decompressors as UPX calls them: each method's stream, made by UCL's own compressor (`ucl_nrv2*_99_compress`
 at level 10, its bit buffer 32, 8 or 16 bits wide), decompresses to the text it was made from. A stream cut short, or
 decompressed to another size, does not hold, and LZMA is no method of UCL's.
 */
final class UCLBridgeTests: XCTestCase {
    private let text = Data("fashion unpacks what UPX packed, block by block; fashion unpacks what UPX packed, block by block.\n".utf8)

    /// The text compressed by each NRV method, numbered as UPX numbers them: NRV2B, NRV2D then NRV2E, each read 32 bits
    /// at a time little-endian, then 8 bits, then 16 bits little-endian.
    private let streams: [UInt8: String] = [
        2: "bfffffff66617368696f6e20756e7061636b73207768617420555058200e6564b0675bfb2c20626c6f080579083b20300000c0a12e0a20010000ff",
        3: "ff66617368696f6e20ff756e7061636b7320ff7768617420555058bf200e6564fb2c20626c6f085b057967083bb02030a1c02e0a000000000120ff",
        4: "ffff66617368696f6e20756e7061636b7320bfff7768617420555058200e65645bfb2c20626c6f080579b067083b2030c0a12e0a000000002001ff",
        5: "bfffffff66617368696f6e20756e7061636b73207768617420555058201c65642c147b7bf720626c6f110b79113b2061922449382e0a00005049ff",
        6: "ff66617368696f6e20ff756e7061636b7320ff7768617420555058bf201c65642cf720626c6f117b0b79117b3b206114382e0a4924924950ff",
        7: "ffff66617368696f6e20756e7061636b7320bfff7768617420555058201c65642c7bf720626c6f110b7911147b3b206149382e0a92245049ff",
        8: "bbffffff66617368696f6e20756e7061636b73207768617420555058201d6564889d35fb2c20626c6f100a79113b2061499224bc2e0a0000a824ff",
        9: "ff66617368696f6e20ff756e7061636b7320ff7768617420555058bb201d6564fb2c20626c6f10350a799d113b208861bc2e0a24924924a8ff",
        10: "ffff66617368696f6e20756e7061636b7320bbff7768617420555058201d656435fb2c20626c6f100a79889d113b206124bc2e0a4992a824ff",
    ]

    /// `stream` decompressed by `method` into `count` bytes: the bridge's verdict, and the bytes when it holds.
    private func decompress(_ stream: Data, method: UInt8, count: Int) -> (Bool?, Data) {
        var output = Data(count: count)
        let result = stream.withUnsafeBytes { source in
            output.withUnsafeMutableBytes { UCLBridge.decompress(source, method: method, into: $0) }
        }
        return (result, output)
    }

    func testEachMethodDecompressesItsStream() throws {
        for (method, hex) in self.streams.sorted(by: { $0.key < $1.key }) {
            let (result, output) = try self.decompress(XCTUnwrap(Data(hex: hex)), method: method, count: self.text.count)
            XCTAssertEqual(result, true, "method \(method)")
            XCTAssertEqual(output, self.text, "method \(method)")
        }
    }

    func testStreamsThatDoNotHoldAreRefused() throws {
        for (method, hex) in self.streams {
            let stream = try XCTUnwrap(Data(hex: hex))
            XCTAssertEqual(self.decompress(stream.dropLast(4), method: method, count: self.text.count).0, false, "method \(method) cut short")
            XCTAssertEqual(self.decompress(stream, method: method, count: self.text.count - 1).0, false, "method \(method) into fewer bytes")
            XCTAssertEqual(self.decompress(stream, method: method, count: self.text.count + 1).0, false, "method \(method) into more bytes")
        }
    }

    func testOtherMethodsAreNotUCLs() throws {
        let stream = try XCTUnwrap(Data(hex: self.streams[2] ?? ""))
        for method: UInt8 in [0, 1, 11, 14, 255] {
            XCTAssertNil(self.decompress(stream, method: method, count: self.text.count).0, "method \(method)")
        }
    }
}
