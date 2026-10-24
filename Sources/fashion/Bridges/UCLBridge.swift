import CUCL
import Foundation

/**
 Bridge to UCL's NRV decompressors, the safe ones UPX unpacks with (`compress_ucl.cpp`): NRV2B, NRV2D and NRV2E, each
 reading its bit stream 8, 16 or 32 bits at a time.
 */
enum UCLBridge {
    /**
     `source` decompressed by UPX method `method`, 2 to 10, into `destination`, which it must fill; nil for any other
     method, or data that does not hold.
     */
    static func decompress(_ source: UnsafeRawBufferPointer, method: UInt8, into destination: UnsafeMutableRawBufferPointer) -> Bool? {
        let decompress: (UnsafePointer<UInt8>?, UInt32, UnsafeMutablePointer<UInt8>?, UnsafeMutablePointer<UInt32>?, UnsafeMutableRawPointer?) -> Int32
        switch method {
        case 2: decompress = ucl_nrv2b_decompress_safe_le32
        case 3: decompress = ucl_nrv2b_decompress_safe_8
        case 4: decompress = ucl_nrv2b_decompress_safe_le16
        case 5: decompress = ucl_nrv2d_decompress_safe_le32
        case 6: decompress = ucl_nrv2d_decompress_safe_8
        case 7: decompress = ucl_nrv2d_decompress_safe_le16
        case 8: decompress = ucl_nrv2e_decompress_safe_le32
        case 9: decompress = ucl_nrv2e_decompress_safe_8
        case 10: decompress = ucl_nrv2e_decompress_safe_le16
        default: return nil
        }
        var length = UInt32(destination.count)
        let status = decompress(source.bindMemory(to: UInt8.self).baseAddress, UInt32(source.count), destination.bindMemory(to: UInt8.self).baseAddress, &length, nil)
        return status == 0 && length == UInt32(destination.count)
    }
}
