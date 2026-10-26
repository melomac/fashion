import CUCL
import Foundation

/**
 Bridge to UCL's NRV decompressors, the safe ones UPX unpacks with (`compress_ucl.cpp`): NRV2B, NRV2D and NRV2E, each
 reading its bit stream 8, 16 or 32 bits at a time.
 */
enum UCLBridge {
    /**
     The bytes a decoder may read past a block: the ones reading 32 bits at a time fetch their next word before they
     check the input (`getbit_le32`, then `fail(ilen >= src_len)` in `n2b_d.c` and the others), up to 3 bytes past a
     block whose last word is partial, which no packer writes, as the 16-bit ones fetch a byte past. UPX's buffer has
     `OVERHEAD` bytes after a block for it (`ibuf.alloc` in `p_unix.cpp`), and so must what is handed here.
     */
    static let slack = 4

    /**
     The first `count` bytes of `source` decompressed by UPX method `method`, 2 to 10, into `destination`, which it must
     fill; nil for any other method, or data that does not hold. `source` holds `slack` bytes more, which a decoder may
     read and never uses.
     */
    static func decompress(_ source: UnsafeRawBufferPointer, count: Int, method: UInt8, into destination: UnsafeMutableRawBufferPointer) -> Bool? {
        precondition(source.count >= count + self.slack, "a block needs \(self.slack) bytes of slack after it")
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
        let status = decompress(source.bindMemory(to: UInt8.self).baseAddress, UInt32(count), destination.bindMemory(to: UInt8.self).baseAddress, &length, nil)
        return status == 0 && length == UInt32(destination.count)
    }
}
