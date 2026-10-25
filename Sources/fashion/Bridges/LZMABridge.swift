import CLZMA
import Foundation

/**
 Bridge to liblzma, the xz library macOS ships, for LZMA as UPX stores it (`upx_lzma_decompress`, `compress_lzma.cpp`):
 two bytes of properties, pb, then lp and lc, the first byte's high bits holding lc + lp for UPX's stub, then the raw
 LZMA1 stream of the block, flushed, without the end marker. `CLZMA` declares what is called here, the SDK linking
 liblzma without a header.
 */
enum LZMABridge {
    /**
     `source` decompressed into `destination`, which it must fill, the stream consumed whole; false for data that does
     not hold.
     */
    static func decompress(_ source: UnsafeRawBufferPointer, into destination: UnsafeMutableRawBufferPointer) -> Bool {
        guard source.count >= 3 else {
            return false
        }
        let (pb, lp, lc) = (UInt32(source[0] & 7), UInt32(source[1] >> 4), UInt32(source[1] & 15))
        guard
            pb < 5,
            lp < 5,
            lc < 9,
            UInt32(source[0] >> 3) == lc + lp
        else {
            return false
        }
        var options = lzma_options_lzma()
        options.lc = lc
        options.lp = lp
        options.pb = pb
        // The dictionary is the window a match reaches back in: the block, no match reaching before its start, within
        // what liblzma allocates.
        options.dict_size = UInt32(clamping: min(max(destination.count, Int(LZMA_DICT_SIZE_MIN)), Int(LZMA_DICT_SIZE_MAX)))
        // liblzma 5.4 decodes a raw stream of known size without end marker as LZMA1EXT, and checks the encoder flushed
        // where the stream ends. Before it, LZMA1 stops where the output ends, reading up to a byte past the stream.
        let extended = lzma_filter_decoder_is_supported(LZMA_FILTER_LZMA1EXT) != 0
        options.ext_size_low = UInt32(truncatingIfNeeded: destination.count)
        options.ext_size_high = UInt32(truncatingIfNeeded: destination.count >> 32)
        return withUnsafeMutablePointer(to: &options) { options in
            let filters = [lzma_filter(id: extended ? LZMA_FILTER_LZMA1EXT : LZMA_FILTER_LZMA1, options: options), lzma_filter(id: LZMA_VLI_UNKNOWN, options: nil)]
            var stream = lzma_stream()
            guard lzma_raw_decoder(&stream, filters) == LZMA_OK else {
                return false
            }
            defer {
                lzma_end(&stream)
            }
            stream.next_in = source.bindMemory(to: UInt8.self).baseAddress! + 2
            stream.avail_in = source.count - 2
            stream.next_out = destination.bindMemory(to: UInt8.self).baseAddress
            stream.avail_out = destination.count
            let result = lzma_code(&stream, LZMA_RUN)
            return (result == LZMA_STREAM_END || result == LZMA_OK) && stream.total_in == UInt64(source.count - 2) && stream.total_out == UInt64(destination.count)
        }
    }
}
