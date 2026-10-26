import CLZMA
import Foundation

/**
 Bridge to the LZMA SDK's decoder, as UPX stores LZMA (`upx_lzma_decompress`, `compress_lzma.cpp`): two bytes of
 properties, pb, then lp and lc, the first byte's high bits holding lc + lp for UPX's stub, then the stream.
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
        let (pb, lp, lc) = (Int32(source[0] & 7), Int32(source[1] >> 4), Int32(source[1] & 15))
        guard
            pb < 5,
            lp < 5,
            lc < 9,
            Int32(source[0] >> 3) == lc + lp
        else {
            return false
        }
        var state = CLzmaDecoderState()
        state.Properties = CLzmaProperties(lc: lc, lp: lp, pb: pb)
        let probs = UnsafeMutablePointer<UInt16>.allocate(capacity: Int(LZMA_BASE_SIZE + (LZMA_LIT_SIZE << (lc + lp))))
        defer {
            probs.deallocate()
        }
        state.Probs = probs
        var consumed: SizeT = 0
        var produced: SizeT = 0
        let stream = source.bindMemory(to: UInt8.self).baseAddress! + 2
        let result = LzmaDecode(&state, stream, SizeT(source.count - 2), &consumed, destination.bindMemory(to: UInt8.self).baseAddress, SizeT(destination.count), &produced)
        return result == 0 && consumed == SizeT(source.count - 2) && produced == SizeT(destination.count)
    }
}
