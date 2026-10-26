@testable import fashion
import Foundation

/**
 The decoders a block of UPX's packed data goes through, fed straight: UCL's NRV2B, NRV2D and NRV2E in their three
 widths (`UCLBridge.decompress`, methods 2 to 10) and the LZMA SDK's (`LZMABridge.decompress`, method 14), picked by
 the block's method as `PackMach.decompress` picks them, then the filter the block names undone over what came out
 (`PackMach.unfilter`), as `unpackExtent` undoes it. The input is the block as `b_info` describes it, six bytes then
 the packed data: the method, the size it must decompress to in three bytes, little-endian, up to 1 MiB, the filter
 and its `cto`. `unpack` reaches the decoders behind a whole packed Mach-O; this reaches them at once, LZMA's two
 property bytes at the data's head, lc up to 8 and lp up to 4 as UPX writes them. UCL's decoders get the block with
 the slack `PackMach` reads after one, since they may read that far past it.
 */
@_cdecl("LLVMFuzzerTestOneInput")
public func fuzzDecompress(_ start: UnsafeRawPointer, _ count: Int) -> CInt {
    let bytes = UnsafeRawBufferPointer(start: start, count: count)
    guard count >= 6 else {
        return 0
    }
    let method = bytes[0]
    let size = min(Int(bytes[1]) | Int(bytes[2]) << 8 | Int(bytes[3]) << 16, 1 << 20)
    let (filter, cto) = (bytes[4], bytes[5])
    guard size > 0 else {
        return 0
    }
    let data = UnsafeRawBufferPointer(rebasing: bytes[6...])
    let source = UnsafeMutableRawBufferPointer.allocate(byteCount: data.count + UCLBridge.slack, alignment: 16)
    source.initializeMemory(as: UInt8.self, repeating: 0)
    source.copyMemory(from: data)
    let destination = UnsafeMutableRawBufferPointer.allocate(byteCount: size, alignment: 16)
    defer {
        source.deallocate()
        destination.deallocate()
    }
    let decompressed = method == 14 ? LZMABridge.decompress(data, into: destination) : UCLBridge.decompress(UnsafeRawBufferPointer(source), count: data.count, method: method, into: destination) ?? false
    if decompressed, filter != 0 {
        try? PackMach.unfilter(destination, id: filter, cto: cto)
    }
    return 0
}
