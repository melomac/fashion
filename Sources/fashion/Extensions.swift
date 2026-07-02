import Foundation

extension Sequence<UInt8> {
    /**
     Lowercase hex encoding via a nibble lookup table.

     Locale-independent and far faster than `String(format:)`,
     which matters when emitting many digests per file across a large tree.
     */
    var hexString: String {
        let digits: [UInt8] = Array("0123456789abcdef".utf8)
        var out: [UInt8] = []
        for byte in self {
            out.append(digits[Int(byte >> 4)])
            out.append(digits[Int(byte & 0x0f)])
        }
        return String(decoding: out, as: UTF8.self)
    }
}
