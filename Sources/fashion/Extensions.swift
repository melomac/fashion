import Foundation

extension String {
    /**
     The count followed by `noun`, or by its `plural` unless the count is one: `String(2, pluralizing: "file")` is
     "2 files". The plural defaults to `noun` + "s"; pass it for any other noun: `String(2, pluralizing: "hash", plural: "hashes")`.
     */
    init(_ count: Int, pluralizing noun: String, plural: String? = nil) {
        self = "\(count) \(count == 1 ? noun : plural ?? noun + "s")"
    }
}

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
