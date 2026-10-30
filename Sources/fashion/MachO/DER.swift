import Foundation

/**
 DER, as much of it as the signatures carry: CoreFoundation's DER property lists, the CMS signature a signer wrote and
 the timestamp token a timestamp authority gave it. Elements are read in turn, each a one-byte tag, a length and its
 content; the length is definite, or indefinite as Security's CMS encoder writes the signature's own sequences, BER
 rather than DER, the content then running to an end-of-contents of two zero bytes. Multi-byte tags are refused.
 */
enum DER {
    /// An element: its tag, its content, and the bytes of the whole, tag and length included.
    struct Element {
        let tag: UInt8
        let content: Data
        let raw: Data
    }

    /// The elements of DER bytes, read in turn.
    struct Reader {
        private let data: Data
        private var offset: Int

        init(_ data: Data) {
            self.data = data
            self.offset = data.startIndex
        }

        var atEnd: Bool {
            self.offset == self.data.endIndex
        }

        /// The next element, its length definite, short or long form, or indefinite, the content then the elements
        /// up to an end-of-contents; nil for anything else, or none left.
        mutating func next() -> Element? {
            guard self.offset + 2 <= self.data.endIndex else {
                return nil
            }
            let start = self.offset
            let tag = self.data[start]
            guard tag & 0x1f != 0x1f else {
                return nil
            }
            var length = Int(self.data[start + 1])
            var at = start + 2
            if length == 0x80 {
                var inner = Reader(self.data[at...])
                while true {
                    guard let element = inner.next() else {
                        return nil
                    }
                    if element.tag == 0, element.content.isEmpty {
                        self.offset = element.raw.endIndex
                        return Element(tag: tag, content: self.data[at ..< element.raw.startIndex], raw: self.data[start ..< self.offset])
                    }
                }
            }
            if length & 0x80 != 0 {
                let count = length & 0x7f
                guard 1 ... 4 ~= count, count <= self.data.endIndex - at else {
                    return nil
                }
                length = self.data[at ..< at + count].reduce(0) { $0 << 8 | Int($1) }
                at += count
            }
            guard length <= self.data.endIndex - at else {
                return nil
            }
            self.offset = at + length
            return Element(tag: tag, content: self.data[at ..< at + length], raw: self.data[start ..< at + length])
        }
    }

    /// Every element of `content`, nil when it does not parse as elements to its end.
    static func elements(of content: Data) -> [Element]? {
        var reader = Reader(content)
        var elements: [Element] = []
        while !reader.atEnd {
            guard let element = reader.next() else {
                return nil
            }
            elements.append(element)
        }
        return elements
    }

    /// `content` under `tag`, its length in the short form or the long one.
    static func encode(_ tag: UInt8, _ content: Data) -> Data {
        var encoded = Data([tag])
        if content.count < 0x80 {
            encoded.append(UInt8(content.count))
        } else {
            let bytes = withUnsafeBytes(of: UInt32(content.count).bigEndian) { Data($0) }.drop { $0 == 0 }
            encoded.append(0x80 | UInt8(bytes.count))
            encoded.append(contentsOf: bytes)
        }
        return encoded + content
    }

    /// A GeneralizedTime's date, `YYYYMMDDHHMMSSZ`, a fraction of a second dropped; nil for any other form.
    static func generalizedTime(_ content: Data) -> Date? {
        guard let string = String(data: content, encoding: .utf8), string.hasSuffix("Z"), string.count >= 15 else {
            return nil
        }
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.dateFormat = "yyyyMMddHHmmss"
        return formatter.date(from: String(string.prefix(14)))
    }
}
