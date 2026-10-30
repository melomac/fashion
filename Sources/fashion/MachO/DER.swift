import Foundation

/**
 DER, as much of it as the signatures carry: CoreFoundation's DER property lists, the CMS signature a signer wrote and
 the timestamp token a timestamp authority gave it. Elements are read in turn, each a one-byte tag, a length and its
 content; the length is definite, or indefinite as Security's CMS encoder writes the signature's own sequences, BER
 rather than DER, the content then running to an end-of-contents of two zero bytes. Multi-byte tags are refused.
 */
enum DER {
    /// How deep elements may nest, where a crafted blob nests one every two bytes and each level read is a stack
    /// frame: Security's CMS and CoreFoundation's plists nest a dozen deep at most.
    static let maxDepth = 32

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
        /// How many indefinite-length elements enclose what is read.
        private let depth: Int

        init(_ data: Data) {
            self.init(data, depth: 0)
        }

        private init(_ data: Data, depth: Int) {
            self.data = data
            self.offset = data.startIndex
            self.depth = depth
        }

        var atEnd: Bool {
            self.offset == self.data.endIndex
        }

        /// The next element, its length definite, short or long form, or indefinite, the content then the elements
        /// up to an end-of-contents, nested no deeper than `maxDepth`; nil for anything else, or none left.
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
                guard self.depth < DER.maxDepth else {
                    return nil
                }
                var inner = Reader(self.data[at...], depth: self.depth + 1)
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

    /// The calendar a GeneralizedTime counts in: Gregorian, UTC.
    private static let utc: Calendar = {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC")!
        return calendar
    }()

    /// A GeneralizedTime's date, `YYYYMMDDHHMMSSZ`, a fraction of a second dropped; nil for any other form.
    static func generalizedTime(_ content: Data) -> Date? {
        guard content.count >= 15, content.last == UInt8(ascii: "Z"), content.prefix(14).allSatisfy({ (0x30 ... 0x39).contains($0) }) else {
            return nil
        }
        let digits = content.prefix(14).map { Int($0 - 0x30) }
        func field(_ start: Int, _ count: Int) -> Int {
            digits[start ..< start + count].reduce(0) { $0 * 10 + $1 }
        }
        let components = DateComponents(year: field(0, 4), month: field(4, 2), day: field(6, 2), hour: field(8, 2), minute: field(10, 2), second: field(12, 2))
        guard components.isValidDate(in: self.utc) else {
            return nil
        }
        return self.utc.date(from: components)
    }
}
