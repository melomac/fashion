import Foundation

/**
 DER, as much of it as the signatures carry: CoreFoundation's DER property lists, the CMS signature a signer wrote and
 the timestamp token a timestamp authority gave it. Elements are read in turn, each a one-byte tag, a length and its
 content; the length is definite, or indefinite as Security's CMS encoder writes the signature's own sequences, BER
 rather than DER, the content then running to an end-of-contents of two zero bytes. Tags and lengths are read as
 Security's decoder reads them, `SEC_ASN1DecoderUpdate`: a tag whose low five bits are set goes on in seven-bit
 bytes (`sec_asn1d_parse_more_identifier`), a long-form length in as many bytes as its first says
 (`sec_asn1d_parse_more_length`), each under the decoder's overflow guard, so that nothing it decodes is refused here.
 */
enum DER {
    /// How deep elements may nest, where a crafted blob nests one every two bytes and each level read is a stack
    /// frame: Security's CMS and CoreFoundation's plists nest a dozen deep at most.
    static let maxDepth = 32

    /// An element: its tag, its content, and the bytes of the whole, tag and length included. A tag in the
    /// high-tag-number form keeps its first byte here, class and constructed bit with the low five bits set, its
    /// number read past it and dropped: nothing read here matches one.
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
        /// Why the last `next` read nothing, where the bytes are at fault: the offset is in the data the outermost
        /// reader was given.
        private(set) var fault: String?

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

        /// The next element, its tag in one byte or the high-tag-number form, its length definite, short or long
        /// form, or indefinite, the content then the elements up to an end-of-contents, nested no deeper than
        /// `maxDepth`; nil for anything else, or none left, `fault` saying which.
        mutating func next() -> Element? {
            let start = self.offset
            func refused(_ why: String) -> Element? {
                self.fault = why
                return nil
            }
            guard start + 2 <= self.data.endIndex else {
                return refused("an element at \(start.hex) cut short")
            }
            // sec_asn1d_parse_identifier: the low five bits all set, the number follows in seven-bit bytes until one
            // without the high bit, and may not pass 57 bits (sec_asn1d_parse_more_identifier).
            let tag = self.data[start]
            var at = start + 1
            if tag & 0x1f == 0x1f {
                var number = 0
                while true {
                    guard at < self.data.endIndex else {
                        return refused("the tag at \(start.hex) cut short")
                    }
                    guard number >> 57 == 0 else {
                        return refused("the tag at \(start.hex) past 57 bits")
                    }
                    number = number << 7 | Int(self.data[at] & 0x7f)
                    at += 1
                    if self.data[at - 1] & 0x80 == 0 {
                        break
                    }
                }
            }
            // sec_asn1d_parse_length: the high bit set, the low seven count the bytes of the length, none meaning
            // indefinite, each byte shifted in under 55 bits (sec_asn1d_parse_more_length).
            guard at < self.data.endIndex else {
                return refused("the length at \(at.hex) missing")
            }
            var length = Int(self.data[at])
            at += 1
            if length == 0x80 {
                // sec_asn1d_push_state: nested past SEC_ASN1D_MAX_DEPTH, the decoder refuses.
                guard self.depth < DER.maxDepth else {
                    return refused("nested past \(DER.maxDepth) levels at \(start.hex)")
                }
                var inner = Reader(self.data[at...], depth: self.depth + 1)
                while true {
                    guard let element = inner.next() else {
                        return refused(inner.fault ?? "an indefinite length at \(start.hex) with no end")
                    }
                    if element.tag == 0, element.content.isEmpty {
                        self.offset = element.raw.endIndex
                        return Element(tag: tag, content: self.data[at ..< element.raw.startIndex], raw: self.data[start ..< self.offset])
                    }
                }
            }
            if length & 0x80 != 0 {
                let count = length & 0x7f
                guard count <= self.data.endIndex - at else {
                    return refused("the length at \(start.hex) of \(count) bytes cut short")
                }
                length = 0
                for byte in self.data[at ..< at + count] {
                    guard length >> 55 == 0 else {
                        return refused("the length at \(start.hex) past 55 bits")
                    }
                    length = length << 8 | Int(byte)
                }
                at += count
            }
            // sec_asn1d_check_and_subtract_length: the length within what is left, which the decoder checks only
            // under a definite length, and allocates and fills otherwise, anything under 2 GiB (PORT_ArenaAlloc).
            guard length <= self.data.endIndex - at else {
                return refused("tag \(String(format: "0x%02x", tag)) at \(start.hex) declares \(length) bytes, \(self.data.endIndex - at) left")
            }
            self.offset = at + length
            return Element(tag: tag, content: self.data[at ..< at + length], raw: self.data[start ..< at + length])
        }
    }

    /**
     The first fault in `content` read as elements to its end, every constructed one's content likewise, down to
     `maxDepth`, as Security's decoder would meet it streaming; nil when there is none. Offsets are in `content`.
     */
    static func fault(in content: Data, depth: Int = 0) -> String? {
        guard depth < self.maxDepth else {
            return "nested past \(self.maxDepth) levels"
        }
        var reader = Reader(content)
        var constructed: [Element] = []
        while !reader.atEnd {
            guard let element = reader.next() else {
                return reader.fault ?? "not DER"
            }
            if element.tag & 0x20 != 0 {
                constructed.append(element)
            }
        }
        for element in constructed {
            if let fault = self.fault(in: element.content, depth: depth + 1) {
                return fault
            }
        }
        return nil
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
