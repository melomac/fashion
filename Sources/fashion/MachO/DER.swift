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

    /**
     An element: its tag, its content, and the bytes of the whole, tag and length included.

     `tag` is the tag as Security's decoder matches it against the one it expects: the class and constructed bits
     of the first byte, with the tag's number (`sec_asn1d_confirm_identifier`). The decoder takes a number under
     31 in the high-tag-number form as it takes it in one byte:

     ```
     30 ..          a SEQUENCE                     tag 0x30
     3f 10 ..       the same, its number apart     tag 0x30
     3f 80 10 ..    the same, the number padded    tag 0x30
     bf 1f ..       context tag 31                 tag 0xbf, which matches nothing read here
     ```

     `identifier` is the first byte as the bytes have it, for a reader that takes no such form, and for the
     end-of-contents, which is a first byte of 0.
     */
    struct Element {
        let tag: UInt8
        let identifier: UInt8
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
            /// Nothing read, `why` kept for the caller.
            func refused(_ why: String) -> Element? {
                self.fault = why
                return nil
            }
            let header: Header
            do {
                header = try DER.header(in: self.data, at: start)
            } catch {
                return refused(error.why)
            }
            let (tag, identifier, at) = (header.tag, header.identifier, header.content)
            guard let length = header.length else {
                // sec_asn1d_push_state: nested past SEC_ASN1D_MAX_DEPTH, the decoder refuses.
                guard self.depth < DER.maxDepth else {
                    return refused("nested past \(DER.maxDepth) levels at \(start.hex)")
                }
                var inner = Reader(self.data[at...], depth: self.depth + 1)
                while true {
                    guard let element = inner.next() else {
                        return refused(inner.fault ?? "an indefinite length at \(start.hex) with no end")
                    }
                    // sec_asn1d_parse_end_of_contents: the end is two zero bytes, and no other empty element of
                    // tag 0, which is read on as an element.
                    if element.identifier == 0, element.raw.count == 2 {
                        self.offset = element.raw.endIndex
                        return Element(tag: tag, identifier: identifier, content: self.data[at ..< element.raw.startIndex], raw: self.data[start ..< self.offset])
                    }
                }
            }
            guard length <= self.data.endIndex - at else {
                return refused(DER.overrun(header, at: start, left: self.data.endIndex - at))
            }
            self.offset = at + length
            return Element(tag: tag, identifier: identifier, content: self.data[at ..< at + length], raw: self.data[start ..< at + length])
        }
    }

    /// An element's tag and length: the tag as the decoder matches it and its first byte as written
    /// (`Element`), where its content starts, and the length it declares, nil when indefinite.
    private struct Header {
        let tag: UInt8
        let identifier: UInt8
        let content: Int
        let length: Int?
    }

    /// Why an element's tag and length do not read.
    private struct Unread: Error {
        let why: String
    }

    /// The tag and length of the element at `start` in `data`, read as Security's decoder reads them. Throws for
    /// bytes cut short or a form the decoder refuses, saying which.
    private static func header(in data: Data, at start: Int) throws(Unread) -> Header {
        guard start + 2 <= data.endIndex else {
            throw Unread(why: "an element at \(start.hex) cut short")
        }

        // sec_asn1d_parse_identifier: the low five bits all set, the number follows in seven-bit bytes until one
        // without the high bit, and may not pass 57 bits (sec_asn1d_parse_more_identifier).
        let identifier = data[start]
        var tag = identifier
        var at = start + 1
        if identifier & 0x1f == 0x1f {
            // The decoder's `unsigned long`: the last byte may fill its top bit, which makes no small number.
            var number: UInt = 0
            while true {
                guard at < data.endIndex else {
                    throw Unread(why: "the tag at \(start.hex) cut short")
                }
                guard number >> 57 == 0 else {
                    throw Unread(why: "the tag at \(start.hex) past 57 bits")
                }
                number = number << 7 | UInt(data[at] & 0x7f)
                at += 1
                if data[at - 1] & 0x80 == 0 {
                    break
                }
            }
            // sec_asn1d_confirm_identifier: the number is matched, however it was written.
            if number < 0x1f {
                tag = identifier & 0xe0 | UInt8(number)
            }
        }

        // sec_asn1d_parse_length: the high bit set, the low seven count the bytes of the length, none meaning
        // indefinite, each byte shifted in under 55 bits (sec_asn1d_parse_more_length).
        guard at < data.endIndex else {
            throw Unread(why: "the length at \(at.hex) missing")
        }
        var length = Int(data[at])
        at += 1
        if length == 0x80 {
            return Header(tag: tag, identifier: identifier, content: at, length: nil)
        }

        if length & 0x80 != 0 {
            let count = length & 0x7f
            guard count <= data.endIndex - at else {
                throw Unread(why: "the length at \(start.hex) of \(count) bytes cut short")
            }
            length = 0
            for byte in data[at ..< at + count] {
                guard length >> 55 == 0 else {
                    throw Unread(why: "the length at \(start.hex) past 55 bits")
                }
                length = length << 8 | Int(byte)
            }
            at += count
        }
        return Header(tag: tag, identifier: identifier, content: at, length: length)
    }

    /// The message for the element at `start`, whose length declares more than the `left` bytes after it.
    private static func overrun(_ header: Header, at start: Int, left: Int) -> String {
        "tag \(String(format: "0x%02x", header.identifier)) at \(start.hex) declares \(header.length ?? 0) bytes, \(left) left"
    }

    /// The outcome of reading one element for `fault(in:)`.
    private enum Read {
        /// The element reads, and ends at this offset.
        case end(Int)
        /// Bytes cut short, or a form the decoder refuses. No fault: the decoder refuses them too, if it reads them.
        case refused
        /// The fault: a length past the bytes left, which the decoder does not check. The message for it.
        case overrun(String)
    }

    /**
     Why `blob`, a CMS message, cannot be handed to Security's decoder; nil when it can, whatever the decoder then
     makes of it.

     The decoder checks an element's length against the first definite length around it, its parent's or one
     further out (`sec_asn1d_prepare_for_contents`, `sec_asn1d_check_and_subtract_length`):

     ```
     the element                                 its length
     ------------------------------------------  -----------------------------------------------------------
     under a definite length                     checked against the parent's, refused when it does not fit
     under indefinite lengths (0x80) inside a    checked against what is left of the definite one
       definite one
     the message itself, or under indefinite     not checked: there is no length to check it against
       lengths all the way up
     ```

     The decoder takes an unchecked length at its word. For a string, it allocates that many bytes, anything under
     2 GiB (`PORT_ArenaAlloc`), and fills them. Indefinite lengths are no rarity: Security's own encoder writes
     them for a signature's outer sequences.

     So the one fault is an unchecked length that declares more than the bytes left. It is looked for in the
     message itself and in every element no definite length encloses, however deep, down to `maxDepth`.

     An indefinite length ends at an end-of-contents: two zero bytes, and nothing else
     (`sec_asn1d_parse_end_of_contents`). Where the decoder expects a field and no end, it reads a tag of 0 as an
     element like any other, and takes its length at its word when unchecked. So any other element of tag 0 is
     read on as an element here.

     Anything else is left to the decoder, to take or refuse:

     - bytes cut short, and forms it refuses;
     - a length that passes a definite length around it, which the decoder checks itself;
     - content of a definite length that does not read as elements: the decoder may not read it as elements at
       all, as with a certificate, whose bytes it keeps as it finds them;
     - what follows the message, the first element of `blob`: it never reads that.

     Offsets in the fault are offsets in `blob`.
     */
    static func fault(in blob: Data) -> String? {
        if case let .overrun(fault) = self.read(blob, at: blob.startIndex, unchecked: true, depth: 0) {
            return fault
        }
        return nil
    }

    /// Read the element at `start` of `data` and every element nested in it, in the order the decoder meets them.
    /// `unchecked` says the decoder does not check this element's length: no element around it has a definite one.
    private static func read(_ data: Data, at start: Int, unchecked: Bool, depth: Int) -> Read {
        guard let header = try? self.header(in: data, at: start) else {
            return .refused
        }

        guard let length = header.length else {
            // sec_asn1d_push_state: nested past SEC_ASN1D_MAX_DEPTH, the decoder refuses.
            guard depth < self.maxDepth else {
                return .refused
            }
            var at = header.content
            while true {
                guard let child = try? self.header(in: data, at: at) else {
                    return .refused
                }
                // The end-of-contents: two zero bytes, no other empty element of tag 0.
                if child.identifier == 0, child.length == 0, child.content == at + 2 {
                    return .end(child.content)
                }
                // A child is checked against the first definite length around it, which is this element's too:
                // an indefinite length has none of its own to check against.
                switch self.read(data, at: at, unchecked: unchecked, depth: depth + 1) {
                case let .end(next):
                    at = next
                case .refused:
                    // Where it ends is unknown, so nothing after it can be read.
                    return .refused
                case let .overrun(fault):
                    return .overrun(fault)
                }
            }
        }

        guard length <= data.endIndex - header.content else {
            return unchecked ? .overrun(self.overrun(header, at: start, left: data.endIndex - header.content)) : .refused
        }

        let end = header.content + length
        if header.tag & 0x20 != 0, depth < self.maxDepth {
            let content = data[..<end]
            var at = header.content
            while at < end {
                switch self.read(content, at: at, unchecked: false, depth: depth + 1) {
                case let .end(next):
                    at = next
                case .refused:
                    // The decoder refuses it there, or does not read this content as elements: no unchecked
                    // length lies past it.
                    at = end
                case let .overrun(fault):
                    return .overrun(fault)
                }
            }
        }
        return .end(end)
    }

    /// The message in `blob`: its first element, which is all Security's decoder reads. `blob` as it is when that
    /// element does not read.
    static func message(of blob: Data) -> Data {
        var reader = Reader(blob)
        return reader.next()?.raw ?? blob
    }

    /**
     The bytes of an OCTET STRING as Security's decoder gives them, nil for any other element. The decoder takes a
     string in one piece or constructed, its substrings strings of the same type, constructed again or not, and
     gives their bytes in turn (`sec_asn1d_concat_substrings`):

     ```
     04 03 61 62 63                             "abc"
     24 07 { 04 01 61, 04 02 62 63 }            "abc"
     24 80 { 24 03 { 04 01 61 }, .. } 00 00     "a.."
     ```
     */
    static func octets(of element: Element) -> Data? {
        self.octets(of: element, depth: 0)
    }

    private static func octets(of element: Element, depth: Int) -> Data? {
        switch element.tag {
        case 0x04:
            return Data(element.content)
        case 0x24:
            guard depth < self.maxDepth, let substrings = self.elements(of: element.content) else {
                return nil
            }
            var bytes = Data()
            for substring in substrings {
                guard let part = self.octets(of: substring, depth: depth + 1) else {
                    return nil
                }
                bytes += part
            }
            return bytes
        default:
            return nil
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
        /// The number the `count` digits from `start` spell.
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
