import Foundation

/**
 The DER form of an entitlements property list, which codesign writes into a signature beside the XML form since
 macOS 12 (`CSSLOT_DER_ENTITLEMENTS`), and which AMFI and the kernel read where it is: CoreFoundation's DER plist.
 A dictionary is a constructed context tag 16 of SEQUENCE pairs, a UTF8String key then its value; a value is a
 BOOLEAN, an INTEGER, a UTF8String, an OCTET STRING, a GeneralizedTime, a SEQUENCE for an array or a dictionary; the
 whole is wrapped in an application tag 16 after an INTEGER version of 1.
 */
enum DEREntitlements {
    /**
     The entitlements `der` holds, as `PropertyListSerialization` hands the XML form; nil for bytes that are not a
     DER plist dictionary.
     */
    static func decode(_ der: Data) -> [String: Any]? {
        var outer = Reader(der)
        guard let wrapper = outer.next(), wrapper.tag == 0x70, outer.atEnd else {
            return nil
        }
        var inner = Reader(wrapper.content)
        guard
            let version = inner.next(), version.tag == 0x02, Self.integer(version.content) == 1,
            let root = inner.next(), inner.atEnd
        else {
            return nil
        }
        return Self.value(of: root) as? [String: Any]
    }

    // MARK: - Private

    /// A DER element: its one-byte tag, and its content.
    private struct Element {
        let tag: UInt8
        let content: Data
    }

    /// The elements of DER bytes, read in turn.
    private struct Reader {
        private let data: Data
        private var offset: Int

        init(_ data: Data) {
            self.data = data
            self.offset = data.startIndex
        }

        var atEnd: Bool {
            self.offset == self.data.endIndex
        }

        /// The next element, its length definite, short or long form; nil for anything else, or none left.
        mutating func next() -> Element? {
            guard self.offset + 2 <= self.data.endIndex else {
                return nil
            }
            let tag = self.data[self.offset]
            var length = Int(self.data[self.offset + 1])
            var at = self.offset + 2
            if length & 0x80 != 0 {
                let count = length & 0x7f
                guard 1 ... 4 ~= count, count <= self.data.endIndex - at else {
                    return nil
                }
                length = self.data[at ..< at + count].reduce(0) { $0 << 8 | Int($1) }
                at += count
            }
            guard tag & 0x1f != 0x1f, length <= self.data.endIndex - at else {
                return nil
            }
            self.offset = at + length
            return Element(tag: tag, content: self.data[at ..< at + length])
        }
    }

    /// The value `element` holds, as a property list holds it; nil for a tag or content a plist has no value for.
    private static func value(of element: Element) -> Any? {
        switch element.tag {
        case 0x01: // BOOLEAN
            element.content.count == 1 ? element.content.first != 0 : nil
        case 0x02: // INTEGER
            self.integer(element.content)
        case 0x04: // OCTET STRING
            Data(element.content)
        case 0x0c: // UTF8String
            String(data: element.content, encoding: .utf8)
        case 0x18: // GeneralizedTime
            self.date(element.content)
        case 0x30: // SEQUENCE: an array
            self.elements(of: element.content).flatMap { elements in
                let values = elements.compactMap(Self.value)
                return values.count == elements.count ? values : nil
            }
        case 0xb0, 0x31: // a dictionary of SEQUENCE pairs: context tag 16, constructed, as CoreFoundation writes it, or a SET
            self.elements(of: element.content).flatMap { pairs in
                var dictionary: [String: Any] = [:]
                for pair in pairs {
                    guard
                        pair.tag == 0x30,
                        let entry = Self.elements(of: pair.content), entry.count == 2,
                        entry[0].tag == 0x0c, let key = String(data: entry[0].content, encoding: .utf8),
                        let value = Self.value(of: entry[1]),
                        dictionary.updateValue(value, forKey: key) == nil
                    else {
                        return nil
                    }
                }
                return dictionary
            }
        default:
            nil
        }
    }

    /// Every element of `content`, nil when it does not parse as elements to its end.
    private static func elements(of content: Data) -> [Element]? {
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

    /// An INTEGER's value, big-endian two's complement; nil past 64 bits.
    private static func integer(_ content: Data) -> Int? {
        guard 1 ... 8 ~= content.count else {
            return nil
        }
        let magnitude = content.reduce(0 as UInt64) { $0 << 8 | UInt64($1) }
        let signExtended = content.count < 8 && content.first! & 0x80 != 0 ? magnitude | ~0 << UInt64(8 * content.count) : magnitude
        return Int(bitPattern: UInt(signExtended))
    }

    /// A GeneralizedTime's date, `YYYYMMDDHHMMSSZ`, as the DER plist writes one; nil for any other form.
    private static func date(_ content: Data) -> Date? {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.dateFormat = "yyyyMMddHHmmss'Z'"
        return String(data: content, encoding: .utf8).flatMap(formatter.date)
    }
}
