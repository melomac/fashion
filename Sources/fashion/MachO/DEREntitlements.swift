import Foundation

/**
 The DER form of an entitlements property list, which codesign writes into a signature beside the XML form since
 macOS 12 (`CSSLOT_DER_ENTITLEMENTS`), and which AMFI reads at exec through CoreEntitlements, refusing the code for
 what it does not take. Version 1, as codesign writes it: an application tag 16 wrapper holding an INTEGER 1 and the
 root dictionary, nothing after it, the dictionary a constructed context tag 16 of SEQUENCE pairs, each a UTF8String
 key and one value, the keys strictly ascending; version 0, which AMFI takes as well: the root dictionary alone, a
 SET, its keys in any order. Bytes past the wrapper, or past a version 0 dictionary, are not read. A value is a
 BOOLEAN, an INTEGER, a UTF8String, a SEQUENCE for an array, or a dictionary under the root's own tag, nested twelve
 levels at most; an OCTET STRING, a NumericString, a UTCTime, a dictionary under another tag, which CoreEntitlements'
 validator admits under options, are refused at exec all the same, as is anything else, a GeneralizedTime among it.
 */
enum DEREntitlements {
    /// Why AMFI refuses the code: `what` the blob holds.
    struct Refusal: Error {
        let what: String

        init(_ what: String) {
            self.what = what
        }
    }

    /// How deep values may nest: the validator refuses a thirteenth level.
    private static let maxDepth = 12

    /// The entitlements `der` holds, as `PropertyListSerialization` hands the XML form, read as AMFI reads them;
    /// throws a `Refusal` for what it refuses the code for.
    static func decode(_ der: Data) throws(Refusal) -> [String: Any] {
        guard !der.starts(with: "<?xml".utf8) else {
            throw Refusal("an XML plist in place of DER")
        }
        var outer = DER.Reader(der)
        guard let first = outer.next() else {
            throw Refusal("no element to read")
        }
        switch first.tag {
        case 0x70:
            var inner = DER.Reader(first.content)
            guard let version = inner.next(), version.tag == 0x02, let number = Self.integer(version.content) else {
                throw Refusal("no version under the wrapper")
            }
            guard number == 1 else {
                throw Refusal("version \(number) where 1 is expected")
            }
            guard let root = inner.next(), root.tag == 0xb0 else {
                throw Refusal("no dictionary after the version")
            }
            guard inner.atEnd else {
                throw Refusal("bytes after the dictionary within the wrapper")
            }
            return try Self.dictionary(root.content, tag: 0xb0, ordered: true, depth: 0)
        case 0x31:
            return try Self.dictionary(first.content, tag: 0x31, ordered: false, depth: 0)
        default:
            throw Refusal("a root that is neither the version 1 wrapper nor a version 0 dictionary")
        }
    }

    // MARK: - Private

    /// A dictionary's `content`, SEQUENCE pairs of a key and one value, the keys strictly ascending when `ordered`;
    /// `tag` is the root's, what a nested dictionary bears; the first of a key twice is kept.
    private static func dictionary(_ content: Data, tag: UInt8, ordered: Bool, depth: Int) throws(Refusal) -> [String: Any] {
        guard let pairs = DER.elements(of: content) else {
            throw Refusal("a dictionary that does not parse")
        }
        var dictionary: [String: Any] = [:]
        var previous: Data?
        for pair in pairs {
            guard pair.tag == 0x30, let entry = DER.elements(of: pair.content), entry.count == 2 else {
                throw Refusal("a pair that is not a key and one value")
            }
            let bytes = Data(entry[0].content)
            guard entry[0].tag == 0x0c, !bytes.isEmpty, !bytes.contains(0), let key = String(data: bytes, encoding: .utf8) else {
                throw Refusal("a key that is not a string")
            }
            if ordered, let previous, !previous.lexicographicallyPrecedes(bytes) {
                // A key is the blob's own bytes: quoted when it is not printable ASCII, so it stays on one line.
                throw Refusal("keys out of order, \(MachOVerifier.shown(key)) after \(MachOVerifier.shown(String(decoding: previous, as: UTF8.self)))")
            }
            previous = bytes
            let value = try Self.value(of: entry[1], tag: tag, ordered: ordered, depth: depth + 1)
            if dictionary[key] == nil {
                dictionary[key] = value
            }
        }
        return dictionary
    }

    /// The value `element` holds, as a property list holds it, `depth` levels down.
    private static func value(of element: DER.Element, tag: UInt8, ordered: Bool, depth: Int) throws(Refusal) -> Any {
        guard depth <= self.maxDepth else {
            throw Refusal("values nested past \(self.maxDepth) levels")
        }
        switch element.tag {
        case tag:
            return try self.dictionary(element.content, tag: tag, ordered: ordered, depth: depth)
        case 0x01: // BOOLEAN
            guard element.content.count == 1 else {
                throw Refusal("a BOOLEAN of \(element.content.count) bytes")
            }
            return element.content.first != 0
        case 0x02: // INTEGER
            guard let integer = Self.integer(element.content) else {
                throw Refusal("an INTEGER past 64 bits")
            }
            return integer
        case 0x0c: // UTF8String
            guard !element.content.contains(0), let string = String(data: element.content, encoding: .utf8) else {
                throw Refusal("a string holding NUL")
            }
            return string
        case 0x30: // SEQUENCE: an array
            guard let elements = DER.elements(of: element.content) else {
                throw Refusal("an array that does not parse")
            }
            var values: [Any] = []
            for element in elements {
                try values.append(Self.value(of: element, tag: tag, ordered: ordered, depth: depth + 1))
            }
            return values
        case 0x04:
            throw Refusal("an OCTET STRING value")
        case 0x12:
            throw Refusal("a NumericString value")
        case 0x17:
            throw Refusal("a UTCTime value")
        case 0x18:
            throw Refusal("a GeneralizedTime value")
        case 0x31, 0x70:
            throw Refusal("a dictionary tagged \(element.tag.hex) under a root tagged \(tag.hex)")
        default:
            throw Refusal("a value tagged \(element.tag.hex), which CoreEntitlements has no type for")
        }
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
}
