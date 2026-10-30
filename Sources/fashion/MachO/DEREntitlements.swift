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
        var outer = DER.Reader(der)
        guard let wrapper = outer.next(), wrapper.tag == 0x70, outer.atEnd else {
            return nil
        }
        var inner = DER.Reader(wrapper.content)
        guard
            let version = inner.next(), version.tag == 0x02, Self.integer(version.content) == 1,
            let root = inner.next(), inner.atEnd
        else {
            return nil
        }
        return Self.value(of: root) as? [String: Any]
    }

    // MARK: - Private

    /// The value `element` holds, as a property list holds it, `depth` levels down; nil for a tag or content a plist
    /// has no value for, or a value nested past `DER.maxDepth`.
    private static func value(of element: DER.Element, depth: Int = 0) -> Any? {
        guard depth < DER.maxDepth else {
            return nil
        }
        return switch element.tag {
        case 0x01: // BOOLEAN
            element.content.count == 1 ? element.content.first != 0 : nil
        case 0x02: // INTEGER
            self.integer(element.content)
        case 0x04: // OCTET STRING
            Data(element.content)
        case 0x0c: // UTF8String
            String(data: element.content, encoding: .utf8)
        case 0x18: // GeneralizedTime
            DER.generalizedTime(element.content)
        case 0x30: // SEQUENCE: an array
            DER.elements(of: element.content).flatMap { elements in
                let values = elements.compactMap { Self.value(of: $0, depth: depth + 1) }
                return values.count == elements.count ? values : nil
            }
        case 0xb0, 0x31: // a dictionary of SEQUENCE pairs: context tag 16, constructed, as CoreFoundation writes it, or a SET
            DER.elements(of: element.content).flatMap { pairs in
                var dictionary: [String: Any] = [:]
                for pair in pairs {
                    guard
                        pair.tag == 0x30,
                        let entry = DER.elements(of: pair.content), entry.count == 2,
                        entry[0].tag == 0x0c, let key = String(data: entry[0].content, encoding: .utf8),
                        let value = Self.value(of: entry[1], depth: depth + 1),
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
