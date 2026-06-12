import Foundation

extension Sequence<UInt8> {
    var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
