/** Hash algorithm enumeration with parsing and aliases. */
enum Algorithm: String, CaseIterable {
    case md5
    case sha1
    case sha224
    case sha256
    case sha384
    case sha512
    case git
    case git256
    case ssdeep
    case tlsh
    case cdhash

    var isFuzzy: Bool {
        [.ssdeep, .tlsh].contains(self)
    }

    /**
     Parse an algorithm name with alias support.
     */
    static func parse(_ name: String) -> Algorithm? {
        let lower = name.lowercased()
        if lower == "sha2" {
            return .sha256
        }
        return Algorithm(rawValue: lower)
    }
}
