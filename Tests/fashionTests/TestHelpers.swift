import Foundation

extension URL {
    /**
     Appends a path component using the `/` operator. Test convenience.
     */
    static func / (url: URL, component: String) -> URL {
        url.appending(path: component)
    }
}
