import Foundation

extension FileManager {
    /**
     Returns the inode (file system file number) for the item at the given path, or `nil` on failure.
     */
    func inode(atPath path: String) -> UInt64? {
        guard let attrs = try? attributesOfItem(atPath: path) else {
            return nil
        }
        return attrs[.systemFileNumber] as? UInt64
    }

    /**
     Returns the device identifier and inode for the item at the given path, or `nil` on failure.
     */
    func deviceInode(atPath path: String) -> (device: UInt64, inode: UInt64)? {
        guard
            let itemAttrs = try? attributesOfItem(atPath: path),
            let ino = itemAttrs[.systemFileNumber] as? UInt64,
            let fsAttrs = try? attributesOfFileSystem(forPath: path),
            let dev = fsAttrs[.systemNumber] as? UInt64
        else {
            return nil
        }

        return (dev, ino)
    }
}

// MARK: -

extension Sequence<UInt8> {
    var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}

// MARK: -

extension URL {
    /**
     Appends a path component to the URL using the `/` operator.

     If the component contains a query string (indicated by `?`) and the URL is not a file URL, the path and query portions are handled separately to avoid percent-encoding.

     - Parameters:
        - url: The base URL.
        - component: The path component to append, optionally including a query string.
     - Returns: A new URL with the path component appended.
     */
    static func / (url: URL, component: String) -> URL {
        if !url.isFileURL, let queryIndex = component.firstIndex(of: "?") {
            let path = String(component[..<queryIndex])
            let query = String(component[component.index(after: queryIndex)...])

            guard var components = URLComponents(url: url, resolvingAgainstBaseURL: true) else {
                return self.fallbackAppend(url: url, component: component)
            }

            components.path += path.hasPrefix("/") ? path : "/\(path)"
            components.query = query

            return components.url ?? self.fallbackAppend(url: url, component: component)
        }

        return self.fallbackAppend(url: url, component: component)
    }

    private static func fallbackAppend(url: URL, component: String) -> URL {
        if #available(macOS 13.0, *) {
            url.appending(path: component)
        } else {
            url.appendingPathComponent(component)
        }
    }
}
