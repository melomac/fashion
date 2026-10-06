import Foundation
import System

/**
 Centralized file reading. Every hash and parser path goes through here, so I/O tuning
 (chunk size, uncached reads, mmap strategy) lives in exactly one place.

 - `open`/`read`/`head` use an uncached descriptor (`F_NOCACHE`) for sequential hashing and cheap
   header peeks, so scanning large trees does not pollute the unified buffer cache.
 - `map` lazily memory-maps a file for random-access parsing (load commands, symbol tables, archive
   tables of contents), where only the touched pages fault in.
 */
enum FileReader {
    /// Streaming chunk size (1 MiB).
    static let chunkSize = 1 << 20

    /**
     Read up to `count` leading bytes, uncached — for cheap magic/header peeks without mapping the file.
     Returns fewer bytes only when the file is shorter.

     Throws on an open or read failure.
     */
    static func head(path: String, count: Int) throws -> [UInt8] {
        let fd = try FileDescriptor.open(path, .readOnly)
        defer {
            try? fd.close()
        }
        _ = fcntl(fd.rawValue, F_NOCACHE, 1)

        // A single read(2) may return fewer bytes than requested (e.g. on network filesystems), so loop
        // until the buffer is filled or EOF; otherwise a short read could misclassify a Mach-O header.
        var bytes = [UInt8](repeating: 0, count: count)
        var filled = 0
        try bytes.withUnsafeMutableBytes { raw in
            while filled < count {
                let bytesRead = try fd.read(into: UnsafeMutableRawBufferPointer(rebasing: raw[filled...]))
                if bytesRead == 0 {
                    break
                }
                filled += bytesRead
            }
        }
        bytes.removeLast(count - filled)

        return bytes
    }

    /**
     Lazily memory-map a file for random-access parsing (only touched pages fault).

     Throws on failure.
     */
    static func map(path: String) throws -> Data {
        do {
            return try Data(contentsOf: URL(fileURLWithPath: path), options: .mappedIfSafe)
        } catch {
            throw File.posixError(error)
        }
    }
}
