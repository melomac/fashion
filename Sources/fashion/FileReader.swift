import Foundation
import System

/**
 Centralized file reading. Every hash and parser path goes through here, so I/O tuning
 (chunk size, uncached reads, mmap strategy) lives in exactly one place.

 - `read`/`head`/`size` use an uncached descriptor (`F_NOCACHE`) for sequential hashing and cheap
   header peeks, so scanning large trees does not pollute the unified buffer cache.
 - `map` lazily memory-maps a file for random-access parsing (load commands, symbol tables, archive
   tables of contents), where only the touched pages fault in.
 */
enum FileReader {
    /// Streaming chunk size (1 MiB).
    static let chunkSize = 1 << 20

    /**
     Stream a file through `consume` in uncached chunks, stopping after `limit` bytes when set.

     Throws on an open or read failure.
     */
    static func read(path: String, limit: Int? = nil, _ consume: (UnsafeRawBufferPointer) -> Void) throws {
        let fd = try FileDescriptor.open(path, .readOnly)
        defer {
            try? fd.close()
        }
        _ = fcntl(fd.rawValue, F_NOCACHE, 1)

        let buffer = UnsafeMutableRawBufferPointer.allocate(byteCount: self.chunkSize, alignment: 1)
        defer {
            buffer.deallocate()
        }

        var remaining = limit ?? Int.max
        while remaining > 0 {
            let want = Swift.min(self.chunkSize, remaining)
            let bytesRead = try fd.read(into: UnsafeMutableRawBufferPointer(rebasing: buffer[..<want]))
            if bytesRead == 0 {
                break
            }
            consume(UnsafeRawBufferPointer(rebasing: buffer[..<bytesRead]))
            remaining -= bytesRead
        }
    }

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
     File size in bytes, following symlinks via the opened descriptor.

     Throws on an open/stat failure.
     */
    static func size(path: String) throws -> Int {
        let fd = try FileDescriptor.open(path, .readOnly)
        defer {
            try? fd.close()
        }

        var info = stat()
        guard fstat(fd.rawValue, &info) == 0 else {
            throw Errno(rawValue: errno)
        }

        return Int(info.st_size)
    }

    /**
     Lazily memory-map a file for random-access parsing (only touched pages fault).

     Throws on failure.
     */
    static func map(path: String) throws -> Data {
        do {
            return try Data(contentsOf: URL(fileURLWithPath: path), options: .mappedIfSafe)
        } catch {
            throw self.posixError(error)
        }
    }

    /**
     The POSIX failure behind a Foundation file error, so every reader and writer describes an I/O error
     the same way and no file name is echoed inside the message. Any other error is returned unchanged.
     */
    static func posixError(_ error: Error) -> Error {
        guard
            let underlying = (error as NSError).userInfo[NSUnderlyingErrorKey] as? NSError,
            underlying.domain == NSPOSIXErrorDomain
        else {
            return error
        }
        return Errno(rawValue: Int32(underlying.code))
    }
}
