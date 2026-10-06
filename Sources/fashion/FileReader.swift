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
     Open a file for uncached reading.
     */
    static func open(path: String) throws -> FileDescriptor {
        let fd = try FileDescriptor.open(path, .readOnly)
        _ = fcntl(fd.rawValue, F_NOCACHE, 1)
        return fd
    }

    /**
     The size of an open file, in bytes.
     */
    static func size(_ fd: FileDescriptor) throws -> Int {
        var info = stat()
        guard fstat(fd.rawValue, &info) == 0 else {
            throw Errno(rawValue: errno)
        }
        return Int(info.st_size)
    }

    /**
     Stream `length` bytes of an open file from `offset` through `consume` in chunks, the way Security's
     `CodeDirectory::Builder` reads one architecture of a universal file from the descriptor at the slice's offset.
     Returns the count read, short of `length` only when the file ends first.

     Throws on a seek or read failure.
     */
    static func read(_ fd: FileDescriptor, offset: Int, length: Int, _ consume: (UnsafeRawBufferPointer) -> Void) throws -> Int {
        if offset > 0 {
            try fd.seek(offset: Int64(offset), from: .start)
        }

        // The buffer is mapped from the kernel rather than taken from malloc: hash threads freeing a 1 MiB block per
        // file left about 100 MiB of emptied malloc regions resident, while unmapping returns the pages at once, and a
        // short file only touches the pages it fills.
        guard
            let base = mmap(nil, self.chunkSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0),
            base != MAP_FAILED
        else {
            throw Errno(rawValue: errno)
        }
        defer {
            munmap(base, self.chunkSize)
        }
        let buffer = UnsafeMutableRawBufferPointer(start: base, count: self.chunkSize)

        var remaining = length
        while remaining > 0 {
            let want = Swift.min(self.chunkSize, remaining)
            let bytesRead = try fd.read(into: UnsafeMutableRawBufferPointer(rebasing: buffer[..<want]))
            if bytesRead == 0 {
                break
            }
            consume(UnsafeRawBufferPointer(rebasing: buffer[..<bytesRead]))
            remaining -= bytesRead
        }
        return length - remaining
    }

    /**
     Read up to `count` leading bytes, uncached — for cheap magic/header peeks without mapping the file.
     Returns fewer bytes only when the file is shorter.

     Throws on an open or read failure.
     */
    static func head(path: String, count: Int) throws -> [UInt8] {
        let fd = try self.open(path: path)
        defer {
            try? fd.close()
        }

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
