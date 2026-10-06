import Foundation
import System

enum FileError: Error, Equatable {
    case sizeChanged(expected: Int, actual: Int)
}

extension FileError: LocalizedError {
    var errorDescription: String? {
        switch self {
        case let .sizeChanged(expected, actual):
            "File changed size while hashing (expected \(String(expected, pluralizing: "byte")), read \(actual))"
        }
    }
}

/**
 A file opened once for everything a scan reads from it, like the `FileDesc` Security's `Universal`, `MachO` and
 `CodeDirectory::Builder` share: headers and tables are read at their offset, and long ranges are streamed in chunks.

 Nothing is mapped: a mapping faults on a bad block of a damaged disk image, which kills the process, and Foundation
 reads a whole file into memory rather than map it from such a volume. A read fails for that one file instead.
 Reads are uncached (`F_NOCACHE`), so scanning large trees does not pollute the unified buffer cache.
 */
final class File {
    /// Streaming chunk size (1 MiB).
    static let chunkSize = 1 << 20

    /// The size when the file was opened: every range read from it is checked against this size.
    let size: Int
    private let fd: FileDescriptor

    init(path: String) throws {
        let fd = try FileDescriptor.open(path, .readOnly)
        var info = stat()
        guard fstat(fd.rawValue, &info) == 0 else {
            let error = Errno(rawValue: errno)
            try? fd.close()
            throw error
        }
        _ = fcntl(fd.rawValue, F_NOCACHE, 1)

        self.fd = fd
        self.size = Int(info.st_size)
    }

    deinit {
        try? self.fd.close()
    }

    /**
     The `count` bytes at `offset`, which the caller has checked against `size`. Throws when the file no longer holds them.
     */
    func read(at offset: Int, count: Int) throws -> Data {
        // Anything above a page is mapped from the kernel, like the stream buffer: freed, it goes back at once.
        var data = if count > Int(getpagesize()) {
            try Self.mapped(count)
        } else {
            Data(count: count)
        }
        let filled = try data.withUnsafeMutableBytes { buffer in
            try self.read(at: offset, into: buffer)
        }
        guard filled == count else {
            throw FileError.sizeChanged(expected: count, actual: filled)
        }
        return data
    }

    /**
     Stream `range` through `consume` in chunks, the way Security's `CodeDirectory::Builder` reads the code of one
     architecture from the descriptor at its offset. Returns the count read, short of the range only when the file ends
     first.
     */
    func stream(_ range: Range<Int>, _ consume: (UnsafeRawBufferPointer) throws -> Void) throws -> Int {
        // The buffer is mapped from the kernel rather than taken from malloc: hash threads freeing a 1 MiB block per
        // file left about 100 MiB of emptied malloc regions resident, while unmapping returns the pages at once, and a
        // short file only touches the pages it fills.
        guard
            let base = mmap(nil, Self.chunkSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0),
            base != MAP_FAILED
        else {
            throw Errno(rawValue: errno)
        }
        defer {
            munmap(base, Self.chunkSize)
        }
        let buffer = UnsafeMutableRawBufferPointer(start: base, count: Self.chunkSize)

        var offset = range.lowerBound
        while offset < range.upperBound {
            let filled = try self.read(at: offset, into: UnsafeMutableRawBufferPointer(rebasing: buffer[..<min(Self.chunkSize, range.upperBound - offset)]))
            if filled == 0 {
                break
            }
            try consume(UnsafeRawBufferPointer(rebasing: buffer[..<filled]))
            offset += filled
        }
        return offset - range.lowerBound
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

    // MARK: - Private

    /**
     `count` zeroed bytes mapped from the kernel, unmapped when the data is released.
     */
    private static func mapped(_ count: Int) throws -> Data {
        guard
            let base = mmap(nil, count, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0),
            base != MAP_FAILED
        else {
            throw Errno(rawValue: errno)
        }
        return Data(bytesNoCopy: base, count: count, deallocator: .unmap)
    }

    /**
     Fill `buffer` from `offset`: a single `pread` may return fewer bytes than asked (on a network file system, say), so
     read until the buffer is full or the file ends. Returns the count read.
     */
    private func read(at offset: Int, into buffer: UnsafeMutableRawBufferPointer) throws -> Int {
        var filled = 0
        while filled < buffer.count {
            let count = try self.fd.read(fromAbsoluteOffset: Int64(offset + filled), into: UnsafeMutableRawBufferPointer(rebasing: buffer[filled...]))
            if count == 0 {
                break
            }
            filled += count
        }
        return filled
    }
}
