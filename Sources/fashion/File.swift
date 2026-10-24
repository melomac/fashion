import Foundation
import System

enum FileError: Error, Equatable {
    /// A read came up short: the file is `now` bytes long, `opened` when it was opened.
    case sizeChanged(opened: Int, now: Int)
    /// A read came up short, and the path names another file now, or none.
    case replaced
    case notRegularFile
}

extension FileError: LocalizedError {
    var errorDescription: String? {
        switch self {
        case let .sizeChanged(opened, now):
            "File changed size while hashing (\(String(opened, pluralizing: "byte")) when opened, \(now) now)"
        case .replaced:
            "File replaced while hashing"
        case .notRegularFile:
            "Not a regular file"
        }
    }
}

/**
 A file opened once for everything a scan reads from it, like the `FileDesc` Security's `Universal`, `MachO` and
 `CodeDirectory::Builder` share: headers and tables are read at their offset, and long ranges are streamed in chunks.

 Nothing is mapped: a mapping faults on a bad block of a damaged disk image, which kills the process, and Foundation
 reads a whole file into memory rather than map it from such a volume. A read fails for that one file instead.
 Reads are uncached (`F_NOCACHE`), so scanning large trees does not pollute the unified buffer cache.

 A file can also be an edit of another, made in memory (`init(editing:pieces:)`), which reads like the file it edits.
 */
final class File {
    /// Streaming chunk size (1 MiB).
    static let chunkSize = 1 << 20

    /// A part of an edited file: bytes in memory, or a range of the file it edits.
    enum Piece {
        case bytes(Data)
        case range(Range<Int>)

        var count: Int {
            switch self {
            case let .bytes(data): data.count
            case let .range(range): range.count
            }
        }
    }

    /// The size when the file was opened: every range read from it is checked against this size.
    let size: Int
    private let path: String
    private let fd: FileDescriptor
    /// The device and inode opened, which the path may no longer name by the time a read comes up short.
    private let identity: (dev_t, ino_t)
    /// The file an edit reads from, and its bytes in order; nil for a file as it is on disk.
    private let edit: (base: File, pieces: [Piece])?

    /**
     Open the regular file at `path`. The walk found one there, but the path may name something else by the time it is
     opened: it is opened without blocking, so a FIFO put in its place cannot hang the scan in open(2), and anything but
     a regular file is refused before it is read.
     */
    init(path: String) throws {
        let fd = try FileDescriptor.open(path, .readOnly, options: .nonBlocking)
        var info = stat()
        guard fstat(fd.rawValue, &info) == 0 else {
            let error = Errno(rawValue: errno)
            try? fd.close()
            throw error
        }
        guard info.st_mode & S_IFMT == S_IFREG else {
            try? fd.close()
            throw FileError.notRegularFile
        }
        // A regular file: its reads block as usual.
        _ = fcntl(fd.rawValue, F_SETFL, 0)
        _ = fcntl(fd.rawValue, F_NOCACHE, 1)

        self.path = path
        self.fd = fd
        self.size = Int(info.st_size)
        self.identity = (info.st_dev, info.st_ino)
        self.edit = nil
    }

    /**
     The file `pieces` make, in order: an edit of `base`, built in memory like the copy Security's `MachOEditor` makes
     before it writes one, where the bytes it keeps are read from `base` when they are asked for rather than copied.
     */
    init(editing base: File, pieces: [Piece]) {
        self.path = base.path
        self.fd = base.fd
        self.size = pieces.reduce(0) { $0 + $1.count }
        self.identity = base.identity
        self.edit = (base, pieces)
    }

    deinit {
        // An edit reads through the descriptor of the file it edits, which closes it.
        if self.edit == nil {
            try? self.fd.close()
        }
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
            throw self.shortRead()
        }
        return data
    }

    /**
     Stream `range` through `consume` in chunks, the way Security's `CodeDirectory::Builder` reads the code of one
     architecture from the descriptor at its offset. Throws when the file no longer holds the range.
     */
    func stream(_ range: Range<Int>, _ consume: (UnsafeRawBufferPointer) throws -> Void) throws {
        var chunk = try Self.mapped(Self.chunkSize)
        try chunk.withUnsafeMutableBytes { buffer in
            var offset = range.lowerBound
            while offset < range.upperBound {
                let count = min(Self.chunkSize, range.upperBound - offset)
                guard try self.read(at: offset, into: UnsafeMutableRawBufferPointer(rebasing: buffer[..<count])) == count else {
                    throw self.shortRead()
                }
                try consume(UnsafeRawBufferPointer(rebasing: buffer[..<count]))
                offset += count
            }
        }
    }

    /**
     How a diagnostic describes an error: an I/O error as `strerror` says it, like a walk error, without the
     "The operation couldn't be completed." that `Errno`'s own `localizedDescription` puts before it; any other error
     by its own description.
     */
    static func message(for error: Error) -> String {
        (error as? Errno)?.description ?? error.localizedDescription
    }

    // MARK: - Private

    /**
     `count` zeroed bytes mapped from the kernel rather than taken from malloc, unmapped when the data is released:
     freed, the pages go back at once, where emptied malloc regions stay resident across the hash threads, and a short
     file only touches the pages it fills.
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
     The error for a read that came up short of the size the file had when it was opened: the path has been replaced
     (it names another file now, or none), or the file itself changed size.
     */
    private func shortRead() -> FileError {
        if let base = self.edit?.base {
            return base.shortRead()
        }
        var now = stat()
        guard stat(self.path, &now) == 0, (now.st_dev, now.st_ino) == self.identity else {
            return .replaced
        }
        return .sizeChanged(opened: self.size, now: Int(now.st_size))
    }

    /**
     Fill `buffer` from `offset`: a single `pread` may return fewer bytes than asked (on a network file system, say), so
     read until the buffer is full or the file ends. Returns the count read.
     */
    private func read(at offset: Int, into buffer: UnsafeMutableRawBufferPointer) throws -> Int {
        if let (base, pieces) = self.edit {
            return try Self.read(pieces, of: base, at: offset, into: buffer)
        }
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

    /**
     Fill `buffer` from `offset` in the file `pieces` make, each from memory or from `base`, until the buffer is full,
     the pieces end, or `base` comes up short. Returns the count read.
     */
    private static func read(_ pieces: [Piece], of base: File, at offset: Int, into buffer: UnsafeMutableRawBufferPointer) throws -> Int {
        var filled = 0
        var start = 0
        for piece in pieces where filled < buffer.count {
            defer {
                start += piece.count
            }
            let skip = offset + filled - start
            guard skip < piece.count else {
                continue
            }
            let count = min(piece.count - skip, buffer.count - filled)
            let target = UnsafeMutableRawBufferPointer(rebasing: buffer[filled ..< filled + count])
            switch piece {
            case let .bytes(data):
                data.copyBytes(to: target, from: data.startIndex + skip ..< data.startIndex + skip + count)
            case let .range(range):
                let read = try base.read(at: range.lowerBound + skip, into: target)
                guard read == count else {
                    return filled + read
                }
            }
            filled += count
        }
        return filled
    }
}
