@testable import fashion
import Foundation

/**
 What every harness shares: the fuzzer's bytes as the `File` a scan opens, and as `Data`, and the walk of a Mach-O the
 scan reads.

 `File` reads a path, not memory, but an edit of one is read from memory: each input is a `File` of one piece, its
 bytes, editing a scratch file opened once per process, so that it is read at its offsets like any file the walk finds
 without going through the file system. Written over the scratch file and opened from there for every input, the way a
 test opens a fixture (`File(data:)` in TestHelpers), the kernel took two thirds of a worker's time, the file's size
 changed and its pages written, read uncached and dropped each time, and the workers of every binary at once spent
 most of theirs waiting on it.
 */
enum Fuzz {
    private static let path = NSTemporaryDirectory() + "fashion-fuzz-\(getpid())"

    /// The scratch file every input's `File` edits, created empty once and removed when the fuzzer exits; never read,
    /// since an input is all bytes.
    private nonisolated(unsafe) static let base: File = {
        let fd = open(path, O_RDONLY | O_CREAT, 0o600)
        precondition(fd >= 0, "cannot create \(path): \(String(cString: strerror(errno)))")
        close(fd)
        atexit { unlink(Fuzz.path) }
        return try! File(path: path)
    }()

    /// The input as a file, in memory.
    static func file(_ start: UnsafeRawPointer, _ count: Int) -> File {
        File(editing: self.base, pieces: [.bytes(self.data(start, count))])
    }

    /// The input in memory.
    static func data(_ start: UnsafeRawPointer, _ count: Int) -> Data {
        Data(bytes: start, count: count)
    }

    /// `Universal.open` on `file`, then what the scan reads from each image it holds.
    static func walk(_ file: File) {
        do {
            switch try Universal.open(file) {
            case let .thin(image):
                self.exercise(image)
            case let .fat(archs):
                for arch in archs {
                    _ = arch.name
                    if let image = try? MachO(file, offset: arch.offset, length: arch.length) {
                        self.exercise(image)
                    }
                    _ = try? MachO(lenient: file, offset: arch.offset, length: arch.length)?.logicalEnd()
                }
            case .notMachO:
                break
            }
        } catch {}
    }

    /// Every accessor the scan reads from a `MachO`, and the logical end of each ending. What `verify` names of the
    /// image is the `verify` harness's.
    static func exercise(_ image: MachO) {
        _ = image.logicalEnd()
        _ = image.filetypeName
        _ = try? image.findCodeSignature()
        _ = try? image.version()
        _ = try? image.findSegment("__TEXT")
        _ = try? image.findSegment("__LINKEDIT")
        for command in image.loadCommands {
            _ = command.isSegment(named: "__TEXT")
            _ = try? SymHash.parseSymtab(command: command, swap: image.swap)
        }
    }
}
