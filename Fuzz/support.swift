@testable import fashion
import Foundation

/**
 What every harness shares: the fuzzer's bytes as the `File` a scan opens, and as `Data`.

 `File` reads a path, not memory, so each input is written over one scratch file per process and opened from there,
 the way a test opens a fixture (`File(data:)` in TestHelpers), then read at its offsets like any file the walk finds.
 */
enum Fuzz {
    private static let path = NSTemporaryDirectory() + "fashion-fuzz-\(getpid())"

    /// The scratch file, created once and removed when the fuzzer exits.
    private static let scratch: Int32 = {
        let fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0o600)
        precondition(fd >= 0, "cannot create \(path): \(String(cString: strerror(errno)))")
        atexit { unlink(Fuzz.path) }
        return fd
    }()

    /// The input as a file, nil when the scratch file cannot hold it.
    static func file(_ start: UnsafeRawPointer, _ count: Int) -> File? {
        guard
            pwrite(self.scratch, start, count, 0) == count,
            ftruncate(self.scratch, off_t(count)) == 0
        else {
            return nil
        }
        return try? File(path: self.path)
    }

    /// The input in memory.
    static func data(_ start: UnsafeRawPointer, _ count: Int) -> Data {
        Data(bytes: start, count: count)
    }
}
