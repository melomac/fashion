@testable import fashion
import Foundation

/**
 What every harness shares: the fuzzer's bytes as the `File` a scan opens, and as `Data`, and the walk of a Mach-O the
 scan reads.

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

    /// Every accessor the scan reads from a `MachO`, and the logical end of each ending.
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
