@testable import fashion
import Foundation

/**
 `Universal.open` and what the scan reads from a `MachO`: the fat architecture table, the header and load-command
 table, every command an accessor loads, and the logical end of each ending.
 */
@_cdecl("LLVMFuzzerTestOneInput")
public func fuzzMachO(_ start: UnsafeRawPointer, _ count: Int) -> CInt {
    guard let file = Fuzz.file(start, count) else {
        return 0
    }

    do {
        switch try Universal.open(file) {
        case let .thin(image):
            exercise(image)
        case let .fat(archs):
            for arch in archs {
                _ = arch.name
                if let image = try? MachO(file, offset: arch.offset, length: arch.length) {
                    exercise(image)
                }
                _ = try? MachO(lenient: file, offset: arch.offset, length: arch.length)?.logicalEnd()
            }
        case .notMachO:
            break
        }
    } catch {}
    _ = try? Universal.fileEnd(file)
    _ = try? MachO(lenient: file)?.logicalEnd()

    return 0
}

private func exercise(_ image: MachO) {
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
