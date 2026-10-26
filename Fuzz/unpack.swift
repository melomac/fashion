@testable import fashion
import Foundation

/**
 `MachOEditor.edit` with `--unpack`: UPX's pack header looked for in each image and checked, the packed data decompressed
 by UCL or liblzma and unfiltered, a signature removed before and after or left on the unpacked image, and a universal
 file laid out again, whole and `--exact`. The edit is then read as the scan reads it: streamed whole, walked as a
 Mach-O, its cdhashes and symhashes taken, each read crossing the pieces it is made of, in memory and on disk.
 */
@_cdecl("LLVMFuzzerTestOneInput")
public func fuzzUnpack(_ start: UnsafeRawPointer, _ count: Int) -> CInt {
    guard let file = Fuzz.file(start, count) else {
        return 0
    }

    for exact in [false, true] {
        for unsign in [true, false] {
            guard let edit = try? MachOEditor.edit(file, exact: exact, unsign: unsign, unpack: true) else {
                continue
            }
            try? edit.file.stream(0 ..< edit.file.size) { _ in }
            Fuzz.walk(edit.file)
            _ = try? CDHash.hash(edit.file, path: "input", exact: exact)
            _ = try? SymHash.compute(edit.file, algorithms: [.sha256], separator: ",", sortSymbols: true)
        }
    }
    return 0
}
