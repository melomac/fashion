@testable import fashion
import Foundation

/**
 `MachOEditor.edit` with `--unpack`: UPX's pack header looked for in each image and checked, the packed data decompressed
 by UCL or LZMA and unfiltered, a signature removed before and after, and a universal file laid out again, whole and
 `--exact`; the edit is then read through.
 */
@_cdecl("LLVMFuzzerTestOneInput")
public func fuzzUnpack(_ start: UnsafeRawPointer, _ count: Int) -> CInt {
    guard let file = Fuzz.file(start, count) else {
        return 0
    }

    for exact in [false, true] {
        if let edit = try? MachOEditor.edit(file, exact: exact, unsign: true, unpack: true) {
            try? edit.file.stream(0 ..< edit.file.size) { _ in }
        }
    }
    return 0
}
