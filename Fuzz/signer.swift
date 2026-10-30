@testable import fashion
import Foundation

/**
 `Signer` over an embedded signature's superblob, as `LC_CODE_SIGNATURE` points at one: the superblob checked as
 `signingData` checks it, its code directories loaded, then the CMS blob decoded and verified over the primary
 directory through Security's decoder, and the chain built by trustd and read for who signed, with certificates the
 fuzzer rewrote, which the CMS signature does not cover. A superblob without a CMS blob, or with none Security loads a
 directory from, ends there, as `verify` ends there.
 */
@_cdecl("LLVMFuzzerTestOneInput")
public func fuzzSigner(_ start: UnsafeRawPointer, _ count: Int) -> CInt {
    let data = Fuzz.data(start, count)
    func word(at offset: Int) -> UInt32 {
        data.withUnsafeBytes { UInt32(bigEndian: $0.loadUnaligned(fromByteOffset: offset, as: UInt32.self)) }
    }
    guard count >= 12, word(at: 0) == 0xfade_0cc0 else {
        return 0
    }
    let length = Int(word(at: 4))
    guard length >= 12, length <= count else {
        return 0
    }
    let superblob = data.prefix(length)
    guard
        (try? MachO.checkIndex(of: superblob)) != nil,
        let primary = (try? MachO.loadCodeDirectories(superblob))?.first,
        let cms = MachO.component(0x10000, of: superblob), cms.count > 8
    else {
        return 0
    }
    if let signer = try? Signer(cms: Data(cms.dropFirst(8)), over: primary.data) {
        _ = signer.kind
        _ = signer.summary
        _ = signer.teamID
        _ = signer.isLegacyDeveloperID
    }
    return 0
}
