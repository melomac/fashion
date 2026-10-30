@testable import fashion
import Foundation

/**
 The DER readers over the input as it is: `DER.elements` over the bytes; the walk of a CMS signature to its first
 signer's signature and timestamp token, then the token decoded by Security and its chain built when there is one;
 the DER entitlements decoder; and a GeneralizedTime. The `signer` and `verify` harnesses reach the same readers
 behind a superblob or a whole Mach-O. The input is read on a thread with a 512 KiB stack, a sixteenth of the main
 thread's, so that a recursion shows within the inputs the fuzzer makes.
 */
@_cdecl("LLVMFuzzerTestOneInput")
public func fuzzDER(_ start: UnsafeRawPointer, _ count: Int) -> CInt {
    let data = Fuzz.data(start, count)
    Fuzz.onSmallStack {
        _ = DER.elements(of: data)
        _ = Signer.signatureAndToken(in: data)
        _ = Signer.timestamp(in: data)
        _ = DEREntitlements.decode(data)
        _ = DER.generalizedTime(data)
    }
    return 0
}
