import CryptoKit
import Foundation
import Security

/**
 Who signed a code directory, as Security verifies it and Gatekeeper classes it. `SecStaticCode::verifySignature`
 decodes the CMS blob with the code directory as its detached content, checks the signature, and builds the signer's
 certificate chain with no anchors of its own: a self-signed certificate anchors itself, and an expired one still
 verifies, so `codesign --verify` passes code the kernel runs and Gatekeeper refuses. Gatekeeper's `PolicyScanner`
 (syspolicyd) then asks who the signer is, with requirements over the chain: Apple itself (`anchor apple`: the Apple
 root, the Apple Code Signing CA, a leaf with the Software Signing marker), the Mac App Store, Developer ID with a
 ticket or from before notarization (`legacy`), TestFlight. AMFI (`AMFIPathValidator`, libmis) accepts those and the
 development certificates too, and reserves most entitlements to Apple's signature or a provisioning profile.

 `anchoredAtApple` is `anchor apple generic`; `kind` is which of Gatekeeper's requirements the chain meets.
 */
struct Signer {
    /// What `SecStaticCode::verifySignature` throws `errSecCSSignatureFailed` for.
    enum Failure: Error {
        /// The CMS blob does not decode.
        case undecodable
        /// The CMS blob carries no signer.
        case unsigned
        /// The signature does not verify over the code directory.
        case invalidSignature
        /// The signer's certificate chain does not build or verify, in trustd's words.
        case chain(String)
    }

    /// Which of Gatekeeper's requirements the chain meets.
    enum Kind {
        /// `anchor apple`: Apple's own software.
        case apple
        /// The Mac App Store, iOS App Store or TestFlight leaf.
        case appStore
        /// A Developer ID leaf under the Developer ID CA.
        case developerID
        /// A development or distribution leaf AMFI accepts and Gatekeeper has no requirement for.
        case development
        /// An Apple-issued leaf for something other than code.
        case otherApple
        /// A chain that does not end at an Apple root.
        case outsideApple
    }

    /// The chain trustd built: the leaf first, the anchor last.
    let chain: [SecCertificate]
    /// The signing time the signer claims, from the CMS attributes.
    let signingTime: Date?
    /// The secure timestamp a timestamp authority certified.
    let timestamp: Date?
    private let leafFields: Set<String>
    private let issuerFields: Set<String>

    /// SHA-256 of Apple Root CA, Apple Root CA - G2 and Apple Root CA - G3, which `anchor apple generic` names.
    private static let appleRoots: Set<String> = [
        "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024",
        "c2b9b042dd57830e7d117dac55ac8ae19407d38e41d88f3215bc3a890444a050",
        "63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179",
    ]

    // The certificate extensions Apple marks its leaves and CAs with (`certificate leaf[field.…] exists`).
    private static let softwareSigning = "1.2.840.113635.100.6.22"
    private static let appleCodeSigningCA = "Apple Code Signing Certification Authority"
    private static let appStoreLeaves = ["1.2.840.113635.100.6.1.9", "1.2.840.113635.100.6.1.9.1", "1.2.840.113635.100.6.1.3", "1.2.840.113635.100.6.1.25.1"]
    private static let developerIDLeaf = "1.2.840.113635.100.6.1.13"
    private static let developerIDCA = "1.2.840.113635.100.6.2.6"
    private static let developerIDDate = "1.2.840.113635.100.6.1.33"
    private static let developmentLeaves = ["1.2.840.113635.100.6.1.12", "1.2.840.113635.100.6.1.2", "1.2.840.113635.100.6.1.7", "1.2.840.113635.100.6.1.4"]

    /// Developer ID accounts created on or after this day (`legacydevid.cpp`) must notarize.
    private static let accountCutOff = "20190407"
    /// Developer ID signatures timestamped on or after this day must have a ticket: June 1, 2019 GMT.
    private static let timestampCutOff = Date(timeIntervalSinceReferenceDate: 581_040_000)

    /**
     Verifies `cms` over `directory` as `SecStaticCode::verifySignature` does: the decoder takes the directory as the
     detached content and the Apple code-signing policy, trustd builds the chain with no network, every self-signed
     certificate an anchor and expiry allowed, as the date the signer claims. Throws a `Failure` otherwise.
     */
    init(cms: Data, over directory: Data) throws(Failure) {
        var created: CMSDecoder?
        guard CMSDecoderCreate(&created) == errSecSuccess, let decoder = created,
              cms.withUnsafeBytes({ $0.baseAddress.map { CMSDecoderUpdateMessage(decoder, $0, cms.count) } ?? errSecParam }) == errSecSuccess,
              CMSDecoderSetDetachedContent(decoder, directory as CFData) == errSecSuccess,
              CMSDecoderFinalizeMessage(decoder) == errSecSuccess
        else {
            throw .undecodable
        }
        var signers = 0
        guard CMSDecoderGetNumSigners(decoder, &signers) == errSecSuccess, signers > 0 else {
            throw .unsigned
        }

        var status = CMSSignerStatus.unsigned
        var built: SecTrust?
        guard
            let policy = SecPolicyCreateWithProperties(kSecPolicyAppleCodeSigning, nil),
            CMSDecoderCopySignerStatus(decoder, 0, [policy] as CFArray, false, &status, &built, nil) == errSecSuccess
        else {
            throw .undecodable
        }
        guard status == .valid, let trust = built else {
            throw status == .invalidSignature ? .invalidSignature : .unsigned
        }

        var time: CFAbsoluteTime = 0
        self.signingTime = CMSDecoderCopySignerSigningTime(decoder, 0, &time) == errSecSuccess ? Date(timeIntervalSinceReferenceDate: time) : nil
        self.timestamp = CMSDecoderCopySignerTimestampWithPolicy(decoder, nil, 0, &time) == errSecSuccess ? Date(timeIntervalSinceReferenceDate: time) : nil

        SecTrustSetNetworkFetchAllowed(trust, false)
        SecTrustSetOptions(trust, [.allowExpired, .allowExpiredRoot, .implicitAnchors])
        if let date = self.timestamp ?? self.signingTime {
            SecTrustSetVerifyDate(trust, date as CFDate)
        }
        var error: CFError?
        guard SecTrustEvaluateWithError(trust, &error) else {
            throw .chain(error.map { ($0 as Error).localizedDescription } ?? "not trusted")
        }
        self.chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate] ?? []
        self.leafFields = Self.fields(of: self.chain.first)
        self.issuerFields = Self.fields(of: self.chain.dropFirst().first)
    }

    /// The leaf's subject summary, its common name for the certificates Apple issues.
    var summary: String {
        self.chain.first.flatMap { SecCertificateCopySubjectSummary($0) as String? } ?? "an unnamed certificate"
    }

    /// Whether the chain ends at one of Apple's roots: `anchor apple generic`.
    var anchoredAtApple: Bool {
        guard let anchor = self.chain.last else {
            return false
        }
        return Self.appleRoots.contains(Data(SHA256.hash(data: SecCertificateCopyData(anchor) as Data)).hexString)
    }

    var kind: Kind {
        guard self.anchoredAtApple else {
            return .outsideApple
        }
        if self.leafFields.contains(Self.softwareSigning), self.chain.count > 1, SecCertificateCopySubjectSummary(self.chain[1]) as String? == Self.appleCodeSigningCA {
            return .apple
        }
        if Self.appStoreLeaves.contains(where: self.leafFields.contains) {
            return .appStore
        }
        if self.leafFields.contains(Self.developerIDLeaf), self.issuerFields.contains(Self.developerIDCA) {
            return .developerID
        }
        if Self.developmentLeaves.contains(where: self.leafFields.contains) {
            return .development
        }
        return .otherApple
    }

    /// The leaf's organizational unit, the team identifier of the certificates Apple issues to developers.
    var teamID: String? {
        guard let leaf = self.chain.first, let values = SecCertificateCopyValues(leaf, [kSecOIDX509V1SubjectName] as CFArray, nil) as? [String: Any] else {
            return nil
        }
        let subject = (values[kSecOIDX509V1SubjectName as String] as? [String: Any])?[kSecPropertyKeyValue as String] as? [[String: Any]]
        return subject?.first { $0[kSecPropertyKeyLabel as String] as? String == "2.5.4.11" }?[kSecPropertyKeyValue as String] as? String
    }

    /**
     Whether a Developer ID signature meets Gatekeeper's `legacy` requirement (`meetsDeveloperIDLegacyAllowedPolicy`),
     which runs it without a ticket: the account was created before the cut-off, where the leaf says when, and a
     timestamp authority certified the signature before the other. The allow lists by hash and team are not consulted.
     */
    var isLegacyDeveloperID: Bool {
        guard self.kind == .developerID, let timestamp, timestamp < Self.timestampCutOff else {
            return false
        }
        if let created = self.developerIDDate, String(created.prefix(8)) >= Self.accountCutOff {
            return false
        }
        return true
    }

    /// When the Developer ID account was created, `YYYYMMDDHHMMSSZ` from the leaf's extension, nil when it has none.
    private var developerIDDate: String? {
        guard
            let leaf = self.chain.first,
            let values = SecCertificateCopyValues(leaf, [Self.developerIDDate] as CFArray, nil) as? [String: Any],
            let entries = (values[Self.developerIDDate] as? [String: Any])?[kSecPropertyKeyValue as String] as? [[String: Any]],
            let raw = entries.compactMap({ $0[kSecPropertyKeyValue as String] as? Data }).first,
            raw.count > 2
        else {
            return nil
        }
        // A DER string: its tag, its length, then the digits.
        return String(decoding: raw.dropFirst(2), as: UTF8.self)
    }

    /// The OIDs of a certificate's fields and extensions, which Apple's markers are among.
    private static func fields(of certificate: SecCertificate?) -> Set<String> {
        guard let certificate, let values = SecCertificateCopyValues(certificate, nil, nil) as? [String: Any] else {
            return []
        }
        return Set(values.keys)
    }
}
