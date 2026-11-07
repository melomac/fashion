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

 The CMS blob, DER, as `signerInfo(in:)` and `signatureAndToken(in:)` walk it, every value at its own length rather
 than at an offset:

 ```text
  ContentInfo { contentType id-signedData, [0] SignedData {
      version, digestAlgorithms,
      encapContentInfo { id-data }                        detached: the content is the code directory at slot 0
      [0] certificates                                    the chain as codesign embeds it, which the signature does not cover
      signerInfos SET { SignerInfo {
          version, sid { issuer, serialNumber }, digestAlgorithm,
          [0] signedAttrs SET {                           what the signature covers
              contentType, messageDigest,                 the digest of the code directory
              signingTime,
              1.2.840.113635.100.9.1,                     hash agility: the cdhashes plist
              1.2.840.113635.100.9.2 }                    hash agility v2: a cdhash per digest algorithm
          signatureAlgorithm, signature OCTET STRING,
          [1] unsignedAttrs SET {                         last, when there are any
              id-aa-timeStampToken: ContentInfo }         the timestamp authority's SignedData over the signature
      } }
  } }
 ```
 */
struct Signer {
    /// What `SecStaticCode::verifySignature` throws `errSecCSSignatureFailed` for.
    enum Failure: Error, Equatable {
        /// The CMS blob is not DER read to its end: what is wrong and where, as the reader met it.
        case malformed(String)
        /// The CMS blob does not decode.
        case undecodable
        /// The CMS blob carries no signer.
        case unsigned
        /// The CMS blob carries more signers than the one Security requires.
        case signers(Int)
        /// The signature does not verify over the code directory.
        case invalidSignature
        /// The signer's certificate chain does not build or verify, in trustd's words.
        case chain(String)
        /// The chain is expired or not yet valid at the date the signer claims, in trustd's words, which Security
        /// tolerates but for the directory's `CS_ENFORCE_EXPIRATION` flag.
        case expired(String)
        /// The signer's hash-agility attributes do not bind the code directories the signature holds: an invalid
        /// signature to Security.
        case agility(String)
        /// The secure timestamp's chain ends outside Apple's roots where the signer's ends at one, which Security
        /// refuses the signature for.
        case timestampChain
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
     detached content and the Apple code-signing policy, then the signer's hash-agility attributes must bind every
     directory the signature holds, `binding`, each with its full cdhash: the cdhashes plist lists their cdhashes
     truncated to 20 bytes, in the order of their hash types, and the v2 attribute names each by its digest
     algorithm with its cdhash, as many as there are directories, the `best` among them; a signer that wrote
     neither binds nothing, which Security lets pass. Then trustd builds the chain with no network, every
     self-signed certificate an anchor, as of the secure timestamp, else the date the signer claims: a chain expired
     or not yet valid then is tried again with expiry allowed, as Security tries it, only without a secure timestamp,
     and not when `enforcingExpiration`, the directory's `CS_ENFORCE_EXPIRATION` flag. A signer anchored at Apple
     whose secure timestamp's chain is not ends the verification too. Throws a `Failure` otherwise. An empty
     `binding` skips the attributes, for a caller with the one directory alone. Hash mode asks whether the signature
     holds and not who signed, so it passes `evaluatingChain` false: the signature and its bindings are checked, the
     chain and the timestamp, trustd's work, are not, and the signer comes back with no chain.
     */
    init(cms: Data, over directory: Data, binding: [Binding] = [], best: HashType? = nil, enforcingExpiration: Bool = false, evaluatingChain: Bool = true) throws(Failure) {
        // Read to its end first, every length within the bytes: Security's decoder checks a length against its
        // parent's only when the parent's is definite (sec_asn1d_check_and_subtract_length), and under an indefinite
        // one allocates what the length says and fills it, 680 MiB for a 4 KiB blob whose OID's length byte the
        // signer fuzz harness made long-form, the OID's own bytes then its length.
        if let fault = DER.fault(in: cms) {
            throw .malformed(fault)
        }
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
        // "CMS has %zu signers, expected exactly one": Security's verifySignature takes no other count.
        guard signers == 1 else {
            throw .signers(signers)
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
        if !binding.isEmpty {
            let bound = binding.sorted { $0.hashType.rawValue < $1.hashType.rawValue }
            let agility = Self.hashAgility(in: cms)
            if let cdhashes = agility.cdhashes, cdhashes != bound.map({ Data($0.cdhash.prefix(20)) }) {
                throw .agility("its cdhashes plist lists other code directories than the signature holds")
            }
            if let v2 = agility.v2 {
                guard v2.count == bound.count, bound.allSatisfy({ v2[$0.hashType] == $0.cdhash }), best.map({ v2[$0] != nil }) ?? true else {
                    throw .agility("its hash agility names other code directories than the signature holds")
                }
            }
        }

        var time: CFAbsoluteTime = 0
        self.signingTime = CMSDecoderCopySignerSigningTime(decoder, 0, &time) == errSecSuccess ? Date(timeIntervalSinceReferenceDate: time) : nil
        guard evaluatingChain else {
            self.timestamp = nil
            self.chain = []
            self.leafFields = []
            self.issuerFields = []
            return
        }
        let stamp = Self.timestamp(in: cms)
        self.timestamp = stamp?.date

        SecTrustSetNetworkFetchAllowed(trust, false)
        SecTrustSetOptions(trust, [.implicitAnchors])
        if let date = self.timestamp ?? self.signingTime {
            SecTrustSetVerifyDate(trust, date as CFDate)
        }
        var error: CFError?
        if !SecTrustEvaluateWithError(trust, &error) {
            // Security's validateDirectory tries again with expiry allowed when that is the failure and no secure
            // timestamp vouches for the date, then refuses what it allowed under CS_ENFORCE_EXPIRATION.
            let reason = error.map { ($0 as Error).localizedDescription } ?? "not trusted"
            guard let failure = error, Self.expiryCodes.contains(OSStatus(CFErrorGetCode(failure))), self.timestamp == nil else {
                throw .chain(reason)
            }
            guard !enforcingExpiration else {
                throw .expired(reason)
            }
            SecTrustSetOptions(trust, [.allowExpired, .allowExpiredRoot, .implicitAnchors])
            guard SecTrustEvaluateWithError(trust, &error) else {
                throw .chain(error.map { ($0 as Error).localizedDescription } ?? reason)
            }
        }
        self.chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate] ?? []
        self.leafFields = Self.fields(of: self.chain.first)
        self.issuerFields = Self.fields(of: self.chain.dropFirst().first)
        // A signer anchored at Apple needs its secure timestamp anchored at Apple too: "timestamp policy
        // verification failed", and the signature with it.
        if let stamp, self.anchoredAtApple, !(stamp.chain.last.map(Self.isAppleRoot) ?? false) {
            throw .timestampChain
        }
    }

    /// trustd's words for a chain expired or not yet valid, the failures Security tries again past.
    private static let expiryCodes: Set<OSStatus> = [errSecCertificateExpired, errSecCertificateNotValidYet]

    // MARK: - Timestamp

    /// The OIDs of the CMS signed-data content type, of the timestamp token attribute (`id-aa-timeStampToken`), and
    /// of the digests a token's imprint may be taken with.
    private static let signedDataType = Data([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02])
    private static let timeStampTokenType = Data([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x0e])
    private static let imprintDigests: [Data: HashType] = [
        Data([0x2b, 0x0e, 0x03, 0x02, 0x1a]): .sha1,
        Data([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]): .sha256,
        Data([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02]): .sha384,
        Data([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03]): .sha512,
    ]

    /**
     The secure timestamp in `cms`: the token a timestamp authority signed over the signer's signature, carried as an
     unsigned attribute of the signer. Its date and the chain trustd built, when the token's imprint is the
     signature's digest, its own
     signature verifies, and its chain builds under Apple's timestamping policy to the system's anchors, or to
     `anchors`, as of the date it certifies, with no network. Security's `CMSDecoderCopySignerTimestampWithPolicy`
     does as much through trustd, which may fetch an issuer over the network for the token's chain, where it fetches
     none for the signer's; this fetches none. The decoder digests no content of the token's type, `TSTInfo`, as it
     reads it, so the content is handed back to it as detached for the signer's digest. Nil without a token that
     holds.
     */
    static func timestamp(in cms: Data, anchors: [SecCertificate]? = nil) -> Timestamp? {
        // The token read to its end as the signer's blob is, before the decoder takes a length at its word.
        guard let stamped = signatureAndToken(in: cms), DER.fault(in: stamped.token) == nil else {
            return nil
        }
        let (signature, token) = (stamped.signature, stamped.token)
        var created: CMSDecoder?
        var content: CFData?
        var status = CMSSignerStatus.unsigned
        var built: SecTrust?
        guard
            CMSDecoderCreate(&created) == errSecSuccess, let decoder = created,
            token.withUnsafeBytes({ $0.baseAddress.map { CMSDecoderUpdateMessage(decoder, $0, token.count) } ?? errSecParam }) == errSecSuccess,
            CMSDecoderFinalizeMessage(decoder) == errSecSuccess,
            CMSDecoderCopyContent(decoder, &content) == errSecSuccess, let info = content as Data?,
            let imprinted = Self.tstInfo(info), imprinted.digest.digest(signature) == imprinted.imprint,
            CMSDecoderSetDetachedContent(decoder, info as CFData) == errSecSuccess,
            let policy = SecPolicyCreateWithProperties(kSecPolicyAppleTimeStamping, nil),
            CMSDecoderCopySignerStatus(decoder, 0, [policy] as CFArray, false, &status, &built, nil) == errSecSuccess,
            status == .valid, let trust = built
        else {
            return nil
        }
        SecTrustSetNetworkFetchAllowed(trust, false)
        if let anchors {
            SecTrustSetAnchorCertificates(trust, anchors as CFArray)
        }
        SecTrustSetVerifyDate(trust, imprinted.date as CFDate)
        guard SecTrustEvaluateWithError(trust, nil) else {
            return nil
        }
        return Timestamp(date: imprinted.date, chain: SecTrustCopyCertificateChain(trust) as? [SecCertificate] ?? [])
    }

    /**
     The fields of the first signer in `cms`, as the encoding lays them: a ContentInfo of SignedData, whose last field
     is the signers, each a SignerInfo of a version, the signer's identifier, a digest algorithm, signed attributes,
     a signature algorithm, the signature, an OCTET STRING, and unsigned attributes, when it has them, last in a
     context tag 1. Nil for anything else.
     */
    private static func signerInfo(in cms: Data) -> [DER.Element]? {
        var reader = DER.Reader(cms)
        guard
            let contentInfo = reader.next(), contentInfo.tag == 0x30,
            let parts = DER.elements(of: contentInfo.content), parts.count == 2,
            parts[0].tag == 0x06, parts[0].content == Self.signedDataType, parts[1].tag == 0xa0,
            let signedData = DER.elements(of: parts[1].content)?.first, signedData.tag == 0x30,
            let signerInfos = DER.elements(of: signedData.content)?.last, signerInfos.tag == 0x31,
            let signerInfo = DER.elements(of: signerInfos.content)?.first, signerInfo.tag == 0x30
        else {
            return nil
        }
        return DER.elements(of: signerInfo.content)
    }

    /// The OIDs of the signer's hash-agility attributes: the cdhashes plist, and the v2 cdhash per digest algorithm.
    private static let hashAgilityType = Data([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x09, 0x01])
    private static let hashAgilityV2Type = Data([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x09, 0x02])

    /**
     The code directories the first signer of `cms` binds, as codesign records them among its signed attributes and
     Security reads them (`CMSDecoderCopySignerAppleCodesigningHashAgility` and its v2): the cdhashes plist, an
     OCTET STRING holding an XML plist whose `cdhashes` are each directory's cdhash truncated to 20 bytes, and the
     v2 attribute, a SEQUENCE per directory of its digest algorithm and its full cdhash. Nil for an attribute that
     is not there.
     */
    static func hashAgility(in cms: Data) -> HashAgility {
        guard let fields = signerInfo(in: cms), let signed = fields.first(where: { $0.tag == 0xa0 }), let attributes = DER.elements(of: signed.content) else {
            return HashAgility(cdhashes: nil, v2: nil)
        }
        var cdhashes: [Data]?
        var v2: [HashType: Data]?
        for attribute in attributes where attribute.tag == 0x30 {
            guard let parts = DER.elements(of: attribute.content), parts.count == 2, parts[0].tag == 0x06, parts[1].tag == 0x31, let values = DER.elements(of: parts[1].content) else {
                continue
            }
            if parts[0].content == Self.hashAgilityType, let plist = values.first, plist.tag == 0x04 {
                let hashes = (try? PropertyListSerialization.propertyList(from: Data(plist.content), format: nil) as? [String: Any])?["cdhashes"] as? [Data]
                cdhashes = hashes ?? []
            } else if parts[0].content == Self.hashAgilityV2Type {
                var named: [HashType: Data] = [:]
                for value in values where value.tag == 0x30 {
                    if let pair = DER.elements(of: value.content), pair.count == 2, pair[0].tag == 0x06, pair[1].tag == 0x04, let hashType = Self.imprintDigests[Data(pair[0].content)] {
                        named[hashType] = Data(pair[1].content)
                    }
                }
                v2 = named
            }
        }
        return HashAgility(cdhashes: cdhashes, v2: v2)
    }

    /// The first signer's signature in `cms`, what a timestamp token is taken over; nil for anything else.
    static func signature(in cms: Data) -> Data? {
        self.signerInfo(in: cms)?.last(where: { $0.tag == 0x04 }).map { Data($0.content) }
    }

    /**
     The first signer's signature in `cms`, and the timestamp token among its unsigned attributes, the value of the
     `id-aa-timeStampToken` one, a ContentInfo of its own. Nil without the token.
     */
    static func signatureAndToken(in cms: Data) -> SignatureAndToken? {
        guard
            let fields = signerInfo(in: cms),
            let unsigned = fields.last, unsigned.tag == 0xa1,
            let signature = fields.last(where: { $0.tag == 0x04 }),
            let attributes = DER.elements(of: unsigned.content)
        else {
            return nil
        }
        for attribute in attributes where attribute.tag == 0x30 {
            guard
                let pair = DER.elements(of: attribute.content), pair.count == 2,
                pair[0].tag == 0x06, pair[0].content == Self.timeStampTokenType,
                pair[1].tag == 0x31, let token = DER.elements(of: pair[1].content)?.first
            else {
                continue
            }
            return SignatureAndToken(signature: Data(signature.content), token: Data(token.raw))
        }
        return nil
    }

    /**
     What a token's `TSTInfo` certifies: its date, and the imprint of what it was taken over, with the digest it was
     taken with. Version, policy, the imprint, a serial number and the time, in that order; nil for any other form.
     */
    private static func tstInfo(_ der: Data) -> TSTInfo? {
        var reader = DER.Reader(der)
        guard
            let info = reader.next(), info.tag == 0x30,
            let fields = DER.elements(of: info.content), fields.count >= 5,
            fields[0].tag == 0x02, fields[1].tag == 0x06, fields[2].tag == 0x30, fields[3].tag == 0x02, fields[4].tag == 0x18,
            let imprint = DER.elements(of: fields[2].content), imprint.count == 2, imprint[0].tag == 0x30, imprint[1].tag == 0x04,
            let algorithm = DER.elements(of: imprint[0].content)?.first, algorithm.tag == 0x06,
            let digest = Self.imprintDigests[Data(algorithm.content)],
            let date = DER.generalizedTime(fields[4].content)
        else {
            return nil
        }
        return TSTInfo(date: date, digest: digest, imprint: Data(imprint[1].content))
    }

    /// A code directory the signature binds, as `init` checks it against the signer's attributes: its hash type, and
    /// its full cdhash.
    struct Binding {
        let hashType: HashType
        let cdhash: Data
    }

    /// A secure timestamp that holds: the date it certifies, and the authority's chain to its anchor.
    struct Timestamp {
        let date: Date
        let chain: [SecCertificate]
    }

    /// The code directories a signer's attributes bind, as codesign records them: the cdhashes plist's, each a cdhash
    /// cut to 20 bytes, and the v2 attribute's, a full cdhash per digest; nil for an attribute that is not there.
    struct HashAgility {
        let cdhashes: [Data]?
        let v2: [HashType: Data]?
    }

    /// A signer's signature, and the timestamp token taken over it.
    struct SignatureAndToken {
        let signature: Data
        let token: Data
    }

    /// What a token's `TSTInfo` certifies: its date, and the imprint of what it was taken over, with its digest.
    private struct TSTInfo {
        let date: Date
        let digest: HashType
        let imprint: Data
    }

    /// The leaf's subject summary, its common name for the certificates Apple issues.
    var summary: String {
        self.chain.first.flatMap { SecCertificateCopySubjectSummary($0) as String? } ?? "an unnamed certificate"
    }

    /// Whether the chain ends at one of Apple's roots: `anchor apple generic`.
    var anchoredAtApple: Bool {
        self.chain.last.map(Self.isAppleRoot) ?? false
    }

    /// Whether `certificate` is one of Apple's roots.
    private static func isAppleRoot(_ certificate: SecCertificate) -> Bool {
        self.appleRoots.contains(Data(SHA256.hash(data: SecCertificateCopyData(certificate) as Data)).hexString)
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
