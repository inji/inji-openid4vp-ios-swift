import Foundation
import JSONWebKey
import CryptoKit
import JSONWebEncryption
import JSONWebAlgorithms

public struct JWEHandler {
    let contentEncryptionAlgorithm: String
    let keyEncryptionAlgorithm: String
    let publicKey: JWK
    let producerInfo: String
    let recipientInfo: String
    
    static let className = String(describing: JWEHandler.self)
    
    func encrypt(_ payload: [String: Any]) throws -> String {
        let recipientKey: JWK = publicKey
        try validateRecipientKey(
            recipientKey,
            for: KeyManagementAlgorithm.ecdhES
        )
        
        var header = DefaultJWEHeaderImpl()
        header.keyManagementAlgorithm = .ecdhES
        header.encodingAlgorithm = .a256GCM
        header.agreementPartyUInfo = Data(base64UrlEncoded: producerInfo)
        header.agreementPartyVInfo = Data(base64UrlEncoded: recipientInfo)
        header.keyID = recipientKey.keyID

        var payloadData: Data
        do {
            payloadData = try toData(payload)
        } catch {
            throw PayloadConversionFailed(className: JWEHandler.className)
        }

        let jwe = try JWE(payload: payloadData, protectedHeader: header, recipientKey: recipientKey)
        
        return jwe.compactSerialization()
    }

    private func validateRecipientKey(
        _ jwk: JWK,
        for algorithm: KeyManagementAlgorithm?
    ) throws {

        let supportedAlgorithms: Set<KeyManagementAlgorithm> = [
            .ecdhES
        ]

        guard let algorithm,
              supportedAlgorithms.contains(algorithm) else {
            throw JweEncryptionFailure(
                message: "Unsupported JWE algorithm: \(String(describing: algorithm))",
                className: Self.className
            )
        }
        
        let kty = jwk.keyType

        switch kty {

        case .octetKeyPair:
            let crv = jwk.curve

            guard crv == .x25519 else {
                throw JweEncryptionFailure(
                    message: "Unsupported OKP curve for ECDH-ES: \(crv?.rawValue ?? "nil"). Only X25519 is supported.",
                    className: Self.className
                )
            }

        case .ellipticCurve:
            let crv = jwk.curve

            guard [.p256, .p384, .p521].contains(crv) else {
                throw JweEncryptionFailure(
                    message: "Unsupported EC curve for ECDH-ES: \(crv?.rawValue ?? "nil")",
                    className: Self.className
                )
            }

        default:
            throw JweEncryptionFailure(
                message: "Unsupported recipient key type: \(kty)",
                className: Self.className
            )
        }
    }
}
