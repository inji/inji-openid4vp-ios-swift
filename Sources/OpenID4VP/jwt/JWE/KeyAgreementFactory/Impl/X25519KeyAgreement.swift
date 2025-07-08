import Foundation
import CryptoKit

class X25519KeyAgreement: JWEKeyAgreement {
    static let className = String(describing: X25519KeyAgreement.self)
    private var ephemeralKeyPair: (privateKey: Curve25519.KeyAgreement.PrivateKey,
                                   publicKey: Curve25519.KeyAgreement.PublicKey)?

    func deriveKey(publicKey: String) throws -> SymmetricKey {
        
        guard let publicKeyData = Data(base64Encoded: makeBase64Standard(publicKey)) else {
            
            throw PublicKeyConversionFailed(className: X25519KeyAgreement.className)
        }
        
        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        let publicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKeyData)

        ephemeralKeyPair = (privateKey, privateKey.publicKey)

        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)

        return sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: "ECDH-ES+A256GCM".data(using: .utf8)!,
            sharedInfo: Data(),
            outputByteCount: 32
        )
    }

    func getEphemeralPublicKey() -> [String: Any]? {
        guard let publicKey = ephemeralKeyPair?.publicKey else { return nil }
        return [
            "kty": "OKP",
            "crv": "X25519",
            "x": base64URLEscaped(publicKey.rawRepresentation.base64EncodedString())
        ]
    }

    func getJWEHeader(alg: String, enc: String, jwk: JWK, producerInfo: String, recipientInfo: String) -> [String: Any] {
        return [
            "alg": alg,
            "enc": enc,
            "kid": jwk.kid,
            "apu": producerInfo,
            "apv": recipientInfo,
        ]
    }
    
    func getEncyptionKey() -> String {
        return ""
    }
}
