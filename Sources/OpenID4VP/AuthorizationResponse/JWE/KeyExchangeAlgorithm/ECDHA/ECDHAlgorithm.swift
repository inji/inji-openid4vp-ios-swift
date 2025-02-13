import Foundation
import CryptoKit

class ECDHESAlgorithm: JWEAlgorithm {
    
    private var ephemeralKeyPair: (privateKey: Curve25519.KeyAgreement.PrivateKey,
                                 publicKey: Curve25519.KeyAgreement.PublicKey)?
    
     func deriveKey(publicKey: Data) throws -> SymmetricKey {
        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        let publicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKey)
        
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
    
    func getEncryptedKey() -> String {
        return ""
    }
    
    func getJWEHeader(config: JWEEncryptionConfig, jwk: JWK) -> [String : Any] {
        return [
            "alg": config.alg,
            "enc": config.enc,
            "kid": jwk.kid ]
    }
}
