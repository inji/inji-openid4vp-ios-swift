import Foundation
import JSONWebKey
import CryptoKit
import Base58Swift

class DidJwkResolver : BaseDidPublicKeyResolver {
    private static let className = String(describing: DidJwkResolver.self)
    let networkManager: NetworkManaging
    
    init(networkManager: NetworkManaging)  {
        self.networkManager = networkManager
    }
    
    func extractPublicKey(parsedDID: ParsedDID, keyId: String? = nil) async throws -> PublicKeyType {
        let base64urlJwk = String(parsedDID.id)
        let jwk = try decodeJWK(base64urlJwk)
        
        return try jwkToPublicKey(jwk, className: Self.className)
    }
    
    func extractJWSAlgorithm(parsedDid: ParsedDID) throws -> String {
        let base64urlJwk = String(parsedDid.id)
        let jwk = try decodeJWK(base64urlJwk)
        
        // Priority 1: Use explicit 'alg' field
        if let alg = jwk.algorithm { return alg }
        
        // Priority 2: Map from kty/crv
        let kty = jwk.keyType
        let crv = jwk.curve
        
        switch (kty, crv) {
        case (.octetKeyPair, .ed25519): return JWSAlgorithm.eddsa
        case (.ellipticCurve, .p256):    return JWSAlgorithm.es256
        case (.ellipticCurve, .p384):    return JWSAlgorithm.es384
        case (.ellipticCurve, .secp256k1): return JWSAlgorithm.es256k
        case (.rsa, _): return JWSAlgorithm.rs256
        default:
            throw UnsupportedOperationException(message: "Unsupported JWK type or curve", className: Self.className)
        }
    }
    
    func decodeJWK(_ base64urlJwk: String) throws -> JWK {
        guard let jwkData = Data(base64UrlEncoded: base64urlJwk) else {
            throw PublicKeyResolutionFailed(message: "Invalid base64url encoding for public key data", className: "Utils")
        }
        
        let jwk = try {
            do {
                return try JSONDecoder().decode(JWK.self, from: jwkData)
            } catch {
                throw PublicKeyResolutionFailed(
                    message: "Failed to decode JWK: \(error.localizedDescription)",
                    className: "Utils"
                )
            }
        }()
        
        return jwk
    }
}
