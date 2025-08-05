import Foundation
import CryptoKit
import Base58Swift

class DidJwkResolver : BaseDidPublicKeyResolver {
    private static let className = String(describing: DidJwkResolver.self)
    let parsedDid: ParsedDID
    let networkManager: NetworkManaging
    
    init(networkManager: NetworkManaging, parsedDID: ParsedDID)  {
        self.networkManager = networkManager
        self.parsedDid = parsedDID
    }
    
    func resolve(verificationaMethodUri kid: String) async throws -> PublicKeyType {
        let base64urlJwk = String(self.parsedDid.id)
        
        guard let jwkData = Data(base64UrlEncoded: base64urlJwk) else {
            throw PublicKeyResolutionFailed(message: "Invalid base64url encoding for public key data", className: Self.className)
        }
        let jwk = try JSONDecoder().decode(JWK.self, from: jwkData)
        
        guard jwk.kty == "OKP" else {
            throw PublicKeyResolutionFailed(
                message: "KeyType - \(jwk.kty) is not supported. Supported: OKP",
                className: Self.className
            )
        }
        
        guard jwk.crv == "Ed25519" else {
            throw PublicKeyResolutionFailed(
                message: "Curve - \(jwk.crv) is not supported. Supported: Ed25519",
                className: Self.className
            )
        }
        
        guard let publicKeyData = Data(base64UrlEncoded: jwk.x) else {
            throw PublicKeyResolutionFailed(message: "Invalid base64url encoding for public key data", className: Self.className)
        }
        
        return try toEd25519Key(publicKeyData: publicKeyData)
    }
}
