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
        let base64urlJwk = String(self.parsedDid.didUrl.dropFirst("did:jwk:".count))
        
        guard let jwkData = decodeBase64Url(base64urlJwk) else {
            throw PublicKeyResolutionFailed(message: "invalidBase64Encoding", className: Self.className)
        }
        let jwk = try JSONDecoder().decode(JWK.self, from: jwkData)
        
        guard jwk.kty == "OKP", jwk.crv == "Ed25519" else {
            throw PublicKeyResolutionFailed(message: "DidJwkResolverError.unsupportedKeyType", className: Self.className)
        }
        
        guard let publicKeyData = decodeBase64Url(jwk.x) else {
            throw PublicKeyResolutionFailed(message: "DidJwkResolverError.keyConstructionFailed", className: Self.className)
        }
        
        do {
            let edKey = try Curve25519.Signing.PublicKey(rawRepresentation: publicKeyData)
            return .ed25519(edKey)
        } catch {
            throw PublicKeyResolutionFailed(message: "DidJwkResolverError.keyConstructionFailed", className: Self.className)
        }
    }
    
    private func decodeBase64Url(_ input: String) -> Data? {
        var base64 = input
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        
        let paddingNeeded = 4 - (base64.count % 4)
        if paddingNeeded < 4 {
            base64 += String(repeating: "=", count: paddingNeeded)
        }
        
        return Data(base64Encoded: base64)
    }
}
