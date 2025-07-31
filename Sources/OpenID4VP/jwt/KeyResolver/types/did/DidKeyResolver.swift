import Foundation
import CryptoKit
import Base58Swift

class DidKeyResolver {
    private let didUrl: String
    private let networkManager: NetworkManaging
    static let className = String(describing: DidPublicKeyResolver.self)
    private static let supportedPublicKeyTypes = ["publicKeyMultibase", "publicKeyJwk"]
    
    init(parsedDid: ParsedDID, networkManager: NetworkManaging) {
        self.didUrl = parsedDid.didUrl
        self.networkManager = networkManager
    }
    
    func resolve(verificationaMethodUri kid: String) async throws -> PublicKeyType {
        guard let didKey = didUrl.components(separatedBy: "#").first?
            .replacingOccurrences(of: "did:key:", with: "") else {
            throw PublicKeyResolutionFailed(message: "invalidDID", className: Self.className)
        }
        
        guard let decodedBytes = Base58.base58Decode(didKey) else {
            throw PublicKeyResolutionFailed(message: "keyDecodingFailed", className: Self.className)
        }
        
        
        guard decodedBytes.count == 34,
              decodedBytes[0] == 0xed,
              decodedBytes[1] == 0x01 else {
            throw PublicKeyResolutionFailed(message: "unsupportedKeyType", className: Self.className)
        }
        
        let keyBytes = decodedBytes[2..<34]
        
        do {
            return try .ed25519(Curve25519.Signing.PublicKey(rawRepresentation: Data(keyBytes)))
        } catch {
            throw PublicKeyResolutionFailed(message: "keyDecodingFailed", className: Self.className)
        }
    }
}
