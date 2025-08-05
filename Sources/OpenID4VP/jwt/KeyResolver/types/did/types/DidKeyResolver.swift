import Foundation
import CryptoKit
import Base58Swift

class DidKeyResolver {
    private let didUrl: String
    private let networkManager: NetworkManaging
    static let className = String(describing: DidKeyResolver.self)
    
    init(parsedDid: ParsedDID, networkManager: NetworkManaging) {
        self.didUrl = parsedDid.didUrl
        self.networkManager = networkManager
    }
    
    func resolve(verificationaMethodUri kid: String) async throws -> PublicKeyType {
        guard let didKey = didUrl.components(separatedBy: "#").first?
            .components(separatedBy: "did:key:")
                .filter({ !$0.isEmpty })
                .first else {
            throw PublicKeyResolutionFailed(message: "invalidDID", className: Self.className)
        }
        
        let base58Part = String(didKey.dropFirst())
        guard let decodedBytes = Base58.base58Decode(base58Part) else {
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
