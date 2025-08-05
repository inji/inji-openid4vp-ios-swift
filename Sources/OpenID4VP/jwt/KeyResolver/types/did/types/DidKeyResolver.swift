import Foundation
import CryptoKit
import Base58Swift

class DidKeyResolver : BaseDidPublicKeyResolver{
    private static let className = String(describing: DidKeyResolver.self)
    let parsedDid: ParsedDID
    let networkManager: NetworkManaging
    static let keySize = 34
    
    init(networkManager: NetworkManaging, parsedDID: ParsedDID) {
        self.networkManager = networkManager
        self.parsedDid = parsedDID
    }
    
    func resolve(verificationaMethodUri kid: String) async throws -> PublicKeyType {
        let decodedBytes = try decodeMultibase(self.parsedDid.id)
        
        guard decodedBytes.count == Self.keySize,
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
