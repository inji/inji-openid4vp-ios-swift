import Foundation
import CryptoKit
import Base58Swift

class DidKeyResolver : BaseDidPublicKeyResolver{
    private static let className = String(describing: DidKeyResolver.self)
    let parsedDid: ParsedDID
    let networkManager: NetworkManaging
    static let keySize = 34
    static let edKeyPrefix = 0xed
    static let multiCodecTrailingByte = 0x01
    
    
    init(networkManager: NetworkManaging, parsedDID: ParsedDID) {
        self.networkManager = networkManager
        self.parsedDid = parsedDID
    }
    
    func resolve(verificationaMethodUri kid: String) async throws -> PublicKeyType {
        let decodedBytes = try decodeMultibase(self.parsedDid.id)
        
        guard decodedBytes.count == Self.keySize,
              decodedBytes[0] == Self.edKeyPrefix,
              decodedBytes[1] == Self.multiCodecTrailingByte else {
            throw PublicKeyResolutionFailed(message: "Provided key is not supported. Supported: Ed25519", className: Self.className)
        }
        
        let keyBytes = decodedBytes[2..<34]
        
        return try toEd25519Key(publicKeyData: keyBytes)
    }
}
