import Foundation
import CryptoKit

class AESGCMEncryption: JWEEncryption {
    func encrypt(_ data: Data, with key: SymmetricKey) throws -> (ciphertext: Data, nonce: Data, tag: Data) {
        let nonce = AES.GCM.Nonce()
        let sealedBox = try AES.GCM.seal(data, using: key, nonce: nonce)
        
        return (
            sealedBox.ciphertext,
            sealedBox.nonce.withUnsafeBytes { Data($0) },
            sealedBox.tag
        )
    }
}
