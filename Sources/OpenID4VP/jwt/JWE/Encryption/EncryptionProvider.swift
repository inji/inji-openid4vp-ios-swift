import Foundation

public struct EncryptionProvider {
    
    static func getEncrypter(_ enc: String) throws -> JWEEncryption {
        switch enc {
        case "A256GCM":
            return AESGCMEncryption(keySize: .bits256)
        default:
            throw UnsupportedEncryptionAlgorithm(message: "Required Encryption algorithm is not supported.", className: JWEHandler.className)
        }
    }
}
