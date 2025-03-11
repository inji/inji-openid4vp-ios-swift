import Foundation

public struct EncryptionProvider {
    
    static func getEncryptor(_ enc: String) throws -> JWEEncryption {
        switch enc {
        case "A256GCM":
            return AESGCMEncryption(keySize: .bits256)
        default:
            throw Logger.handleException(exceptionType: "UnsupportedEncryptionAlgorithm", className: JWEHandler.className)
        }
    }
}
