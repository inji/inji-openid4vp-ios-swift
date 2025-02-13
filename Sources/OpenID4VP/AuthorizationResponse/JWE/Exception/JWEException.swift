import Foundation

enum JWEException: Error, LocalizedError {
    case publicKeyConversionFailed
    case payloadConversionFailed
    case unsupportedKeyExchangeAlgorithm
    case unsupportedEncryptionAlgorithm
    case invalidJwksInput(fieldPath: String)
    
    public var errorDescription: String? {
        switch self {
        case .publicKeyConversionFailed:
            return "Public key Data conversion from base64 failed."
        case .payloadConversionFailed:
            return "Payload data conversion failed."
        case .unsupportedKeyExchangeAlgorithm:
            return "Required Key exchange algorithm is not supported."
        case .unsupportedEncryptionAlgorithm:
            return "Required Encryption algorithm is not supported."
        case .invalidJwksInput(let fieldName):
            return "Invalid Input: \(fieldName) param is empty."
        default:
            return "An error occurred."
        }
    }
}
