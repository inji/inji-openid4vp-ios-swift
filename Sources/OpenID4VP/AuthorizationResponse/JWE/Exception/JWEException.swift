import Foundation

enum JWEException: Error, LocalizedError {
    case publicKeyConversionFailed
    case payloadConversionFailed
    case unsupportedKeyAgreementAlgorithm
    case unsupportedEncryptionAlgorithm
    case invalidEncryptionKeySize
    case invalidJwksInput(fieldPath: String)
    
    public var errorDescription: String? {
        switch self {
        case .publicKeyConversionFailed:
            return "Public key Data conversion from base64 failed."
        case .payloadConversionFailed:
            return "Payload data conversion failed."
        case .unsupportedKeyAgreementAlgorithm:
            return "Required Key Agreement algorithm is not supported."
        case .unsupportedEncryptionAlgorithm:
            return "Required Encryption algorithm is not supported."
        case .invalidJwksInput(let fieldName):
            return "Invalid Input: \(fieldName) param is empty."
        case .invalidEncryptionKeySize:
            return "Invalid Key size provided for encryption."
        default:
            return "An error occurred."
        }
    }
}
