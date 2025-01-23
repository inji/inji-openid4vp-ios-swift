import Foundation

enum ProofVerificationException: Error, Equatable, LocalizedError {
    case invalidClientIdScheme(message: String)
    case urlCreationFailed(message: String)
    case kidExtractionFailed(message: String)
    case invalidSignature(message: String)
    case proofVerificationFailed(message: String)
    case publicKeyNotFound
    case publicKeyExtractionFailed
    
    public var errorDescription: String? {
        switch self {
        case .invalidClientIdScheme(let message):
            return message
        case .urlCreationFailed(let message):
            return message
        case .kidExtractionFailed(let message):
            return message
        case .invalidSignature(let message):
            return message
        case .proofVerificationFailed(let message):
            return message
        case .publicKeyNotFound:
            return "Public key not found in the did document."
        case .publicKeyExtractionFailed:
            return "Public key extraction failed."
        default:
            return "An error occurred."
        }
    }
}

