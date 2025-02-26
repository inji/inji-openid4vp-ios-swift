import Foundation

enum JwtVerificationException: Error, Equatable, LocalizedError {
    case invalidClientIdScheme(message: String)
    case kidExtractionFailed(message: String)
    case invalidSignature(message: String)
    case proofVerificationFailed(message: String)
    case publicKeyNotFound(message: String?)
    case publicKeyResolutionFailed(message: String)
    case publicKeyExtractionFailed
    
    public var errorDescription: String? {
        switch self {
        case .invalidClientIdScheme(let message):
            return message
        case .kidExtractionFailed(let message):
            return message
        case .invalidSignature(let message):
            return message
        case .proofVerificationFailed(let message):
            return message
        case .publicKeyNotFound(let message):
            return message ?? "Public key not found in the did document."
        case .publicKeyExtractionFailed:
            return "Public key extraction failed."
        case .publicKeyResolutionFailed(let message):
            return message
        default:
            return "An error occurred."
        }
    }
}

