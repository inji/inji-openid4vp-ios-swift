import Foundation

enum VerifierVerificationException: Error, LocalizedError {
    case invalidVerifierClientID(message: String)
    case responseUriIsEmpty
    
    public var errorDescription: String? {
        switch self {
        case .invalidVerifierClientID(let message):
            return message
        default:
            return "An error occurred."
        }
    }
}
