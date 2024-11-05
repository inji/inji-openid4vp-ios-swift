import Foundation

enum NetworkRequestException: Error, LocalizedError {
    case invalidResponse
    case networkRequestFailed(message: String)
    case interruptedIOException
    
    public var errorDescription: String? {
        switch self {
        case .networkRequestFailed(let message):
            return message
        default:
            return "An error occurred."
        }
    }
}
