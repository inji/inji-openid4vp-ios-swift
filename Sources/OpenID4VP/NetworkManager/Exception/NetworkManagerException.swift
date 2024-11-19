import Foundation

enum NetworkRequestException: Error, LocalizedError {
    case invalidResponse(message: String)
    case networkRequestFailed(message: String)
    case networkRequestTimeout
    
    public var errorDescription: String? {
        switch self {
        case .networkRequestFailed(let message):
            return "Network request failed with error response - \(message)"
        case .invalidResponse(let message):
            return message
        case .networkRequestTimeout:
            return "VP sharing failed due to connection timeout"
        default:
            return "An error occurred."
        }
    }
}
