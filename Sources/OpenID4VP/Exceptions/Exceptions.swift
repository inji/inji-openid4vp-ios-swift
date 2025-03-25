import Foundation

enum Exceptions: Error, Equatable, LocalizedError {
    case invalidData(message: String)
    
    public var errorDescription: String? {
        switch self {
        case .invalidData(let message):
            return message
        }
    }
}
