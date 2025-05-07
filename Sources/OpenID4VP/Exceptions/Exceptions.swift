import Foundation

public enum Exceptions: Error, Equatable, LocalizedError {
    case invalidData(message: String)
    case missingInput(fieldPath: String)
    case invalidInput(fieldPath: String)
    
    public var errorDescription: String? {
        switch self {
        case .invalidData(let message):
            return message
        case .missingInput(let fieldName):
            return "Missing Input: \(fieldName) param is required"
        case .invalidInput(let fieldName):
            return "Invalid Input: \(fieldName) value cannot be empty or null"
        }   
    }
}
