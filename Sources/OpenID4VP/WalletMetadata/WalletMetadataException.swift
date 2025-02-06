import Foundation

enum ValidationError: Error, LocalizedError {
    case invalidJSON
    case missingRequiredField(String)
    case extraField(String)

    var errorDescription: String? {
        switch self {
        case .invalidJSON:
            return "Invalid JSON format."
        case .missingRequiredField(let field):
            return "Missing required field: \(field)."
        case .extraField(let field):
            return "Extra field detected: \(field)."
        }
    }
}
