import Foundation

enum AuthorizationRequestException: Error, Equatable, LocalizedError {
    case jsonDecodingFailed
    case invalidPresentationDefinition
    case invalidQueryParams(message: String)
    case invalidInput(fieldName: String)
    case missingInput(fieldName: String)
    case decodingException
    case utf8Encoding(fieldName: String)
    case urlCreationFailed
    case queryItemsRetrievalFailed
    case parameterValuesAreEmpty
    
    public var errorDescription: String? {
        switch self {
        case .invalidInput(let fieldName):
            return "Invalid input for key : \(fieldName)"
        case .missingInput(let fieldName):
            return "Missing Input: \(fieldName) param is required."
        case .invalidQueryParams(let message):
            return message
        case .utf8Encoding(let fieldName):
            return "Failed to convert \(fieldName) string to UTF-8 data"
        default:
            return "An error occurred."
        }
    }
}
