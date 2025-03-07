import Foundation

enum AuthorizationResponseException: Error, LocalizedError {
    case credentialsMapIsEmpty
    case credentialsMapValueIsEmpty
    case jsonEncodingException(fieldName: String)
    case invalidURL
    
    public var errorDescription: String? {
        switch self {
        case .jsonEncodingException(let fieldName):
            return "Error occurred while serializing \(fieldName)"
        case .credentialsMapIsEmpty:
            return "Verifiable credentials map is empty."
        case .credentialsMapValueIsEmpty:
            return "Verifiable credentials map value is empty."
        default:
            return "An error occurred."
        }
    }
}
