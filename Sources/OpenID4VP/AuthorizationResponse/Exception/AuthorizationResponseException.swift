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
        default:
            return "An error occurred."
        }
    }
}
