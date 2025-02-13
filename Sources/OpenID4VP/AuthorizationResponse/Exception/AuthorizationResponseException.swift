import Foundation

enum AuthorizationResponseException: Error, LocalizedError {
    case credentialsMapIsEmpty
    case credentialsMapValueIsEmpty
    
    public var errorDescription: String? {
        switch self {
        case .credentialsMapIsEmpty:
            return "Credentials map received is empty."
        case .credentialsMapValueIsEmpty:
            return "Value of credentials inside credentials map is empty."
        default:
            return "An error occurred."
        }
    }
}
