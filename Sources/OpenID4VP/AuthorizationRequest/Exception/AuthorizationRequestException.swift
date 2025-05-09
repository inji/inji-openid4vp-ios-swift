import Foundation

enum AuthorizationRequestException: Error, Equatable, LocalizedError {
    case jsonDecodingFailed(fieldPath: String, message: String)
    case jsonEncodingFailed(fieldPath: String, message: String)
    case invalidPresentationDefinition
    case invalidQueryParams(message: String)
    case invalidLimitDisclosure
    case decodingException(fieldPath: String)
    case utf8Encoding(fieldPath: String)
    case urlCreationFailed(message: String)
    case queryItemsRetrievalFailed
    case parameterValuesAreEmpty
    case mismatchingClientIDInRequest
    case invalidVerifier(message: String?)
    case unsupportedHttpMethod(message: String)
    case invalidInputPattern(fieldPath: String)
    case unexpectedError(message: String)
    case invalidResponseMode(message: String)
    
    public var errorDescription: String? {
        switch self {
        case .invalidQueryParams(let message):
            return message
        case .invalidLimitDisclosure:
            return "Invalid Input: constraints->limit_disclosure value should be preferred"
        case .decodingException(let fieldPath):
            return "Error occurred while decoding \(fieldPath)"
        case .utf8Encoding(let fieldPath):
            return "Failed to convert \(fieldPath) string to UTF-8 data"
        case .jsonDecodingFailed(let fieldPath, let message):
            return "Json Decoding failed for \(fieldPath) due to this error: \(message)."
        case .jsonEncodingFailed(let fieldPath, let message):
            return "Json Encoding failed for \(fieldPath) due to this error: \(message)."
        case .invalidVerifier(let message):
            return "Invalid Verifier: VP sharing failed: Verifier authentication was unsuccessful.\(message ?? "")"
        case .mismatchingClientIDInRequest:
            return "Client Id is mismatching in QR data and Request Uri response"
        case .invalidInputPattern:
            return "Invalid Input Pattern: $fieldName pattern is not matching with OpenId4VP specification"
        case .unsupportedHttpMethod(let message):
            return "Unsupported HTTP method: \(message)"
        case .unexpectedError(let message):
            return message
        case .urlCreationFailed(let message):
            return message
        case .invalidResponseMode(let message):
            return message
        default:
            return "An error occurred."
        }
    }
}
