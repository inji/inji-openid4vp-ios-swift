import Foundation

enum AuthorizationRequestException: Error, Equatable, LocalizedError {
    case jsonDecodingFailed(fieldPath: String, message: String)
    case jsonEncodingFailed(fieldPath: String, message: String)
    case invalidPresentationDefinition
    case invalidQueryParams(message: String)
    case invalidInput(fieldPath: String)
    case invalidLimitDisclosure
    case missingInput(fieldPath: String)
    case decodingException(fieldPath: String)
    case utf8Encoding(fieldPath: String)
    case urlCreationFailed(message: String)
    case queryItemsRetrievalFailed
    case parameterValuesAreEmpty
    case mismatchingClientIDInRequest
    case mismatchingClientIdSchemeInRequest
    case invalidVerifier(message: String?)
    case invalidVerifierRedirectUri
    case unsupportedHttpMethod(message: String)
    case invalidInputPattern(fieldPath: String)
    case unexpectedError(message: String)
    case invalidResponseMode(message: String)
    case invalidData(message: String)
    
    public var errorDescription: String? {
        switch self {
        case .invalidInput(let fieldName):
            return "Invalid Input: \(fieldName) value cannot be empty or null"
        case .missingInput(let fieldName):
            return "Missing Input: \(fieldName) param is required"
        case .invalidQueryParams(let message):
            return message
        case .invalidLimitDisclosure:
            return "Invalid Input: constraints->limit_disclosure value should be either required or preferred"
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
        case .mismatchingClientIdSchemeInRequest:
            return "Client Id Scheme is mismatching in QR data and Request Uri response"
        case .invalidVerifierRedirectUri:
            return "Client Id and Redirect uri value should be equal"
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
        case .invalidData(let message):
            return message
        default:
            return "An error occurred."
        }
    }
}
