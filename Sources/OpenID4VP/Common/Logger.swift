import Foundation

class Logger {
    private static var logTag = ""
    private static var traceabilityId: String?
    
    static func setTraceabilityId(className: String, traceabilityId: String? = nil) {
        if let traceId = traceabilityId {
            self.traceabilityId = traceId
        }
    }
    static func getLogTag(_ className: String) -> String {
        return "INJI-OpenID4VP : \(className) | traceID \(String(describing: self.traceabilityId))"
    }
    
    static func error(_ logTag: String, _ exception: Error) {
        print("\(logTag) | ERROR: \(exception.localizedDescription)")
    }
    
    static func handleException(exceptionType: String, message: String? = nil, fieldPath: [String]? = nil, className: String) -> Error {
        var fieldPathAsString: String = ""
        if let fieldPath = fieldPath{
            fieldPathAsString = fieldPath.joined(separator: "->")
        }
        let exception: Error
        switch exceptionType {
        case "MissingInput":
            exception = AuthorizationRequestException.missingInput(fieldPath: fieldPathAsString)
        case "InvalidInput":
            exception = AuthorizationRequestException.invalidInput(fieldPath: fieldPathAsString)
        case "InvalidInputPattern":
            exception = AuthorizationRequestException.invalidInputPattern(fieldPath: fieldPathAsString)
        case "InvalidQueryParams":
            exception = AuthorizationRequestException.invalidQueryParams(message: message ?? "")
        case "UTF8Encoding":
            exception = AuthorizationRequestException.utf8Encoding(fieldPath: fieldPathAsString)
        case "JsonDecodingFailed":
            exception = AuthorizationRequestException.jsonDecodingFailed(fieldPath: fieldPathAsString, message: message ?? "")
        case "JsonEncodingFailed":
            exception = AuthorizationRequestException.jsonEncodingFailed(fieldPath: fieldPathAsString, message: message ?? "")
        case "Decoding":
            exception = AuthorizationRequestException.decodingException(fieldPath: fieldPathAsString)
        case "InvalidVerifierClientID":
            exception = AuthorizationRequestException.invalidVerifierClientID
        case "InvalidLimitDisclosure":
            exception = AuthorizationRequestException.invalidLimitDisclosure
        default:
            // Handle unexpected exception types, e.g., log an error
            exception = AuthorizationRequestException.unexpectedError(message: "An unexpected exception occurred: exception type: \(exceptionType)")
        }
        error(getLogTag(className), exception)
        return exception
    }
}
