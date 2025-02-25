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
        case "InvalidVerifier":
            exception = AuthorizationRequestException.invalidVerifier(message: message)
        case "MismatchingClientIDInRequest":
            exception = AuthorizationRequestException.mismatchingClientIDInRequest
        case "MismatchingClientIdSchemeInRequest":
            exception = AuthorizationRequestException.mismatchingClientIdSchemeInRequest
        case "InvalidVerifierRedirectUri":
            exception = AuthorizationRequestException.invalidVerifierRedirectUri
        case "InvalidLimitDisclosure":
            exception = AuthorizationRequestException.invalidLimitDisclosure
        case "InvalidClientIdScheme":
            exception = JwtVerificationException.invalidClientIdScheme(message: message ?? "")
        case "UrlCreationFailed":
            exception = NetworkRequestException.urlCreationFailed(message: message ?? "")
        case "PublicKeyNotFound":
            exception = JwtVerificationException.publicKeyNotFound(message: message)
        case "PublicKeyExtractionFailed":
            exception = JwtVerificationException.publicKeyExtractionFailed
        case "KidExtractionFailed":
            exception = JwtVerificationException.kidExtractionFailed(message: message ?? "")
        case "InvalidSignature":
            exception = JwtVerificationException.invalidSignature(message: message ?? "")
        case "ProofVerificationFailed":
            exception = JwtVerificationException.proofVerificationFailed(message: message ?? "")
        case "UnsupportedHttpMethod" :
            exception = AuthorizationRequestException.unsupportedHttpMethod(message: message ?? "")
        case "InvalidData":
            exception = AuthorizationRequestException.invalidData(message: message ?? "")
        case "InvalidResponseMode":
            exception = AuthorizationRequestException.invalidResponseMode(message: message ?? "")
        case "UnsupportedDidUrl":
            exception = DidResolverExceptions.unsupportedDidUrl(message: message)
        case "DidResultionFailed":
            exception = DidResolverExceptions.didResolutionFailed(message: message)
        case "PublicKeyResolutionFailed":
            exception = JwtVerificationException.publicKeyResolutionFailed(message: message ?? "Error occurred while resolve public key")
        default:
            exception = AuthorizationRequestException.unexpectedError(message: "An unexpected exception occurred: exception type: \(exceptionType)")
        }
        error(getLogTag(className), exception)
        return exception
    }
}
