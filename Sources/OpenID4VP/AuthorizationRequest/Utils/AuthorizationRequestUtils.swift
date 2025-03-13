import Foundation
import CryptoKit

func validateAttribute(
    _ attribute: String,
    values: [String: Any]
) throws {
    guard let value = values[attribute] else {
        throw Logger.handleException(
            exceptionType: "MissingInput",
            fieldPath: [attribute],
            className: AuthorizationRequest.className
        )
    }
    
    if let stringValue = value as? String {
        if stringValue.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ||
            stringValue.lowercased() == "nil" ||
            stringValue.lowercased() == "null" {
            throw Logger.handleException(
                exceptionType: "InvalidInput",
                fieldPath: [attribute],
                className: AuthorizationRequest.className
            )
        }
    }
}

func validateAuthorizationRequestObjectAndParameters(params: [String: String], requestUriParams: [String: Any]) throws {
    guard params["client_id"] == requestUriParams["client_id"] as? String else {
        throw Logger.handleException(exceptionType: "MismatchingClientIDInRequest", className: AuthorizationRequest.className)
    }
    
    guard params["client_id_scheme"] == requestUriParams["client_id_scheme"] as? String else {
        throw Logger.handleException(exceptionType: "MismatchingClientIdSchemeInRequest", className: AuthorizationRequest.className)
    }
}

func urlEncodedRequest(_ decodedRequest: String) -> String? {
    return decodedRequest.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)
}

func getQueryItems(_ encodedUrl: URL) -> [URLQueryItem]? {
    return URLComponents(url: encodedUrl, resolvingAgainstBaseURL: false)?.queryItems
}

extension Dictionary where Key == String, Value == String {
    func values(forKeys keys: [String]) -> [String]? {
        let values = keys.compactMap { self[$0] }
        return values.count == keys.count ? values : nil
    }
}

extension KeyedDecodingContainer {
    func decodeRequired<T>(
        _ type: T.Type,
        forKey key: K,
        fieldPath: [String],
        className: String,
        isMandatory: Bool
    ) throws -> T? where T: Decodable {
        if isMandatory {
            guard contains(key) else {
                throw Logger.handleException(
                    exceptionType: "MissingInput",
                    fieldPath: fieldPath,
                    className: className
                )
            }
        }
        if contains(key) {
            let rawValue = try decodeIfPresent(T?.self, forKey: key)
            if rawValue == nil {
                throw Logger.handleException(
                    exceptionType: "InvalidInput",
                    fieldPath: fieldPath,
                    className: InputDescriptor.className
                )
            }
            return rawValue!
        }
        return nil
    }
}


func getAuthorizationRequestHandler(trustedVerifiers : [Verifier], authorizationRequestParameters: [String:Any], shouldValidateClient: Bool, networkManager: NetworkManaging,setResponseUri: @escaping (String) -> Void) throws -> ClientIdSchemeBasedAuthorizationRequestHandler {
    let clientIdScheme = getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.clientIdScheme.rawValue]) ?? ClientIdScheme.preRegistered.rawValue
    
    switch clientIdScheme {
    case ClientIdScheme.preRegistered.rawValue:
        return PreRegisteredSchemeAuthorizationRequestHandler(trustedVerifiers: trustedVerifiers, authorizationRequestParameters: authorizationRequestParameters, networkManager: networkManager, shouldValidateClient: shouldValidateClient, setResponseUri: setResponseUri)
    case ClientIdScheme.did.rawValue:
        return DidSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters, networkManager: networkManager, setResponseUri: setResponseUri)
    case ClientIdScheme.redirectUri.rawValue:
        return RedirectUriSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters, networkManager: networkManager, setResponseUri: setResponseUri)
    default:
        throw Logger.handleException(exceptionType: "InvalidData",message: "Client id scheme in request is not supported" ,className: AuthorizationRequest.className)
    }
}

func extractQueryParameters(_ input: String) throws -> [String: String] {
    guard input.firstIndex(of: "?") != nil else {
        throw Logger.handleException(exceptionType: "InvalidQueryParams", message: "Query parameters are missing in the Authorization request", className: AuthorizationRequest.className)
    }
    let urlComponents = URLComponents(string: input)
    var decodedParams = [String: String]()
    
    if let queryItems = urlComponents?.queryItems {
        for item in queryItems {
            if let decodedValue = item.value?.removingPercentEncoding {
                decodedParams[item.name] = decodedValue
            }
        }
    }
    
    return decodedParams
}

func validateField(_ field: String?, _ fieldPath: [String], _ className: String) throws {
    if let field = field {
        guard isNeitherNullNorEmpty(field: field) else {
            throw Logger.handleException(exceptionType: "InvalidInput", fieldPath: fieldPath, className: className)
        }
    }
}
