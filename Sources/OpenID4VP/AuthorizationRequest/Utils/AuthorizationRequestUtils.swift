import Foundation
import CryptoKit

func parseAndValidatePresentationDefinitionInAuthorizationRequest(
    params: [String: Any],
    networkManager: NetworkManaging
) async throws -> [String: Any] {
    
    let hasPresentationDefinition = params.keys.contains("presentation_definition")
    let hasPresentationDefinitionUri = params.keys.contains("presentation_definition_uri")
    
    guard hasPresentationDefinition != hasPresentationDefinitionUri else {
        throw Logger.handleException(
            exceptionType: "InvalidQueryParams",
            message: "Either presentation_definition or presentation_definition_uri request param can be provided but not both",
            className: AuthorizationRequest.className
        )
    }
    
    var presentationDefinitionString: String
    
    if hasPresentationDefinition, let value = params["presentation_definition"] {
        guard let valueStr = getStringValue(value), isNeitherNullNorEmpty(field: valueStr), valueStr != "null" else {
            throw Logger.handleException(
                exceptionType: "InvalidInput",
                fieldPath: ["presentation_definition"],
                className: AuthorizationRequest.className
            )
        }
        presentationDefinitionString = valueStr
        
    } else if hasPresentationDefinitionUri, let value = params[AuthorizationRequestFieldConstants.presentationDefinitionUri.rawValue] {
        guard isValidUri(value as! String)
        else {
            throw Logger.handleException(
                exceptionType: "InvalidData",
                message: "presentation_defintion_uri data is not valid",
                className: AuthorizationRequest.className
            )
        }
        guard let valueStr = getStringValue(value), isNeitherNullNorEmpty(field: valueStr), valueStr != "null" else {
            throw Logger.handleException(
                exceptionType: "InvalidInput",
                fieldPath: [AuthorizationRequestFieldConstants.presentationDefinitionUri.rawValue],
                className: AuthorizationRequest.className
            )
        }
        
        guard let url = URL(string: valueStr) else {
            throw Logger.handleException(
                exceptionType: "UrlCreationFailed",
                fieldPath: ["presentation_definition_uri"],
                className: AuthorizationRequest.className
            )
        }
        
        let response = try await networkManager.sendHTTPRequest(
            url: url, method: .GET, bodyParams: nil, headers: nil
        )
        presentationDefinitionString = response.responseBody
        
    } else {
        throw Logger.handleException(
            exceptionType: "InvalidQueryParams",
            message: "Either presentation_definition or presentation_definition_uri request param must be present",
            className: AuthorizationRequest.className
        )
    }
    
    let presentationDefinition = try PresentationDefinitionValidator.validate(presentatioDefinition: presentationDefinitionString)
    
    var mutableParams = params
    mutableParams[AuthorizationRequestFieldConstants.presentationDefinition.rawValue] = presentationDefinition
    
    return mutableParams
}

func validateKey(
    _ key: String,
    values: [String: Any]
) throws {
    guard let value = values[key] else {
        throw Logger.handleException(
            exceptionType: "MissingInput",
            fieldPath: [key],
            className: AuthorizationRequest.className
        )
    }
    
    if let stringValue = value as? String {
        if stringValue.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ||
            stringValue.lowercased() == "nil" ||
            stringValue.lowercased() == "null" {
            throw Logger.handleException(
                exceptionType: "InvalidInput",
                fieldPath: [key],
                className: AuthorizationRequest.className
            )
        }
    }
}

func fetchAuthRequestObjectByReference(params: [String: String], requestUri: String, networkManager: NetworkManaging) async throws -> (responseBody: String, httpUrlResponse: HTTPURLResponse) {
    do {
        if !isNeitherNullNorEmpty(field: requestUri) || !(requestUri != "null") {
            throw Logger.handleException(exceptionType: "InvalidInput", fieldPath: ["requestUri"], className: AuthorizationRequest.className)
        }
        let requestUriMethod = params["request_uri_method"] ?? "get"
        let httpMethod = try determineHttpMethod(method: requestUriMethod)
        
        guard let url = URL(string: params["request_uri"]!) else {
            throw Logger.handleException(exceptionType: "UrlCreationFailed", fieldPath: ["request_uri_method"], className: AuthorizationRequest.className)
        }
        
        return try await networkManager.sendHTTPRequest(url: url, method: httpMethod, bodyParams: nil, headers: nil)
    }
}

func validateMatchOfAuthRequestObjectAndParams(params: [String: String], requestUriParams: [String: String]) throws {
    guard params["client_id"] == requestUriParams["client_id"] else {
        throw Logger.handleException(exceptionType: "MismatchingClientIDInRequest", className: AuthorizationRequest.className)
    }
    
    guard params["client_id_scheme"] == requestUriParams["client_id_scheme"] else {
        throw Logger.handleException(exceptionType: "MismatchingClientIdSchemeInRequest", className: AuthorizationRequest.className)
    }
}

func urlEncodedRequest(_ decodedRequest: String) -> String? {
    return decodedRequest.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)
}

func getQueryItems(_ encodedUrl: URL) -> [URLQueryItem]? {
    return URLComponents(url: encodedUrl, resolvingAgainstBaseURL: false)?.queryItems
}

func parseAndValidateClientMetadataInAuthorizationRequest(_ params: [String: Any]) throws -> [String: Any] {
    var mutableParams = params
    
    if let clientMetaString = params["client_metadata"] as? String {
        let clientMetadata = try ClientMetadata.deserializeAndValidate(clientMetadata: clientMetaString)
        mutableParams["client_metadata"] = clientMetadata
    }
    return mutableParams
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
        return PreRegisteredSchemeAuthRequestHandler(trustedVerifiers: trustedVerifiers, authorizationRequestParameters: authorizationRequestParameters, networkManager: networkManager, shouldValidateClient: shouldValidateClient, setResponseUri: setResponseUri)
    case ClientIdScheme.did.rawValue:
        return DidSchemeAuthRequestHandler(authorizationRequestParam: authorizationRequestParameters, networkManager: networkManager, setResponseUri: setResponseUri)
    case ClientIdScheme.redirectUri.rawValue:
        return RedirectUriSchemeAuthRequestHandler(authorizationRequestParam: authorizationRequestParameters, networkManager: networkManager, setResponseUri: setResponseUri)
    default:
        throw Logger.handleException(exceptionType: "InvalidClientIdScheme",message: "Client id scheme in request is not supported" ,className: AuthorizationRequest.className)
    }
}

func extractQueryParameters(_ input: String) -> [String: String] {
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
