import Foundation
import CryptoKit

func isJWT(_ encodedString: String) -> Bool{
    return encodedString.contains(".") ? true : false
}

func determineHttpMethod(method: String) throws -> HTTP_METHOD {
    if method.contains("get") {
        return HTTP_METHOD.GET
    } else if method.contains("post") {
        return HTTP_METHOD.POST
    } else {
        throw NSError(domain: "UnsupportedMethod", code: 2,
                      userInfo: ["description": "Unsupported HTTP method: \(method)"])
    }
}

func fetchPresentationDefinition(params: [String: String], networkManager: NetworkManaging) async throws -> String{
    let hasPresentationDefinition = params.keys.contains("presentation_definition")
    let hasPresentationDefinitionUri = params.keys.contains("presentation_definition_uri")
    let presentationDefinition: String
    
    if hasPresentationDefinition && hasPresentationDefinitionUri {
        throw Logger.handleException(exceptionType: "InvalidQueryParams", message: "Either presentation_definition or presentation_definition_uri request param can be provided but not both", className: AuthorizationRequest.className)
        
    } else if(hasPresentationDefinition){
        
        let value = params["presentation_definition"]!
        if !isNeitherNullNorEmpty(field: value) && !(value != "null") {
            throw Logger.handleException(exceptionType: "InvalidInput", fieldPath: ["presentation_definition"], className: AuthorizationRequest.className)
        }
        presentationDefinition = params["presentation_definition"]!
        
    }else if(hasPresentationDefinitionUri){
        
        let value = params["presentation_definition_uri"]!
        
        if !isNeitherNullNorEmpty(field: value) && !(value != "null") {
            throw Logger.handleException(exceptionType: "InvalidInput", fieldPath: ["presentation_definition_uri"], className: AuthorizationRequest.className)
        }
        
        guard let url = URL(string: params["presentation_definition_uri"]!) else {
            throw Logger.handleException(exceptionType: "UrlCreationFailed", fieldPath: ["presentation_definition_uri"], className: AuthorizationRequest.className)
        }
        
        presentationDefinition = try await networkManager.sendHTTPRequest(url: url, method: HTTP_METHOD.GET, bodyParams: nil, headers: nil) ?? ""
        
    }else {
        throw Logger.handleException(exceptionType: "InvalidQueryParams", message: "Either presentation_definition or presentation_definition_uri request param must be present", className: AuthorizationRequest.className)
    }
    return presentationDefinition
}

func validateKey(
    _ key: String,
    values: inout [String: String],
    networkManager: NetworkManaging,
    setResponseUri: (String) -> Void
) async throws {
    if key == "presentation_definition" {
        values[key] = try await fetchPresentationDefinition(params: values, networkManager: networkManager)
    }
    
    guard let value = values[key], isNeitherNullNorEmpty(field: value), value != "null" else {
        throw Logger.handleException(
            exceptionType: values[key] == nil ? "MissingInput" : "InvalidInput",
            fieldPath: [key],
            className: AuthorizationRequest.className
        )
    }
    
    if key == "response_uri" {
        setResponseUri(value)
    }
}

func baseRequiredKeys(params: [String: String]) -> [String] {
    var keys = [
        "presentation_definition",
        "client_id",
        "client_id_scheme",
        "response_type",
        "nonce",
        "state"
    ]
    
    if params["client_metadata"] != nil {
        keys.append("client_metadata")
    }
    return keys
}

func validateUriCombinations(
    redirectUri: String?,
    responseUri: String?,
    responseMode: String?
) throws {
    let allNil = redirectUri == nil && responseUri == nil && responseMode == nil
    let allPresent = redirectUri != nil && responseUri != nil && responseMode != nil
    
    if allNil {
        throw Logger.handleException(
            exceptionType: "MissingInput",
            fieldPath: ["response_uri", "response_mode", "redirect_uri"],
            className: AuthorizationRequest.className
        )
    }
    if allPresent {
        throw Logger.handleException(
            exceptionType: "InvalidInput",
            fieldPath: ["response_uri", "response_mode", "redirect_uri"],
            className: AuthorizationRequest.className
        )
    }
}

func updateRequiredKeys(
    _ requiredKeys: inout [String],
    redirectUri: String?,
    responseUri: String?,
    responseMode: String?
) {
    if redirectUri != nil, responseUri == nil, responseMode == nil {
        requiredKeys.append("redirect_uri")
    }
    if responseUri != nil, responseMode != nil, redirectUri == nil {
        requiredKeys.append(contentsOf: ["response_uri", "response_mode"])
    }
}

func validateVerifier(verifierList: [Verifier], authorizationRequest: AuthorizationRequest,shouldValidateClient: Bool) throws {
    
    let clientIdScheme = authorizationRequest.clientIdScheme
    let clientId = authorizationRequest.clientId
    let redirectUri = authorizationRequest.redirectUri
    
    if clientIdScheme == ClientIdScheme.preRegistered.rawValue {
        
        if shouldValidateClient {
            guard !verifierList.isEmpty else {
                throw Logger.handleException(exceptionType: "EmptyVerifierList", className: AuthorizationRequest.className)
            }
            
            guard verifierList.contains(where: { $0.clientId == clientId && $0.responseUris.contains(authorizationRequest.responseUri!) }) else {
                throw Logger.handleException(exceptionType: "InvalidVerifierClientID", className: AuthorizationRequest.className)
            }
        }
    }
    
    if clientIdScheme == ClientIdScheme.redirectUri.rawValue {
        
        guard authorizationRequest.responseUri == nil, authorizationRequest.responseMode == nil else {
            throw Logger.handleException(exceptionType: "InvalidQueryParams", message: "Response Uri and Response mode should not be present, when client id scheme is Redirect Uri", className: AuthorizationRequest.className)
        }
        
        if (redirectUri != nil) {
            guard redirectUri == clientId else {
                throw Logger.handleException(exceptionType: "InvalidVerifierRedirectUri", className: AuthorizationRequest.className)
            }
        }
    }
}

func validateQRRequestParamsAndRetrievedRequestParams(params: [String: String], requestUriParams: [String: String]) throws {
    guard params["client_id"] == requestUriParams["client_id"] else {
        throw Logger.handleException(exceptionType: "MismatchingClientIDInRequest", className: AuthorizationRequest.className)
    }
    
    guard params["client_id_scheme"] == requestUriParams["client_id_scheme"] else {
        throw Logger.handleException(exceptionType: "MismatchingClientIdSchemeInRequest", className: AuthorizationRequest.className)
    }
}

func decodeAuthorizationRequest(_ encodedAuthorizationRequest: String) -> String? {
    return Data(base64Encoded: encodedAuthorizationRequest)
        .flatMap { String(data: $0, encoding: .utf8) }
}

func urlEncodedRequest(_ decodedRequest: String) -> URL? {
    return decodedRequest.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)
        .flatMap { URL(string: $0) }
}

func getQueryItems(_ encodedUrl: URL) -> [URLQueryItem]? {
    return URLComponents(url: encodedUrl, resolvingAgainstBaseURL: false)?.queryItems
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
