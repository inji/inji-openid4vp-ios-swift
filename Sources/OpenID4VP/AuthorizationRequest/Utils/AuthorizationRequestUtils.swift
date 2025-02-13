import Foundation
import CryptoKit

func isJWT(_ authorizationRequest: String) -> Bool {
    return authorizationRequest.split(separator: ".").count == 3
}

func determineHttpMethod(method: String) throws -> HTTP_METHOD {
    if method.contains("get") {
        return HTTP_METHOD.GET
    } else if method.contains("post") {
        return HTTP_METHOD.POST
    } else {
        throw Logger.handleException(exceptionType: "UnsupportedHttpMethod", message: method, className: AuthorizationRequest.className)
    }
}

func extractQueryParams(from queryItems: [URLQueryItem]) throws -> [String: String] {
    var extractedValues: [String: String] = [:]
    
    for queryItem in queryItems {
        extractedValues[queryItem.name] = queryItem.value
    }
    return extractedValues
}

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
        
    } else if hasPresentationDefinitionUri, let value = params["presentation_definition_uri"] {
        guard let valueStr = getStringValue(value), isNeitherNullNorEmpty(field: valueStr), valueStr != "null" else {
            throw Logger.handleException(
                exceptionType: "InvalidInput",
                fieldPath: ["presentation_definition_uri"],
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
        
        presentationDefinitionString = try await networkManager.sendHTTPRequest(
            url: url, method: .GET, bodyParams: nil, headers: nil
        ) ?? ""
        
    } else {
        throw Logger.handleException(
            exceptionType: "InvalidQueryParams",
            message: "Either presentation_definition or presentation_definition_uri request param must be present",
            className: AuthorizationRequest.className
        )
    }
    
    let presentationDefinition = try PresentationDefinitionValidator.validate(presentatioDefinition: presentationDefinitionString)
    
    var mutableParams = params
    mutableParams["presentation_definition"] = presentationDefinition
    
    return mutableParams
}

func validateKey(
    _ key: String,
    values: [String: Any],
    setResponseUri: (String) -> Void
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
    
    if key == "response_uri", let responseUri = value as? String {
        setResponseUri(responseUri)
    }
}

func commonRequiredKeys(params: [String: Any]) -> [String] {
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
    redirectUri: Any?,
    responseUri: Any?,
    responseMode: Any?
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
    redirectUri: Any?,
    responseUri: Any?,
    responseMode: Any?
) {
    if redirectUri != nil, responseUri == nil, responseMode == nil {
        requiredKeys.append("redirect_uri")
    }
    if responseUri != nil, responseMode != nil, redirectUri == nil {
        requiredKeys.append(contentsOf: ["response_uri", "response_mode"])
    }
}

func validateVerifier(verifierList: [Verifier], params: [String: Any],shouldValidateClient: Bool) throws {
    
    let clientIdScheme = getStringValue(params["client_id_scheme"] ?? "")
    let clientId = getStringValue(params["client_id"] ?? "")
    
    if clientIdScheme == ClientIdScheme.preRegistered.rawValue {
        
        if shouldValidateClient {
            guard !verifierList.isEmpty else {
                throw Logger.handleException(exceptionType: "EmptyVerifierList", className: AuthorizationRequest.className)
            }
            
            guard verifierList.contains(where: { $0.clientId == clientId && $0.responseUris.contains(getStringValue(params["response_uri"])!) }) else {
                throw Logger.handleException(exceptionType: "InvalidVerifierClientID", className: AuthorizationRequest.className)
            }
        }
    }
    
    if clientIdScheme == ClientIdScheme.redirectUri.rawValue {
        
        guard params["response_uri"] == nil, params["response_mode"] == nil else {
            throw Logger.handleException(exceptionType: "InvalidQueryParams", message: "Response Uri and Response mode should not be present, when client id scheme is Redirect Uri", className: AuthorizationRequest.className)
        }
        
        if params["redirect_uri"] != nil {
            guard getStringValue(params["redirect_uri"] ?? "") == clientId else {
                throw Logger.handleException(exceptionType: "InvalidVerifierRedirectUri", className: AuthorizationRequest.className)
            }
        }
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
    
    guard let clientMetaString = params["client_metadata"] as? String else {
        return mutableParams
    }
    
    let clientMetadata = try ClientMetadata.deserializeAndValidate(clientMetadata: clientMetaString)
    
    if let responseMode = params["response_mode"] as? String,
       responseMode == ResponseMode.directPostJwt.rawValue {
        guard clientMetadata.jwks != nil,
              clientMetadata.authorization_encrypted_response_alg != nil,
              clientMetadata.authorization_encrypted_response_enc != nil else {
            throw Logger.handleException(
                exceptionType: "MissingInputsInClientMetadataForResponseModeDirectPostJwt",
                className: AuthorizationRequest.className
            )
        }
    }
    
    mutableParams["client_metadata"] = clientMetadata
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
