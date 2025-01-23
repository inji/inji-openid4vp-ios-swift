import Foundation
import JSONWebSignature
import CryptoKit

extension Dictionary where Key == String, Value == String {
    func values(forKeys keys: [String]) -> [String]? {
        let values = keys.compactMap { self[$0] }
        return values.count == keys.count ? values : nil
    }
}

public struct AuthorizationRequest: Encodable {
    let clientId: String
    let clientIdScheme: String
    var presentationDefinition: Any
    let responseType: String
    let responseMode: String?
    let nonce: String
    let state: String
    let redirectUri: String?
    let responseUri: String?
    var clientMetadata: Any?
    static let className = String(describing: AuthorizationRequest.self)
    static var authorizationRequest: AuthorizationRequest?
    
    enum CodingKeys: String, CodingKey {
        case client_id
        case client_id_scheme
        case presentation_definition
        case response_type
        case response_mode
        case nonce
        case state
        case redirect_uri
        case response_uri
        case client_metadata
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(clientId, forKey: .client_id)
        try container.encode(clientIdScheme, forKey: .client_id_scheme)
        if let presentationDefString = presentationDefinition as? String {
            try container.encode(presentationDefString, forKey: .presentation_definition)
        } else if let presentationDefObject = presentationDefinition as? PresentationDefinition {
            try container.encode(presentationDefObject, forKey: .presentation_definition)
        }
        try container.encode(responseType, forKey: .response_type)
        try container.encode(responseMode, forKey: .response_mode)
        try container.encode(nonce, forKey: .nonce)
        try container.encode(state, forKey: .state)
        try container.encode(responseUri, forKey: .response_uri)
        try container.encode(redirectUri, forKey: .redirect_uri)
        if let clientMetadataString = clientMetadata as? String {
            try container.encode(clientMetadataString, forKey: .client_metadata)
        } else if let clientMetadataObject = clientMetadata as? ClientMetadata {
            try container.encode(clientMetadataObject, forKey: .client_metadata)
        }
    }
    
    static func validateAndGetAuthorizationRequest(encodedAuthorizationRequest: String, setResponseUri: (String) -> Void, shouldValidateClient: Bool, trustedVerifierJSON: [Verifier], networkManager: NetworkManaging) async throws -> AuthorizationRequest {
        
        let requestParts = encodedAuthorizationRequest.components(separatedBy: "?")
        guard requestParts.count > 1 else {
            throw Logger.handleException(exceptionType: "InvalidQueryParams", message: "Query parameters are missing in the Authorization request", className: AuthorizationRequest.className)
        }
        
        let baseUrl = requestParts[0]
        let encodedQuery = requestParts[1]
        
        if isJWT(encodedQuery) {
            
            let requestJson = try extractPayloadJsonFromJwt(jwtToken: encodedQuery)
            
            if(shouldValidateClient){
                let proofJwtManager = ProofJwtManager(networkManager: networkManager)
                try await proofJwtManager.verifyJWT(jwtToken: encodedQuery, clientId: requestJson["client_id"]!, clienIdScheme: requestJson["client_id_scheme"]!)
            }
            
            let params = try await validateQueryParams(requestJson,setResponseUri,networkManager)
            
            authorizationRequest = createAuthorizationRequest(from: params)
            
        } else {
            guard let decodedQuery = decodeAuthorizationRequest(encodedQuery) else {
                throw Logger.handleException(exceptionType: "Decoding", fieldPath: ["Authorization Request"], className: AuthorizationRequest.className)
            }
            let decodedRequest = "\(baseUrl)?\(decodedQuery)"
            
            authorizationRequest = try await parseAuthorizationRequest(decodedAuthorizationRequest: decodedRequest, setResponseUri: setResponseUri, networkManager: networkManager)
            
            if(shouldValidateClient){
                try validateVerifier(verifierList: trustedVerifierJSON, authorizationRequest: authorizationRequest!)
            }
        }
        return authorizationRequest!
    }
    
    private static func parseAuthorizationRequest(decodedAuthorizationRequest: String, setResponseUri: (String) -> Void, networkManager: NetworkManaging) async throws -> AuthorizationRequest {
        
        guard let encodedRequestUrl = urlEncodedRequest(decodedAuthorizationRequest) else {
            throw Logger.handleException(exceptionType: "UrlCreationFailed", fieldPath: ["Authorization Request"], className: AuthorizationRequest.className)
        }
        
        guard let queryItems = getQueryItems(encodedRequestUrl) else {
            throw Logger.handleException(exceptionType: "InvalidQueryParams", message: "Exception occurred when extracting the query params from Authorization Request", className: AuthorizationRequest.className)
        }
        
        var params = try extractQueryParams(from: queryItems)
        
        params = try await validateQueryParams(params,setResponseUri,networkManager)
        
        return createAuthorizationRequest(from: params)
    }
    
    private static func extractQueryParams(from queryItems: [URLQueryItem]) throws -> [String: String] {
        var extractedValues: [String: String] = [:]
        
        for queryItem in queryItems {
            extractedValues[queryItem.name] = queryItem.value
        }
        
        return extractedValues
    }
    
    private static func fetchPresentationDefinition(params: [String: String], networkManager: NetworkManaging) async throws -> String{
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
    
    
    private static func validateQueryParams(
        _ paramsToValidate: [String: String],
        _ setResponseUri: (String) -> Void,
        _ networkManager: NetworkManaging
    ) async throws -> [String: String] {
        var values = paramsToValidate
        var requiredKeys = baseRequiredKeys(params: values)
        
        try validateUriCombinations(
            redirectUri: values["redirect_uri"],
            responseUri: values["response_uri"],
            responseMode: values["response_mode"]
        )
        
        updateRequiredKeys(
            &requiredKeys,
            redirectUri: values["redirect_uri"],
            responseUri: values["response_uri"],
            responseMode: values["response_mode"]
        )
        
        for key in requiredKeys {
            try await validateKey(key, values: &values, networkManager: networkManager, setResponseUri: setResponseUri)
        }
        
        return values
    }
    
    private static func baseRequiredKeys(params: [String: String]) -> [String] {
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
    
    private static func validateUriCombinations(
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
    
    private static func updateRequiredKeys(
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
    
    private static func validateKey(
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
    
}
