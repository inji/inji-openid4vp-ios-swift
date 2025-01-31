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
        
        guard let decodedQuery = decodeAuthorizationRequest(encodedQuery) else {
            throw Logger.handleException(exceptionType: "Decoding", fieldPath: ["Authorization Request"], className: AuthorizationRequest.className)
        }
        
        let decodedRequest = "\(baseUrl)?\(decodedQuery)"
        
        return try await parseAuthorizationRequest(decodedAuthorizationRequest: decodedRequest, setResponseUri: setResponseUri, networkManager: networkManager, shouldValidateClient: shouldValidateClient, trustedVerifierJSON: trustedVerifierJSON)
    }
    
    private static func parseAuthorizationRequest(decodedAuthorizationRequest: String, setResponseUri: (String) -> Void, networkManager: NetworkManaging, shouldValidateClient: Bool, trustedVerifierJSON: [Verifier]) async throws -> AuthorizationRequest {
        
        guard let encodedRequestUrl = urlEncodedRequest(decodedAuthorizationRequest) else {
            throw Logger.handleException(exceptionType: "UrlCreationFailed", fieldPath: ["Authorization Request"], className: AuthorizationRequest.className)
        }
        
        guard let queryItems = getQueryItems(encodedRequestUrl) else {
            throw Logger.handleException(exceptionType: "InvalidQueryParams", message: "Exception occurred when extracting the query params from Authorization Request", className: AuthorizationRequest.className)
        }
        
        var params = try extractQueryParams(from: queryItems)
        
        let authRequestParams = try await fetchAuthRequestData(params: params, networkManager: networkManager)
        
        params = try await validateQueryParams(authRequestParams,setResponseUri,networkManager)
        
        let authorizationRequestObj = createAuthorizationRequest(from: params)
        
        try validateVerifier(verifierList: trustedVerifierJSON, authorizationRequest: authorizationRequestObj, shouldValidateClient: shouldValidateClient)
        
        return authorizationRequestObj
        
    }
    
    private static func fetchAuthRequestData(params: [String: String], networkManager: NetworkManaging) async throws -> [String: String] {
        guard let requestUri = params["request_uri"] else {
            return params
        }
        do {
            if !isNeitherNullNorEmpty(field: requestUri) || !(requestUri != "null") {
                throw Logger.handleException(exceptionType: "InvalidInput", fieldPath: ["requestUri"], className: AuthorizationRequest.className)
            }
            let requestUriMethod = params["request_uri_method"] ?? "get HTTP/1.1"
            let httpMethod = try determineHttpMethod(method: requestUriMethod)
            
            guard let url = URL(string: params["request_uri"]!) else {
                throw Logger.handleException(exceptionType: "UrlCreationFailed", fieldPath: ["request_uri_method"], className: AuthorizationRequest.className)
            }
            
            let authorizationRequestParams = try await networkManager.sendHTTPRequest(url: url, method: httpMethod, bodyParams: nil, headers: nil) ?? ""
            
            let resquestUriParams =  try await processResponseAndFetchAuthRequestParams(authorizationRequest: authorizationRequestParams, networkManager: networkManager)
            
            try validateQRRequestParamsAndRetrievedRequestParams(params: params, requestUriParams: resquestUriParams)
            
            return resquestUriParams
        } catch {
            throw error
        }
    }
    
    private static func processResponseAndFetchAuthRequestParams(authorizationRequest: String, networkManager: NetworkManaging) async throws -> [String: String] {
        if authorizationRequest.components(separatedBy: ".").count == 3 {
            let authRequestParamaeters =  try extractPayloadJsonFromJwt(jwtToken: authorizationRequest)
            
            let proofJwtManager = ProofJwtManager(networkManager: networkManager)
            try await proofJwtManager.verifyJWT(jwtToken: authorizationRequest, clientId: authRequestParamaeters["client_id"]!, clienIdScheme: authRequestParamaeters["client_id_scheme"]!)
            
            return authRequestParamaeters
        }
        else{
            let str = makeBase64Standard(authorizationRequest)
            return try decodeBase64ToJSON(str)
        }
    }
    
    private static func extractQueryParams(from queryItems: [URLQueryItem]) throws -> [String: String] {
        var extractedValues: [String: String] = [:]
        
        for queryItem in queryItems {
            extractedValues[queryItem.name] = queryItem.value
        }
        return extractedValues
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

    private static func createAuthorizationRequest(from params: [String: String]) -> AuthorizationRequest {
        return AuthorizationRequest(
            clientId: params["client_id"]!,
            clientIdScheme: params["client_id_scheme"]!,
            presentationDefinition: params["presentation_definition"]!,
            responseType: params["response_type"]!,
            responseMode: params["response_mode"],
            nonce: params["nonce"]!,
            state: params["state"]!,
            redirectUri: params["redirect_uri"],
            responseUri: params["response_uri"],
            clientMetadata: params["client_metadata"]
        )
    }
}
