import Foundation
import JSONWebSignature
import CryptoKit

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
    
    static func validateAndGetAuthorizationRequest(encodedAuthorizationRequest: String, setResponseUri: (String) -> Void, shouldValidateClient: Bool, trustedVerifierJSON: [Verifier], networkManager: NetworkManaging, walletMetadata: String?) async throws -> AuthorizationRequest {
        
        guard let queryStart = encodedAuthorizationRequest.firstIndex(of: "?") else {
            throw Logger.handleException(exceptionType: "InvalidQueryParams", message: "Query parameters are missing in the Authorization request", className: AuthorizationRequest.className)
        }
        let encodedString = String(encodedAuthorizationRequest[encodedAuthorizationRequest.index(after: queryStart)...])
        
        guard let decodedQuery = decodeBase64ToString(encodedString) else {
            throw Logger.handleException(exceptionType: "Decoding", fieldPath: ["Authorization Request"], className: AuthorizationRequest.className)
        }
        var authorizationRequestParams = try await parseAuthorizationRequest(queryString: decodedQuery, setResponseUri: setResponseUri, networkManager: networkManager, shouldValidateClient: shouldValidateClient, trustedVerifierJSON: trustedVerifierJSON, walletMetadata:walletMetadata)
        
        try validateVerifier(verifierList: trustedVerifierJSON, params: authorizationRequestParams, shouldValidateClient: shouldValidateClient)
        
        authorizationRequestParams = try validateAuthorizationRequestParams(authorizationRequestParams, setResponseUri)
        
        return createAuthorizationRequest(from: authorizationRequestParams)
    }
    
    private static func parseAuthorizationRequest(queryString: String, setResponseUri: (String) -> Void, networkManager: NetworkManaging, shouldValidateClient: Bool, trustedVerifierJSON: [Verifier], walletMetadata: String?) async throws -> [String: Any] {
        
        guard let encodedQuery = urlEncodedRequest(queryString) else {
            throw Logger.handleException(exceptionType: "UrlCreationFailed", fieldPath: ["Authorization Request"], className: AuthorizationRequest.className)
        }
        
        let uriString = "?\(encodedQuery)"
        let uri = URL(string: uriString)
        
        guard let query = getQueryItems(uri!) else {
            throw Logger.handleException(exceptionType: "InvalidQueryParams", message: "Exception occurred when extracting the query params from Authorization Request", className: AuthorizationRequest.className)
        }
        
        let params = try extractQueryParams(from: query)
        
        return try await fetchAuthorizationRequestMap(params: params, networkManager: networkManager, walletMetaData:walletMetadata)
    }
    
    private static func fetchAuthorizationRequestMap(params: [String: String], networkManager: NetworkManaging, walletMetaData: String?) async throws -> [String: Any] {
        
        
        var authorizationRequestMap = (params["request_uri"] != nil) ?
        try await fetchAuthRequestObjectByReference(
            params: params,
            requestUri: params["request_uri"]!,
            networkManager: networkManager,
            walletMetadata: walletMetaData
        ) : params
        
        authorizationRequestMap = try parseAndValidateClientMetadataInAuthorizationRequest(authorizationRequestMap)
        authorizationRequestMap = try await parseAndValidatePresentationDefinitionInAuthorizationRequest(params: authorizationRequestMap, networkManager: networkManager)
        
        return authorizationRequestMap
    }
    
    private static func fetchAuthRequestObjectByReference(params: [String: String], requestUri: String, networkManager: NetworkManaging, walletMetadata: String? = nil) async throws -> [String: Any] {
        do {
            if !isNeitherNullNorEmpty(field: requestUri) || !(requestUri != "null") {
                throw Logger.handleException(exceptionType: "InvalidInput", fieldPath: ["requestUri"], className: AuthorizationRequest.className)
            }
            let requestUriMethod = params["request_uri_method"] ?? "get"
            let httpMethod = try determineHttpMethod(method: requestUriMethod)
            
            guard let url = URL(string: params["request_uri"]!) else {
                throw Logger.handleException(exceptionType: "UrlCreationFailed", fieldPath: ["request_uri_method"], className: AuthorizationRequest.className)
            }


            var bodyParams: String? = nil
            var headerParams: [String: String]? = nil
            if let walletMetadata = walletMetadata {
                do {
                    let walletMetadatObj = try JSONDecoder().decode(WalletMetadata.self, from: walletMetadata.data(using: .utf8)!)
                    var bodyComponents = [URLQueryItem]()
                    bodyComponents.append(URLQueryItem(name: "wallet_metadata", value: encodeQueryValue(walletMetadata)))
                   
                    var urlComponents = URLComponents()
                    urlComponents.queryItems = bodyComponents

                    let requestBody = urlComponents.query
                    bodyParams = requestBody
                    
                    headerParams = [
                        "content-type": "application/x-www-form-urlencoded",
                        "accept": "application/oauth-authz-req+jwt"
                    ]
                } catch {
                    throw Logger.handleException(
                        exceptionType: "InvalidWalletMetadata",
                        fieldPath: ["walletMetadata"],
                        className: AuthorizationRequest.className
                    )
                }
                
                
            }
           
            let response = try await networkManager.sendHTTPRequest(url: url, method: httpMethod, bodyParams: bodyParams, headers: headerParams) ?? ""
            
            return try await extractAuthorizationRequestData(response: response, params: params, networkManager: networkManager)
        }
    }
    
    private static func extractAuthorizationRequestData(response: String, params: [String: String], networkManager: NetworkManaging) async throws -> [String: String] {
        
        var authorizationRequestObject: [String: String]
        
        if isJWT(response) {
            authorizationRequestObject =  try extractPayloadJsonFromJwt(jwtToken: response, jwtPart: .payload)
            
            try validateMatchOfAuthRequestObjectAndParams(params: params, requestUriParams: authorizationRequestObject)
            
            let proofJwtManager = ProofJwtManager(networkManager: networkManager)
            try await proofJwtManager.verifyJWT(jwtToken: response, clientId: authorizationRequestObject["client_id"]!, clienIdScheme: authorizationRequestObject["client_id_scheme"]!)
            
            return authorizationRequestObject
        }
        else{
            authorizationRequestObject = try decodeBase64ToJSON(makeBase64Standard(response))
            try validateMatchOfAuthRequestObjectAndParams(params: params, requestUriParams: authorizationRequestObject)
        }
        return authorizationRequestObject
    }
    
    private static func validateAuthorizationRequestParams(
        _ paramsToValidate: [String: Any],
        _ setResponseUri: (String) -> Void
    )  throws -> [String: Any] {
        let values = paramsToValidate
        var requiredKeys = commonRequiredKeys(params: values)
        
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
            try validateKey(key, values: values, setResponseUri: setResponseUri)
        }
        return values
    }
    
    private static func createAuthorizationRequest(from params: [String: Any]) -> AuthorizationRequest {
        
        return AuthorizationRequest(
            clientId: getStringValue(params["client_id"])!,
            clientIdScheme: getStringValue(params["client_id_scheme"])!,
            presentationDefinition: params["presentation_definition"]! as! PresentationDefinition,
            responseType: getStringValue(params["response_type"])!,
            responseMode: getStringValue(params["response_mode"]),
            nonce: getStringValue(params["nonce"])!,
            state: getStringValue(params["state"])!,
            redirectUri: getStringValue(params["redirect_uri"]),
            responseUri: getStringValue(params["response_uri"]),
            clientMetadata: params["client_metadata"] as? ClientMetadata
        )
    }
}
