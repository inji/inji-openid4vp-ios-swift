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
    
    static func validateAndGetAuthorizationRequest(encodedAuthorizationRequest: String, setResponseUri: @escaping (String) -> Void, shouldValidateClient: Bool, trustedVerifierJSON: [Verifier], networkManager: NetworkManaging) async throws -> AuthorizationRequest {
        let authorizationRequestParams: [String: Any]
        do {
            guard let queryStart = encodedAuthorizationRequest.firstIndex(of: "?") else {
                throw Logger.handleException(exceptionType: "InvalidQueryParams", message: "Query parameters are missing in the Authorization request", className: AuthorizationRequest.className)
            }
            let encodedString = String(encodedAuthorizationRequest[encodedAuthorizationRequest.index(after: queryStart)...])
            
            guard let decodedQuery = decodeBase64ToString(encodedString) else {
                throw Logger.handleException(exceptionType: "Decoding", fieldPath: ["Authorization Request"], className: AuthorizationRequest.className)
            }
            var extractedQueryParameters = try extractTheQueryParams(decodedQuery)
            
            authorizationRequestParams = try await getAuthorizationRequestObjectMap(authRequestParams: extractedQueryParameters, trustedVerifiers: trustedVerifierJSON, shouldValidateClient: shouldValidateClient, networkManager: networkManager, setResponseUri: setResponseUri)

        } catch {
            throw error
        }
        
        return createAuthorizationRequest(from: authorizationRequestParams)
    }
    
    private static func getAuthorizationRequestObjectMap(authRequestParams : [String:Any],trustedVerifiers : [Verifier], shouldValidateClient: Bool, networkManager: NetworkManaging,setResponseUri: @escaping (String) -> Void) async throws -> [String: Any]{
        let authorizationRequestHandler = try getAuthRequestHandler(trustedVerifiers: trustedVerifiers, authRequestParams: authRequestParams, shouldValidateClient: shouldValidateClient, networkManager: networkManager, setResponseUri: setResponseUri)
        
        try await processAndValidateAuthorizationRequestParameter( authorizationRequestHandler)
        
        return authorizationRequestHandler.authRequestParam
    }
    
    private static func processAndValidateAuthorizationRequestParameter(_ authRequestHandler: ClientIdSchemeBasedAuthRequestHandler)async throws {
        try authRequestHandler.validateClientId()
        try await authRequestHandler.gatherAuthRequest()
        try authRequestHandler.gatherInfoForSendingResponseToVerifier()
        try await authRequestHandler.validateAndParseRequestFields()
    }
    
    private static func extractTheQueryParams(_ query: String) throws  -> [String: String]{
        guard let encodedQuery = urlEncodedRequest(query) else {
            throw Logger.handleException(exceptionType: "UrlCreationFailed", fieldPath: ["Authorization Request"], className: AuthorizationRequest.className)
        }
        
        let uriString = "?\(encodedQuery)"
        let uri = URL(string: uriString)
        
        guard let queryItems = getQueryItems(uri!) else {
            throw Logger.handleException(exceptionType: "InvalidQueryParams", message: "Exception occurred when extracting the query params from Authorization Request", className: AuthorizationRequest.className)
        }
        
        var extractedValues: [String: String] = [:]
        
        for queryItem in queryItems {
            extractedValues[queryItem.name] = queryItem.value
        }
        return extractedValues
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
