import Foundation
import JSONWebSignature
import CryptoKit

public struct AuthorizationRequest : Encodable {
    let clientId: String
    let clientIdScheme: String
    var presentationDefinition: Any
    let responseType: String
    let responseMode: String?
    let nonce: String
    let state: String?
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
    
    static func validateAndCreateAuthorizationRequest(urlEncodedAuthorizationRequest: String, setResponseUri: @escaping (String) -> Void, shouldValidateClient: Bool, trustedVerifierJSON: [Verifier], networkManager: NetworkManaging) async throws -> AuthorizationRequest {
        let extractedQueryParameters = try extractQueryParameters(urlEncodedAuthorizationRequest)
        
        return try await getAuthorizationRequest(authorizationRequestParameters: extractedQueryParameters, trustedVerifiers: trustedVerifierJSON, shouldValidateClient: shouldValidateClient, networkManager: networkManager, setResponseUri: setResponseUri)
    }
    
    private static func getAuthorizationRequest(authorizationRequestParameters : [String:Any],trustedVerifiers : [Verifier], shouldValidateClient: Bool, networkManager: NetworkManaging,setResponseUri: @escaping (String) -> Void) async throws -> AuthorizationRequest{
        let authorizationRequestHandler = try getAuthorizationRequestHandler(trustedVerifiers: trustedVerifiers, authorizationRequestParameters: authorizationRequestParameters, shouldValidateClient: shouldValidateClient, networkManager: networkManager, setResponseUri: setResponseUri)
        
        try await processAndValidateAuthorizationRequestParameter( authorizationRequestHandler)
        
        return authorizationRequestHandler.createAuthorizationRequest()
    }
    
    private static func processAndValidateAuthorizationRequestParameter(_ authorizationRequestHandler: ClientIdSchemeBasedAuthorizationRequestHandler)async throws {
        try authorizationRequestHandler.validateClientId()
        try await authorizationRequestHandler.fetchAuthorizationRequest()
        try authorizationRequestHandler.setResponseUrl()
        try await authorizationRequestHandler.validateAndParseRequestFields()
    }
}
