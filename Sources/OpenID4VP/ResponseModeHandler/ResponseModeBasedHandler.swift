import Foundation
import JSONWebKey

protocol ResponseModeBasedHandler {
    func validate(clientMetadata: ClientMetadata?,
                  walletConfig: WalletConfig,
                  shouldValidateWithWalletMetadata: Bool) throws -> ResponseEncryptionSpecification?
    
    func validate(clientMetadata: ClientMetadataDraft23?,
                  walletConfig: WalletConfig,
                  shouldValidateWithWalletMetadata: Bool) throws -> ResponseEncryptionSpecification?
    
    func sendAuthorizationResponse(authorizationRequest: AuthorizationRequest,
                                   authorizationResponse: AuthorizationResponse,
                                   url: String,
                                   networkManager: NetworkManaging,
                                   producerInfo: String,
                                   recipientInfo: String,
                                   walletConfig: WalletConfig
    ) async throws -> NetworkResponse
    
    func setResponseUrl(authorizationRequestParameters: [String : Any]) throws -> String
    
    func getResponseEndpoint(authorizationRequestParameters: [String : Any]) throws -> String
    
    func getAuthorizationResponse(
        authorizationRequest: AuthorizationRequest,
        authorizationResponse: AuthorizationResponse,
        walletNonce: String,
        walletConfig: WalletConfig
    ) throws -> [String: String]
    
    func getAuthorizationErrorResponse(
        authorizationRequest: AuthorizationRequest?,
        authorizationResponse: AuthorizationErrorResponse,
        walletNonce: String
    ) throws -> [String: String]
    
    func getVerifierPublicKeyForEncryption(
        authorizationRequest: AuthorizationRequest,
        walletConfig: WalletConfig
    ) throws -> JWK?
    
    /// Constructs an authorization error response body as per response mode.
    func getAuthorizationErrorResponse(
        dispatchInfo: ResponseDispatchInfo,
        authorizationResponse: AuthorizationErrorResponse
    ) throws -> [String: String]
    
    /// Sends an authorization error response to the verifier.
    func sendAuthorizationError(
        dispatchInfo: ResponseDispatchInfo,
        authorizationResponse: AuthorizationErrorResponse,
        networkManager: NetworkManaging
    ) async throws -> NetworkResponse
    
    /// Constructs an authorization response body as per response mode.
    func getAuthorizationResponse(
        dispatchInfo: ResponseDispatchInfo,
        authorizationResponse: AuthorizationResponse
    ) throws -> [String: String]
    
    /// Sends an authorization response to the verifier.
    func sendAuthorizationResponse(
        dispatchInfo: ResponseDispatchInfo,
        authorizationResponse: AuthorizationResponse,
        networkManager: NetworkManaging
    ) async throws -> NetworkResponse
}

extension ResponseModeBasedHandler {
    
    func setResponseUrl(authorizationRequestParameters: [String : Any]) throws -> String {
        
        try validateAttribute(AuthorizationRequestFieldConstants.responseUri, values: authorizationRequestParameters)
        
        let className = String(describing: ResponseModeBasedHandler.self)
        let responseUriValue = authorizationRequestParameters[AuthorizationRequestFieldConstants.responseUri] as! String
        
        guard isValidUri(responseUriValue) else {
            throw InvalidData(
                message: "response_uri data is not valid",
                className: className,
                code: OpenID4VPErrorCodes.invalidRequest
            )
        }
        
        return responseUriValue
    }
    
    func getResponseEndpoint(authorizationRequestParameters: [String : Any]) throws -> String {
        try validateAttribute(AuthorizationRequestFieldConstants.responseUri, values: authorizationRequestParameters)
        
        let className = String(describing: ResponseModeBasedHandler.self)
        let responseUriValue = authorizationRequestParameters[AuthorizationRequestFieldConstants.responseUri] as! String
        
        guard isValidUri(responseUriValue) else {
            throw InvalidData(
                message: "response_uri data is not valid",
                className: className,
                code: OpenID4VPErrorCodes.invalidRequest
            )
        }
        
        return responseUriValue
    }
}
