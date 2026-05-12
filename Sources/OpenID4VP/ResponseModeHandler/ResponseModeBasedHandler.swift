import Foundation
import JSONWebKey

protocol ResponseModeBasedHandler {
    func validate(clientMetadata: ClientMetadata?,
                  walletConfig: WalletConfig,
                  shouldValidateWithWalletMetadata: Bool) throws
    
    func validate(clientMetadata: ClientMetadataDraft23?,
                  walletConfig: WalletConfig,
                  shouldValidateWithWalletMetadata: Bool) throws
    
    func sendAuthorizationResponse(authorizationRequest: AuthorizationRequest,
                                   authorizationResponse: AuthorizationResponse,
                                   url: String,
                                   networkManager: NetworkManaging,
                                   producerInfo: String,
                                   recipientInfo: String,
                                   walletConfig: WalletConfig
    ) async throws -> NetworkResponse
    
    func setResponseUrl(authorizationRequestParameters: [String : Any], setResponseUri: (String) -> Void) throws
    
    func getResponseEndpoint(authorizationRequest: AuthorizationRequest) throws -> String
    
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
}

extension ResponseModeBasedHandler {
    
    func setResponseUrl(authorizationRequestParameters: [String : Any], setResponseUri: (String) -> Void) throws {
        
        try validateAttribute(AuthorizationRequestFieldConstants.responseUri.rawValue, values: authorizationRequestParameters)
        
        let className = String(describing: ResponseModeBasedHandler.self)
        let responseUriValue = authorizationRequestParameters[AuthorizationRequestFieldConstants.responseUri.rawValue] as! String
        
        guard isValidUri(responseUriValue) else {
            throw InvalidData(
                message: "response_uri data is not valid",
                className: className,
                code: OpenID4VPErrorCodes.invalidRequest
            )
        }
        
        setResponseUri(responseUriValue)
    }
}
