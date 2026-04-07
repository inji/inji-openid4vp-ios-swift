import Foundation

protocol ResponseModeBasedHandler {
    func validate(clientMetadata: ClientMetadata?,
                  walletMetadata: WalletMetadata?,
                  shouldValidateWithWalletMetadata: Bool) throws
    func validate(clientMetadata: ClientMetadataV2?,
                  walletMetadata: WalletMetadataV2?,
                  shouldValidateWithWalletMetadata: Bool) throws
    
    func sendAuthorizationResponse(authorizationRequest: AuthorizationRequest,
                                   authorizationResponse: AuthorizationResponse,
                                   url: String,
                                   networkManager: NetworkManaging,
                                   producerInfo: String,
                                   recipientInfo: String
    ) async throws -> NetworkResponse
    
    func sendAuthorizationResponse(authorizationRequest: AuthorizationRequestV2,
                                   authorizationResponse: AuthorizationResponseV2,
                                   url: String,
                                   networkManager: NetworkManaging,
                                   producerInfo: String,
                                   recipientInfo: String
    ) async throws -> NetworkResponse
    
    func setResponseUrl(authorizationRequestParameters: [String : Any], setResponseUri: (String) -> Void) throws
    
    func getAuthorizationResponse(
            authorizationRequest: AuthorizationRequestV2,
            authorizationResponse: AuthorizationResponseV2,
            walletNonce: String
        ) throws -> [String: String]

        func getAuthorizationErrorResponse(
            authorizationRequest: AuthorizationRequestV2?,
            authorizationResponse: AuthorizationErrorResponse,
            walletNonce: String
        ) throws -> [String: String]
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
