import Foundation

class PreRegisteredSchemeAuthorizationRequestHandler:  ClientIdSchemeBasedAuthorizationRequestHandler {
    let trustedVerifiers: [Verifier]
    let shouldValidateClient: Bool
    
    init(trustedVerifiers: [Verifier],
         authorizationRequestParameters: [String: Any],
         walletMetadata: WalletMetadata?,
         shouldValidateClient: Bool,
         setResponseUri: @escaping (String) -> Void,
         walletNonce: String,
         networkManager: NetworkManaging) {
        self.trustedVerifiers = trustedVerifiers
        self.shouldValidateClient = shouldValidateClient
        super.init(authorizationRequestParameters: authorizationRequestParameters,
                   walletMetadata: walletMetadata,
                   setResponseUri: setResponseUri,
                   walletNonce: walletNonce,
                   networkManager: networkManager)
        delegate = self
        super.className = String(describing: PreRegisteredSchemeAuthorizationRequestHandler.self)
    }
    
    override func validateClientId() throws {
        if shouldValidateClient {
            guard trustedVerifiers.contains(where: { $0.clientId == authorizationRequestParameters[AuthorizationRequestFieldConstants.clientId.rawValue] as! String }) else {
                throw InvalidVerifier(message: "Verifier is not trusted by the wallet", className: AuthorizationRequest.className)
            }
        }
    }
    
    func process(walletMetadata: WalletMetadata) -> WalletMetadata {
        var updatedWalletMetadata = walletMetadata
        updatedWalletMetadata.requestObjectSigningAlgValuesSupported = nil
        return updatedWalletMetadata
    }
    
    func getHeadersForAuthorizationRequestUri() -> [String : String]? {
        return [Header.contentType.rawValue: ContentTypes.applicationFormUrlEncoded.rawValue,
                Header.accept.rawValue: ContentTypes.applicationJson.rawValue]
    }
    
    func validateRequestUriResponse(requestUriResponse: (body: String, httpUrlResponse: HTTPURLResponse)?,walletNonce: String, isMismatchedAcceptableType: Bool) async throws {
        if (isMismatchedAcceptableType) {
            throw InvalidData(
                message: "Authorization Request must not be signed for given client_id_scheme",
                className: className
            )
        }
        
        if let requestUriResponse = requestUriResponse {
            let isContentTypeNotJson = !requestUriResponse.httpUrlResponse.isHeaderContentType(equalTo: ContentTypes.applicationJson.rawValue)
            
            if (isContentTypeNotJson || isJWS(requestUriResponse.body)) {
                throw InvalidData(
                    message: "Authorization Request must not be signed for given client_id_scheme",
                    className: className
                )
            }
            
            guard let responseBody = requestUriResponse.body.data(using: .utf8) else {
                throw InvalidData(
                    message: "Conversion failed",
                    className: className
                )
            }
            guard let authorizationRequestObject = try JSONSerialization.jsonObject(with: responseBody, options: []) as? [String: Any]  else {
                throw InvalidData(
                    message: "Conversion failed",
                    className: className
                )
            }
            
            // wallet_nonce is passed in the POST request to request_uri,so the Request URI response must have wallet_nonce and Wallet MUST validate whether the request object contains the respective nonce value in a wallet_nonce claim.
            let requestUriMethod = try determineHttpMethod(method: authorizationRequestParameters[AuthorizationRequestFieldConstants.requestUriMethod.rawValue] as? String ?? HttpMethod.get.rawValue)
            if( requestUriMethod == .post) {
                try validateWalletNonce(authorizationRequestObject, walletNonce)
            }
            
            try validateAuthorizationRequestObjectAndParameters(params: authorizationRequestParameters as! [String : String], requestUriParams: authorizationRequestObject)
            
            authorizationRequestParameters = authorizationRequestObject
        }
    }
    
    override func validateAndParseRequestFields()async throws {
        if shouldValidateClient {
            let clientId = authorizationRequestParameters[AuthorizationRequestFieldConstants.clientId.rawValue] as! String
            if let preRegisteredClient = trustedVerifiers.filter({ $0.clientId == clientId }).first {
                let responseUri = getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.responseUri.rawValue]) ?? "null"
                guard preRegisteredClient.responseUris.contains(responseUri) else {
                    throw InvalidVerifier(
                        message: "response_uri trust cannot be established",
                        className: AuthorizationRequest.className
                    )
                }
                if(preRegisteredClient.clientMetadata != nil && authorizationRequestParameters.keys.contains(AuthorizationRequestFieldConstants.clientMetadata.rawValue)){
                    throw InvalidVerifier(
                        message: "client_metadata provided despite pre-registered metadata already existing for the Client Identifier.",
                        className: AuthorizationRequest.className
                    )
                }
            }
        }
        try await super.validateAndParseRequestFields()
    }
}
