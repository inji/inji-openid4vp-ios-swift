import Foundation
class RedirectUriSchemeAuthorizationRequestHandler:  ClientIdSchemeBasedAuthorizationRequestHandler {
    override init(authorizationRequestParameters: [String: Any],
                  walletMetadata: WalletMetadata?,
                  setResponseUri: @escaping (String) -> Void,
                  walletNonce: String,
                  networkManager: NetworkManaging) {
        super.init(authorizationRequestParameters: authorizationRequestParameters,
                   walletMetadata: walletMetadata,
                   setResponseUri: setResponseUri,
                   walletNonce: walletNonce,
                   networkManager: networkManager)
        delegate = self
        super.className = String(describing: RedirectUriSchemeAuthorizationRequestHandler.self)
    }
    
    func isRequestUriSupported() -> Bool {
        return false
    }
    
    func validateRequestUriResponse(requestUriResponse:  (body: String, httpUrlResponse: HTTPURLResponse)?,walletNonce: String, isMismatchedAcceptableType: Bool) async throws {
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
            
            self.authorizationRequestParameters = authorizationRequestObject
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
    
    override func validateAndParseRequestFields()async throws {
        try await super.validateAndParseRequestFields()
        let responseMode = getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.responseMode.rawValue])
        switch responseMode {
        case ResponseMode.directPost.rawValue, ResponseMode.directPostJwt.rawValue:
            try validateUriCombinations(authorizationRequestParameters: authorizationRequestParameters, validAttribute: AuthorizationRequestFieldConstants.responseUri.rawValue, inValidAttribute: AuthorizationRequestFieldConstants.redirectUri.rawValue)
        default:
            throw InvalidResponseMode(
                message : "Given response_mode \(String(describing: responseMode)) is not supported",
                className: className
            )
        }
        
    }
    
    private func validateUriCombinations(authorizationRequestParameters: [String: Any], validAttribute: String, inValidAttribute: String) throws {
        if authorizationRequestParameters.keys.contains(inValidAttribute) {
            throw InvalidData(message: "\(inValidAttribute) should not be present for given response_mode", className: className)
        } else {
            try validateAttribute(validAttribute, values: self.authorizationRequestParameters)
        }
        
        let validValue = authorizationRequestParameters[validAttribute]
        // Extract client_id if client_id_scheme is also part of client_id in the authorizationRequestParameters otherwise use the client_id directly.
        let clientIdValue = authorizationRequestParameters[AuthorizationRequestFieldConstants.clientIdScheme.rawValue] == nil
        ? extractClientIdPartOnly(authorizationRequestParameters[AuthorizationRequestFieldConstants.clientId.rawValue] as? String ?? "") :
        authorizationRequestParameters[AuthorizationRequestFieldConstants.clientId.rawValue] as? String ?? ""
        
        if validValue as? String != clientIdValue {
            throw InvalidData(
                message: "\(validAttribute) should be equal to client_id for given client_id_scheme",
                className: className
            )
        }
    }
    
}
