import Foundation
class RedirectUriSchemeAuthorizationRequestHandler:  ClientIdSchemeBasedAuthorizationRequestHandler {
    override init(authorizationRequestParameters: [String: Any],
                  walletMetadata: WalletMetadata? = nil,
                  setResponseUri: @escaping (String) -> Void,
                  networkManager: NetworkManaging) {
        super.init(authorizationRequestParameters: authorizationRequestParameters,
                   walletMetadata: walletMetadata,
                   setResponseUri: setResponseUri,
                   networkManager: networkManager)
        delegate = self
        super.className = String(describing: RedirectUriSchemeAuthorizationRequestHandler.self)
    }
    
    func validateRequestUriResponse(requestUriResponse:  (body: String, httpUrlResponse: HTTPURLResponse)?) async throws {
        if let requestUriResponse = requestUriResponse {
            let isContentTypeNotJson = !requestUriResponse.httpUrlResponse.isHeaderContentType(equalTo: ContentTypes.applicationJson.rawValue)
            if (isContentTypeNotJson || isJWS(requestUriResponse.body)) {
                throw Logger.handleException(
                    exceptionType: "InvalidData",
                    message: "Authorization Request must not be signed for given client_id_scheme",
                    className: className
                )
            }
            guard let responseBody = requestUriResponse.body.data(using: .utf8) else {
                throw Logger.handleException(
                    exceptionType: "InvalidData",
                    message: "Conversion failed",
                    className: className
                )
            }
            guard let authorizationRequestObject = try JSONSerialization.jsonObject(with: responseBody, options: []) as? [String: Any]  else {
                throw Logger.handleException(
                    exceptionType: "InvalidData",
                    message: "Conversion failed",
                    className: className
                )
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
        return ["content-type": ContentTypes.applicationFormUrlEncoded.rawValue,
                "accept": ContentTypes.applicationJson.rawValue]
    }
    
    override func validateAndParseRequestFields()async throws {
        try await super.validateAndParseRequestFields()
        let responseMode = getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.responseMode.rawValue])
        switch responseMode {
        case ResponseMode.directPost.rawValue, ResponseMode.directPostJwt.rawValue:
            try validateUriCombinations(authorizationRequestParameters: authorizationRequestParameters, validAttribute: AuthorizationRequestFieldConstants.responseUri.rawValue, inValidAttribute: AuthorizationRequestFieldConstants.redirectUri.rawValue)
        default:
            throw Logger.handleException(
                exceptionType : "InvalidResponseMode",
                message : "Given response_mode \(String(describing: responseMode)) is not supported", className: className
            )
        }
        
    }
    
    private func validateUriCombinations(authorizationRequestParameters: [String: Any], validAttribute: String, inValidAttribute: String) throws {
        if authorizationRequestParameters.keys.contains(inValidAttribute) {
            throw Logger.handleException(
                exceptionType: "invalidInput",
                message: "\(inValidAttribute) should not be present for given response_mode", className: className
            )
        } else {
            try validateAttribute(validAttribute, values: self.authorizationRequestParameters)
        }
        
        let validValue = authorizationRequestParameters[validAttribute]
        let clientIdValue = extractClientIdPartOnly(authorizationRequestParameters[AuthorizationRequestFieldConstants.clientId.rawValue] as? String ?? "")
        if validValue as? String != clientIdValue {
            throw Logger.handleException(
                exceptionType: "InvalidVerifier",
                message: "\(validAttribute) should be equal to client_id for given client_id_scheme", className: className
            )
        }
    }
}
