import Foundation

class PreRegisteredSchemeAuthorizationRequestHandler:  ClientIdSchemeBasedAuthorizationRequestHandler {
    let trustedVerifiers: [Verifier]
    let shouldValidateClient: Bool
    
    init(trustedVerifiers: [Verifier], authorizationRequestParameters: [String: Any], networkManager: NetworkManaging, shouldValidateClient: Bool, setResponseUri: @escaping (String) -> Void) {
        self.trustedVerifiers = trustedVerifiers
        self.shouldValidateClient = shouldValidateClient
        super.init(authorizationRequestParameters: authorizationRequestParameters, networkManager: networkManager, setResponseUri: setResponseUri)
        delegate = self
    }
    
    override func validateClientId() throws {
        try super.validateClientId()
        if shouldValidateClient {
            guard trustedVerifiers.contains(where: { $0.clientId == authorizationRequestParameters[AuthorizationRequestFieldConstants.clientId.rawValue] as! String }) else {
                throw Logger.handleException(exceptionType: "InvalidVerifier", message: "Verifier not available in trusted list", className: AuthorizationRequest.className)
            }
        }
    }
    
    func validateRequestUriResponse() async throws {
        if let requestUriResponse = self.requestUriResponse {
            let isContentTypeNotJson = !requestUriResponse.httpUrlResponse.isHeaderContentType(equalTo: ContentTypes.applicationJson.rawValue)

            if (isContentTypeNotJson || isJWT(requestUriResponse.body)) {
                throw Logger.handleException(
                    exceptionType: "InvalidData",
                    message: "Authorization Request must not be signed for given client_id_scheme",
                    className: PreRegisteredSchemeAuthorizationRequestHandler.className
                )
            }
            
            guard let responseBody = requestUriResponse.body.data(using: .utf8) else {
                throw Logger.handleException(
                    exceptionType: "InvalidData",
                    message: "Conversion failed",
                    className: PreRegisteredSchemeAuthorizationRequestHandler.className
                )
            }
            guard let authorizationRequestObject = try JSONSerialization.jsonObject(with: responseBody, options: []) as? [String: Any]  else {
                throw Logger.handleException(
                    exceptionType: "InvalidData",
                    message: "Conversion failed",
                    className: PreRegisteredSchemeAuthorizationRequestHandler.className
                )
            }

            try validateAuthorizationRequestObjectAndParameters(params: authorizationRequestParameters as! [String : String], requestUriParams: authorizationRequestObject)
            
            authorizationRequestParameters = authorizationRequestObject
        }
    }
    
    override func validateAndParseRequestFields()async throws {
        if shouldValidateClient {
            guard trustedVerifiers.contains(where: { $0.clientId == authorizationRequestParameters[AuthorizationRequestFieldConstants.clientId.rawValue] as! String && $0.responseUris.contains(getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.responseUri.rawValue]) ?? "null") }) else {
                throw Logger.handleException(exceptionType: "InvalidVerifier", message: "response_uri trust cannot be established", className: AuthorizationRequest.className)
            }
        }
        try await super.validateAndParseRequestFields()
    }
}
