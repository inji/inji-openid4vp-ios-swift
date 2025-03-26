import Foundation

class PreRegisteredSchemeAuthorizationRequestHandler:  ClientIdSchemeBasedAuthorizationRequestHandler {
    let trustedVerifiers: [Verifier]
    let shouldValidateClient: Bool
    
    init(trustedVerifiers: [Verifier], authorizationRequestParameters: [String: Any], networkManager: NetworkManaging, shouldValidateClient: Bool, setResponseUri: @escaping (String) -> Void) {
        self.trustedVerifiers = trustedVerifiers
        self.shouldValidateClient = shouldValidateClient
        super.init(authorizationRequestParameters: authorizationRequestParameters, networkManager: networkManager, setResponseUri: setResponseUri)
        delegate = self
        super.className = String(describing: PreRegisteredSchemeAuthorizationRequestHandler.self)
    }
    
    override func validateClientId() throws {
        if shouldValidateClient {
            guard trustedVerifiers.contains(where: { $0.clientId == authorizationRequestParameters[AuthorizationRequestFieldConstants.clientId.rawValue] as! String }) else {
                throw Logger.handleException(exceptionType: "InvalidVerifier", message: "Verifier not available in trusted list", className: AuthorizationRequest.className)
            }
        }
    }
    
    func validateRequestUriResponse() async throws {
        if let requestUriResponse = self.requestUriResponse {
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
