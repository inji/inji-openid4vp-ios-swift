import Foundation

class PreRegisteredSchemeAuthRequestHandler:  ClientIdSchemeBasedAuthorizationRequestHandler {
    let trustedVerifiers: [Verifier]
    let shouldValidateClient: Bool
    
    init(trustedVerifiers: [Verifier], authorizationRequestParameters: [String: Any], networkManager: NetworkManaging, shouldValidateClient: Bool, setResponseUri: @escaping (String) -> Void) {
        self.trustedVerifiers = trustedVerifiers
        self.shouldValidateClient = shouldValidateClient
        super.init(authorizationRequestParam: authorizationRequestParameters, networkManager: networkManager, setResponseUri: setResponseUri)
        delegate = self
    }
    
    override func validateClientId() throws {
        try super.validateClientId()
        if shouldValidateClient {
            guard !trustedVerifiers.isEmpty else {
                throw Logger.handleException(exceptionType: "EmptyVerifierList", className: AuthorizationRequest.className)
            }
            guard trustedVerifiers.contains(where: { $0.clientId == authorizationRequestParameters[AuthorizationRequestFieldConstants.clientId.rawValue] as! String }) else {
                throw Logger.handleException(exceptionType: "InvalidVerifier", className: AuthorizationRequest.className)
            }
        }
    }
    
    func fetchAuthRequestImpl()async throws -> [String : Any] {
        if let requestUri = authorizationRequestParameters[AuthorizationRequestFieldConstants.requestUri.rawValue] {
            guard isValidUri(requestUri as! String)
            else {
                throw Logger.handleException(
                    exceptionType: "InvalidData",
                    message: "request_uri data is not valid",
                    className: AuthorizationRequest.className
                )
            }
            let response = try await fetchAuthRequestObjectByReference(params: authorizationRequestParameters as! [String:String], requestUri: requestUri as! String, networkManager: networkManager)
            if (isJWT(response as! String)) {
                throw Logger.handleException(
                    exceptionType: "InvalidData",
                    message: "Authorization Request must not be signed for given client_id_scheme",
                    className: self.className
                )
            }
            let authorizationRequestObject = try decodeBase64ToJSON(makeBase64Standard(response as! String))
            try validateMatchOfAuthRequestObjectAndParams(params: authorizationRequestParameters as! [String : String], requestUriParams: authorizationRequestObject)
            
            return authorizationRequestObject
        }
        return authorizationRequestParameters
    }
    
    
    override func validateAndParseRequestFields()async throws {
        try await super.validateAndParseRequestFields()
        if shouldValidateClient {
            guard trustedVerifiers.contains(where: { $0.clientId == authorizationRequestParameters[AuthorizationRequestFieldConstants.clientId.rawValue] as! String && $0.responseUris.contains(getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.responseUri.rawValue]) ?? "null") }) else {
                throw Logger.handleException(exceptionType: "InvalidVerifier", className: AuthorizationRequest.className)
            }
        }
    }
}
