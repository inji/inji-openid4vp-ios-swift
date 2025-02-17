import Foundation

class PreRegisteredSchemeAuthRequestHandler:  ClientIdSchemeBasedAuthRequestHandler {
    let trustedVerifiers: [Verifier]
    let shouldValidateClient: Bool
    
    init(trustedVerifiers: [Verifier], authRequestParam: [String: Any], networkManager: NetworkManaging, shouldValidateClient: Bool, setResponseUri: @escaping (String) -> Void) {
        self.trustedVerifiers = trustedVerifiers
        self.shouldValidateClient = shouldValidateClient
        super.init(authRequestParam: authRequestParam, networkManager: networkManager, setResponseUri: setResponseUri)
        delegate = self
    }
    
    override func validateClientId() throws {
        try super.validateClientId()
        if shouldValidateClient {
            guard !trustedVerifiers.isEmpty else {
                throw Logger.handleException(exceptionType: "EmptyVerifierList", className: AuthorizationRequest.className)
            }
            guard trustedVerifiers.contains(where: { $0.clientId == authRequestParam[AuthorizationRequestFieldConstants.clientId.rawValue] as! String }) else {
                throw Logger.handleException(exceptionType: "InvalidVerifierClientID", className: AuthorizationRequest.className)
            }
        }
    }
    
    func gatherAuthRequestImpl()async throws -> [String : Any] {
        if(authRequestParam["request_uri"] != nil){
            let response = try await fetchAuthRequestObjectByReference(params: authRequestParam as! [String:String], requestUri: authRequestParam["request_uri"] as! String, networkManager: networkManager)
            if (isJWT(response as! String)) {
                throw Logger.handleException(
                    exceptionType: "InvalidData",
                    message: "Authorization Request must not be signed for given client_id_scheme",
                    className: self.className
                )
            }
            let authorizationRequestObject = try decodeBase64ToJSON(makeBase64Standard(response as! String))
            try validateMatchOfAuthRequestObjectAndParams(params: authRequestParam as! [String : String], requestUriParams: authorizationRequestObject)
            
            return authorizationRequestObject
        }
        return authRequestParam
    }
    
    
    override func validateAndParseRequestFields()async throws {
        try await super.validateAndParseRequestFields()
        if shouldValidateClient {
            guard trustedVerifiers.contains(where: { $0.clientId == authRequestParam[AuthorizationRequestFieldConstants.clientId.rawValue] as! String && $0.responseUris.contains(getStringValue(authRequestParam[AuthorizationRequestFieldConstants.responseUri.rawValue]) ?? "null") }) else {
                throw Logger.handleException(exceptionType: "InvalidVerifierClientID", className: AuthorizationRequest.className)
            }
        }
    }
}
