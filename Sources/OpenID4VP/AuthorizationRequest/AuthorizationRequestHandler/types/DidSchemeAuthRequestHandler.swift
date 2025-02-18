class DidSchemeAuthRequestHandler:  ClientIdSchemeBasedAuthRequestHandler {
    override init(authRequestParam: [String: Any], networkManager: NetworkManaging, setResponseUri: @escaping (String) -> Void) {
        super.init(authRequestParam: authRequestParam, networkManager: networkManager, setResponseUri: setResponseUri)
        delegate = self
    }
    
    func gatherAuthRequestImpl() async throws -> [String : Any] {
        guard let requestUri = getStringValue(authRequestParam[AuthorizationRequestFieldConstants.requestUri.rawValue]) else {
            throw Logger.handleException(
                exceptionType: "MissingInput",
                message : "request_uri must be present for given client_id_scheme", fieldPath: ["request_uri"],
                className: self.className)
        }
        let response = try await fetchAuthRequestObjectByReference(params: authRequestParam as! [String:String], requestUri: requestUri, networkManager: networkManager)
        if (isJWT(response as! String)) {
            let clienId: String = authRequestParam["client_id"] as! String
            
            let keyResolver: KeyResolver = DidKeyResolver(didUrl: clienId, networkManager: networkManager)
            let jwtHandler = JWTHandler(jwt: response as! String, keyResolver: keyResolver)
            
            try await jwtHandler.verify()
            
            let authorizationRequestObject =  try extractDataJsonFromJwt(jwtToken: response as! String, jwtPart: .payload)
            
            try validateMatchOfAuthRequestObjectAndParams(params: authRequestParam as! [String:String], requestUriParams: authorizationRequestObject)
            
            return authorizationRequestObject
        }
        throw Logger.handleException(exceptionType: "InvalidData", message: "Authorization Request must be signed and contain JWT for given client_id_scheme", className: self.className)
    }
}
