class DidSchemeAuthRequestHandler:  ClientIdSchemeBasedAuthorizationRequestHandler {
    override init(authorizationRequestParam authorizationRequestParameters: [String: Any], networkManager: NetworkManaging, setResponseUri: @escaping (String) -> Void) {
        super.init(authorizationRequestParam: authorizationRequestParameters, networkManager: networkManager, setResponseUri: setResponseUri)
        delegate = self
    }
    
    func fetchAuthRequestImpl() async throws -> [String : Any] {
        guard let requestUri = getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.requestUri.rawValue]) else {
            throw Logger.handleException(
                exceptionType: "MissingInput",
                message : "request_uri must be present for given client_id_scheme", fieldPath: ["request_uri"],
                className: self.className)
        }
        guard isValidUri(requestUri)
        else {
            throw Logger.handleException(
                exceptionType: "InvalidData",
                message: "request_uri data is not valid",
                className: AuthorizationRequest.className
            )
        }
        let (response, httpUrlResponse) = try await fetchAuthRequestObjectByReference(params: authorizationRequestParameters as! [String:String], requestUri: requestUri, networkManager: networkManager)
        
        let isContentTypeJWT = httpUrlResponse.isHeaderContentType(equalTo: ContentTypes.applicationJwt.rawValue)
        if (isContentTypeJWT && isJWT(response)) {
            let clienId: String = authorizationRequestParameters["client_id"] as! String
            
            let keyResolver: KeyResolver = DidKeyResolver(didUrl: clienId, networkManager: networkManager)
            let jwtHandler = JWTHandler(jwt: response , keyResolver: keyResolver)
            
            try await jwtHandler.verify()
            
            let authorizationRequestObject =  try extractDataJsonFromJwt(jwtToken: response , jwtPart: .payload)
            
            try validateMatchOfAuthRequestObjectAndParams(params: authorizationRequestParameters as! [String:String], requestUriParams: authorizationRequestObject)
            
            return authorizationRequestObject
        }
        else {
            throw Logger.handleException(exceptionType: "InvalidData", message: "Authorization Request must be signed and contain JWT for given client_id_scheme", className: self.className)
        }
    }
}
