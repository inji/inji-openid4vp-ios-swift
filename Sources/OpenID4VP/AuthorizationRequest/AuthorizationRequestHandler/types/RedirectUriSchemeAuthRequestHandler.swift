class RedirectUriSchemeAuthRequestHandler:  ClientIdSchemeBasedAuthRequestHandler {
    override init(authRequestParam: [String: Any], networkManager: NetworkManaging, setResponseUri: @escaping (String) -> Void) {
        super.init(authRequestParam: authRequestParam, networkManager: networkManager, setResponseUri: setResponseUri)
        delegate = self
    }
    
    func gatherAuthRequestImpl() async throws -> [String : Any] {
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
        let responseMode = getStringValue(authRequestParam[AuthorizationRequestFieldConstants.responseMode.rawValue])
        switch responseMode {
        case ResponseMode.directPost.rawValue:
            try validateUriCombinations(authRequestParam: authRequestParam, validKey: AuthorizationRequestFieldConstants.responseUri.rawValue, inValidKey: AuthorizationRequestFieldConstants.redirectUri.rawValue)
        case  ResponseMode.directPostJwt.rawValue:
            try validateUriCombinations(authRequestParam: authRequestParam, validKey: AuthorizationRequestFieldConstants.responseUri.rawValue, inValidKey: AuthorizationRequestFieldConstants.redirectUri.rawValue)
            throw Logger.handleException(
                exceptionType : "InvalidResponseMode",
                message : "Given response_mode \(String(describing: responseMode)) is not supported", className: self.className
            )
        case ResponseMode.fragment.rawValue:
            try validateUriCombinations(authRequestParam: authRequestParam, validKey: AuthorizationRequestFieldConstants.redirectUri.rawValue, inValidKey: AuthorizationRequestFieldConstants.responseUri.rawValue)
            throw Logger.handleException(
                exceptionType : "InvalidResponseMode",
                message : "Given response_mode \(String(describing: responseMode)) is not supported", className: self.className
            )
        default:
            throw Logger.handleException(
                exceptionType : "InvalidResponseMode",
                message : "Given response_mode \(String(describing: responseMode)) is not supported", className: self.className
            )
        }
        
    }
    
    private func validateUriCombinations(authRequestParam: [String: Any], validKey: String, inValidKey: String) throws {
        if authRequestParam.keys.contains(inValidKey) {
            throw Logger.handleException(
                exceptionType: "invalidInput",
                message: "\(inValidKey) should not be present for given response_mode", className: className
            )
        } else {
            try validateKey(validKey, values: self.authRequestParam)
        }
        
        if let validValue = authRequestParam[validKey], let clientIdValue = authRequestParam[AuthorizationRequestFieldConstants.clientId.rawValue] as? String, validValue as? String != clientIdValue {
            throw Logger.handleException(
                exceptionType: "invalidVerifierRedirectUri",
                message: "\(validKey) should be equal to client_id for given client_id_scheme", className: className
            )
        }
    }    
}
