class RedirectUriSchemeAuthRequestHandler:  ClientIdSchemeBasedAuthorizationRequestHandler {
    override init(authorizationRequestParam authorizationRequestParameters: [String: Any], networkManager: NetworkManaging, setResponseUri: @escaping (String) -> Void) {
        super.init(authorizationRequestParam: authorizationRequestParameters, networkManager: networkManager, setResponseUri: setResponseUri)
        delegate = self
    }
    
    func fetchAuthRequestImpl() async throws -> [String : Any] {
        if let requestUri = authorizationRequestParameters["request_uri"] {
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
        let responseMode = getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.responseMode.rawValue])
        switch responseMode {
        case ResponseMode.directPost.rawValue:
            try validateUriCombinations(authorizationRequestParameters: authorizationRequestParameters, validKey: AuthorizationRequestFieldConstants.responseUri.rawValue, inValidKey: AuthorizationRequestFieldConstants.redirectUri.rawValue)
        default:
            throw Logger.handleException(
                exceptionType : "InvalidResponseMode",
                message : "Given response_mode \(String(describing: responseMode)) is not supported", className: self.className
            )
        }
        
    }
    
    private func validateUriCombinations(authorizationRequestParameters: [String: Any], validKey: String, inValidKey: String) throws {
        if authorizationRequestParameters.keys.contains(inValidKey) {
            throw Logger.handleException(
                exceptionType: "invalidInput",
                message: "\(inValidKey) should not be present for given response_mode", className: className
            )
        } else {
            try validateKey(validKey, values: self.authorizationRequestParameters)
        }
        
        if let validValue = authorizationRequestParameters[validKey], let clientIdValue = authorizationRequestParameters[AuthorizationRequestFieldConstants.clientId.rawValue] as? String, validValue as? String != clientIdValue {
            throw Logger.handleException(
                exceptionType: "InvalidVerifier",
                message: "\(validKey) should be equal to client_id for given client_id_scheme", className: className
            )
        }
    }
}
