import Foundation


protocol AbstractMethodsForClientIdSchemeBasedAuthorizationRequestHandler {
    func validateRequestUriResponse(requestUriResponse: (body: String, httpUrlResponse: HTTPURLResponse)?) async throws
    func process(walletMetadata: WalletMetadata) throws -> WalletMetadata
    func getHeadersForAuthorizationRequestUri() -> [String: String]?
}

class ClientIdSchemeBasedAuthorizationRequestHandlerBaseClass  {
    var delegate: AbstractMethodsForClientIdSchemeBasedAuthorizationRequestHandler!
    var authorizationRequestParameters: [String: Any]
    let walletMetadata: WalletMetadata?
    let setResponseUri: (String) -> Void
    let networkManager: NetworkManaging
    var shouldValidateWithWalletMetadata: Bool = false
    var className = String(describing: ClientIdSchemeBasedAuthorizationRequestHandler.self)
    
    init(authorizationRequestParameters: [String: Any],
         walletMetadata: WalletMetadata?,
         setResponseUri: @escaping (String) -> Void,
         networkManager: NetworkManaging) {
        self.authorizationRequestParameters = authorizationRequestParameters
        self.setResponseUri = setResponseUri
        self.networkManager = networkManager
        self.walletMetadata = walletMetadata
    }
    
    func validateClientId() throws {
        return
    }
    
    func fetchAuthorizationRequest() async throws{
        var requestUriResponse: (body: String, httpUrlResponse: HTTPURLResponse)? = nil
        if let requestUri = authorizationRequestParameters["request_uri"] as? String {
            if !isNeitherNullNorEmpty(field: requestUri) || !(requestUri != "null") {
                throw Logger.handleException(exceptionType: "InvalidInput", fieldPath: ["requestUri"], className: className)
            }
            guard isValidUri(requestUri)
            else {
                throw Logger.handleException(
                    exceptionType: "InvalidData",
                    message: "request_uri \(requestUri) data is not valid",
                    className: className
                )
            }
            
            let requestUriMethod = authorizationRequestParameters["request_uri_method"] as? String ?? HttpMethod.get.rawValue
            let httpMethod = try determineHttpMethod(method: requestUriMethod)
            
            var body: [String: String]? = nil
            var headers: [String: String]? = nil

            if httpMethod == .post {
                if let walletMetadata = walletMetadata {
                    try isClientIdSchemeSupported(walletMetadata: walletMetadata)
                    let processedWalletMetadata = try delegate.process(walletMetadata: walletMetadata)
                    body = ["wallet_metadata": try encode(processedWalletMetadata, fieldName:  "wallet_metadata", className: className)]
                    headers = delegate.getHeadersForAuthorizationRequestUri()
                    shouldValidateWithWalletMetadata = true
                }
            }
            
            let response = try await networkManager.sendHTTPRequest(url: requestUri, method: httpMethod, bodyParams: body, headers: headers)
            
            requestUriResponse = (response.responseBody, response.httpUrlResponse)
            
        }
        try await delegate.validateRequestUriResponse(requestUriResponse: requestUriResponse)
    }
    
    func validateAndParseRequestFields() async throws {
        let mandatoryFields = [AuthorizationRequestFieldConstants.responseType.rawValue,AuthorizationRequestFieldConstants.nonce.rawValue]

        for field in mandatoryFields {
            try validateAttribute(field, values: authorizationRequestParameters)
        }
        
        let optionalFields = [AuthorizationRequestFieldConstants.state.rawValue, AuthorizationRequestFieldConstants.responseMode.rawValue]
        for field in optionalFields {
            if (authorizationRequestParameters[field] != nil){
                try validateAttribute(field, values: authorizationRequestParameters)
            }
        }
        
        authorizationRequestParameters = try parseAndValidateClientMetadata(authorizationRequest: authorizationRequestParameters, shouldValidateWithWalletMetadata: shouldValidateWithWalletMetadata, walletMetadata: walletMetadata)
        
        let presentationDefinitionUriSupported = !shouldValidateWithWalletMetadata || walletMetadata?.presentationDefinitionURISupported ?? true
        
        authorizationRequestParameters = try await parseAndValidatePresentationDefinition(authorizationRequestParameters, presentationDefinitionUriSupported, networkManager)
    }
    
    final func setResponseUrl() throws {
        let responseMode = getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.responseMode.rawValue])
        
        try ResponseModeBasedHandlerFactory.get(responseMode: responseMode).setResponseUrl(authorizationRequestParameters: authorizationRequestParameters,setResponseUri: setResponseUri)
    }
    
    private func isClientIdSchemeSupported(walletMetadata: WalletMetadata) throws {
        let clientId = getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.clientId.rawValue])
        let clientIdScheme = try extractClientIdScheme(clientId: clientId ?? "")
        if !walletMetadata.clientIdSchemesSupported.contains(clientIdScheme) {
            throw Logger.handleException(
                exceptionType: "InvalidData",
                message: "client_id_scheme is not supported by wallet", className: className
            )
        }
    }
    
    final func createAuthorizationRequest() -> AuthorizationRequest {
        return AuthorizationRequest(
            clientId: getStringValue(authorizationRequestParameters["client_id"])!,
            presentationDefinition: authorizationRequestParameters["presentation_definition"]! as! PresentationDefinition,
            responseType: getStringValue(authorizationRequestParameters["response_type"])!,
            responseMode: getStringValue(authorizationRequestParameters["response_mode"]),
            nonce: getStringValue(authorizationRequestParameters["nonce"])!,
            state: getStringValue(authorizationRequestParameters["state"]),
            redirectUri: getStringValue(authorizationRequestParameters["redirect_uri"]),
            responseUri: getStringValue(authorizationRequestParameters["response_uri"]),
            clientMetadata: authorizationRequestParameters["client_metadata"] as? ClientMetadata
        )
    }
}

typealias ClientIdSchemeBasedAuthorizationRequestHandler = ClientIdSchemeBasedAuthorizationRequestHandlerBaseClass & AbstractMethodsForClientIdSchemeBasedAuthorizationRequestHandler
