import Foundation


protocol AbstractMethodsForClientIdSchemeBasedAuthorizationRequestHandler {
    func process(walletMetadata: WalletMetadata) throws -> WalletMetadata
    func getHeadersForAuthorizationRequestUri() -> [String: String]?
    func isRequestUriSupported() -> Bool
    func isRequestObjectSupported() -> Bool
    func extractPublicKey(keyId: String?, algorithm: String) async throws -> PublicKeyType
    func clientIdScheme() -> String
}

class ClientIdSchemeBasedAuthorizationRequestHandlerBaseClass  {
    var delegate: AbstractMethodsForClientIdSchemeBasedAuthorizationRequestHandler!
    var authorizationRequestParameters: [String: Any]
    let walletMetadata: WalletMetadata?
    let setResponseUri: (String) -> Void
    let walletNonce: String
    let networkManager: NetworkManaging
    var shouldValidateWithWalletMetadata: Bool = false
    var className = String(describing: ClientIdSchemeBasedAuthorizationRequestHandler.self)
    
    let errorMessageForMismatchedAcceptableType: String = "does not match any acceptable types"
    
    init(authorizationRequestParameters: [String: Any],
         walletMetadata: WalletMetadata?,
         setResponseUri: @escaping (String) -> Void,
         walletNonce: String,
         networkManager: NetworkManaging) {
        self.authorizationRequestParameters = authorizationRequestParameters
        self.setResponseUri = setResponseUri
        self.networkManager = networkManager
        self.walletMetadata = walletMetadata
        self.walletNonce = walletNonce
    }
    
    func validateClientId() throws {
        return
    }
    
    func fetchAuthorizationRequest() async throws{
        if let requestUri = authorizationRequestParameters["request_uri"] as? String {
            guard (delegate.isRequestUriSupported()) else {
                throw InvalidData(
                    message: "request_uri is not supported for given client_id_scheme",
                    className: className
                )
            }
            
            if !isNeitherNullNorEmpty(field: requestUri) || (requestUri == "null") {
                throw InvalidInput(fieldPath: ["requestUri"], className: className)
            }
            guard isValidUri(requestUri)
            else {
                throw InvalidData(
                    message: "request_uri \(requestUri) data is not valid",
                    className: className
                )
            }
            
            let httpMethod = try requestUriMethod()
            
            var body: [String: String]? = nil
            var headers: [String: String]? = nil
            
            if httpMethod == .post {
                body = [:]
                body?["wallet_nonce"] = walletNonce
                if let walletMetadata = walletMetadata {
                    try isClientIdSchemeSupported(walletMetadata: walletMetadata)
                    let processedWalletMetadata = try delegate.process(walletMetadata: walletMetadata)
                    let extractedExpr: String = try encode(processedWalletMetadata, fieldName:  "wallet_metadata", className: className)
                    body?["wallet_metadata"] = extractedExpr
                    headers = [Header.contentType.rawValue: ContentTypes.applicationFormUrlEncoded.rawValue,
                               Header.accept.rawValue: ContentTypes.applicationJwt.rawValue]
                    shouldValidateWithWalletMetadata = true
                }
            }
            do{
                let response = try await networkManager.sendHTTPRequest(url: requestUri, method: httpMethod, bodyParams: body, headers: headers)
                try await validateRequestUriResponse(response)                
            } catch let error as NetworkRequestException {
                let isMismatchedAcceptableType = error.localizedDescription.contains(errorMessageForMismatchedAcceptableType)
                if(isMismatchedAcceptableType){
                    throw InvalidData(
                        message: "Authorization Request Object must have content type 'application/oauth-authz-req+jwt'", className: className)
                }
            }
        } else {
            guard (delegate.isRequestObjectSupported()) else {
                throw InvalidData(
                    message: "request object is not supported for given client_id_scheme - \(delegate.clientIdScheme())",
                    className: className
                )
            }
        }
    }
    
    private func validateRequestUriResponse(_ requestUriResponse: (responseBody: String, httpUrlResponse: HTTPURLResponse)) async throws {
        guard isJWS(requestUriResponse.responseBody) else {
            throw InvalidData(
                message: "Authorization Request Object must be a signed JWT", className: className)
        }
        
        let jwtRequest = requestUriResponse.responseBody
        let authorizationRequestObject =  try JWSHandler.extractDataJsonFromJws(jws: jwtRequest, jwsPart: .payload)
        
        //TODO: whats the order of validate wallet nonce and validate jwt request?
        let requestUriMethod = try requestUriMethod()
        if(requestUriMethod == .post){
            try validateWalletNonce(authorizationRequestObject, walletNonce)
        }
        
        try await validateJWTRequest(jwtRequest)
        
        try validateAuthorizationRequestObjectAndParameters(params: authorizationRequestParameters as! [String:String], requestUriParams: authorizationRequestObject)
        
        self.authorizationRequestParameters = authorizationRequestObject
    }
    
    // If the key is not associated with the client or if signature validation fails, error code = invalid_request_object
    private func validateJWTRequest(_ jwtRequest: String) async throws {
        do {
            let header = try JWSHandler.extractDataJsonFromJws(jws: jwtRequest,jwsPart: .header)
            
            guard let algorithm = header["alg"] as? String else {
                throw InvalidData(message: "Request URI response validation failed - alg is not present in JWS header", className: className, code: OpenID4VPErrorCodes.invalidRequestObject)
            }
            
            try validateAuthorizationRequestSigningAlgorithm(algorithm)
            
            let publicKey = try await delegate.extractPublicKey(keyId: header["kid"] as? String, algorithm: algorithm)
            try await JWSHandler.verify(jws: jwtRequest , publicKey: publicKey)
        } catch {
            throw InvalidData(message: "Request URI response validation failed - \(error.localizedDescription)", className: className, code: OpenID4VPErrorCodes.invalidRequestObject)
        }
    }
    
    func validateAndParseRequestFields() async throws {
        let mandatoryFields = [AuthorizationRequestFieldConstants.responseType.rawValue,AuthorizationRequestFieldConstants.nonce.rawValue]
        
        for field in mandatoryFields {
            try validateAttribute(field, values: authorizationRequestParameters)
        }
        
        try validateResponseTypeSupported((authorizationRequestParameters[AuthorizationRequestFieldConstants.responseType.rawValue] as? String)!)
        
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
        let clientIdScheme = try extractClientIdScheme(authorizationRequestParams: authorizationRequestParameters)
        let walletSupportedClientIdSchemes = walletMetadata.clientIdSchemesSupported.compactMap { $0.rawValue }
        if !walletSupportedClientIdSchemes.contains(clientIdScheme) {
            throw InvalidData(
                message: "client_id_scheme is not supported by wallet",
                className: className
            )
        }
    }
    
    private func validateAuthorizationRequestSigningAlgorithm(_ algorithm: String) throws {
        if shouldValidateWithWalletMetadata, let walletMetadata = walletMetadata {
            if let supportedAlgs = walletMetadata.requestObjectSigningAlgValuesSupported?.compactMap({$0.rawValue}) ,
               !supportedAlgs.contains(algorithm) {
                throw InvalidData(
                    message: "request_object_signing_alg is not supported by wallet",
                    className: className
                )
            }
        }
    }
    
    private func requestUriMethod() throws -> HttpMethod {
        let requestUriMethod = authorizationRequestParameters[AuthorizationRequestFieldConstants.requestUriMethod.rawValue] as? String ?? HttpMethod.get.rawValue
        let httpMethod = try determineHttpMethod(method: requestUriMethod)
        return httpMethod
    }
    
    private func validateWalletNonce(_ authorizationRequestObject: [String : Any], _ walletNonce: String) throws {
        let walletNonceFromAuthorizationRequest = authorizationRequestObject[AuthorizationRequestFieldConstants.walletNonce.rawValue] as? String
        if walletNonce != walletNonceFromAuthorizationRequest {
            throw InvalidData(message: "wallet_nonce provided in the authorization request is not the same as shared by wallet", className: AuthorizationRequest.className)
        }
    }
    
    final func createAuthorizationRequest() -> AuthorizationRequest {
        return AuthorizationRequest(
            clientId: getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.clientId.rawValue])!,
            clientIdScheme: getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.clientIdScheme.rawValue]),
            presentationDefinition: authorizationRequestParameters[AuthorizationRequestFieldConstants.presentationDefinition.rawValue]! as! PresentationDefinition,
            responseType: getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.responseType.rawValue])!,
            responseMode: getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.responseMode.rawValue]),
            nonce: getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.nonce.rawValue])!,
            state: getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.state.rawValue]),
            redirectUri: getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.redirectUri.rawValue]),
            responseUri: getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.responseUri.rawValue]),
            walletNonce: getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.walletNonce.rawValue]),
            clientMetadata: authorizationRequestParameters[AuthorizationRequestFieldConstants.clientMetadata.rawValue] as? ClientMetadata
        )
    }
}

typealias ClientIdSchemeBasedAuthorizationRequestHandler = ClientIdSchemeBasedAuthorizationRequestHandlerBaseClass & AbstractMethodsForClientIdSchemeBasedAuthorizationRequestHandler
