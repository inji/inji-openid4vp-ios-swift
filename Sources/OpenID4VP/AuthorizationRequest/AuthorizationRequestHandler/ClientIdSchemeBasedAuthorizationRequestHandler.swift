import Foundation


protocol AbstractMethodsForClientIdSchemeBasedAuthorizationRequestHandler {
    func validateRequestUriResponse(requestUriResponse: (body: String, httpUrlResponse: HTTPURLResponse)?,walletNonce: String, isMismatchedAcceptableType: Bool) async throws
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
        var isMismatchedAcceptableType : Bool = false
        var requestUriResponse: (body: String, httpUrlResponse: HTTPURLResponse)? = nil
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
            
            let requestUriMethod = authorizationRequestParameters[AuthorizationRequestFieldConstants.requestUriMethod.rawValue] as? String ?? HttpMethod.get.rawValue
            let httpMethod = try determineHttpMethod(method: requestUriMethod)
            
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
                try await validateAuthorizationRequestObject(response)
                
                requestUriResponse = (response.responseBody, response.httpUrlResponse)
            } catch let error as NetworkRequestException {
                isMismatchedAcceptableType = error.localizedDescription.contains(errorMessageForMismatchedAcceptableType)
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
        try await delegate.validateRequestUriResponse(requestUriResponse: requestUriResponse, walletNonce: self.walletNonce, isMismatchedAcceptableType: isMismatchedAcceptableType)
    }
    
    //TODO: rename to validateRequestUriResponse
    private func validateAuthorizationRequestObject(_ requestUriResponse: (responseBody: String, httpUrlResponse: HTTPURLResponse)) async throws {
        //TODO: remove this check as its redundant. isMismatchedAcceptableType handles it already
        guard requestUriResponse.httpUrlResponse.isHeaderContentType(equalTo: ContentTypes.applicationJwt.rawValue) else {
            throw InvalidData(
                message: "Authorization Request Object must have content type 'application/oauth-authz-req+jwt'", className: className)
        }
        
        
        guard isJWS(requestUriResponse.responseBody) else {
            throw InvalidData(
                message: "Authorization Request Object must be a signed JWT", className: className)
        }
        
        let clientId: String = authorizationRequestParameters[AuthorizationRequestFieldConstants.clientId.rawValue] as! String
        let actualAuthorizationRequestObject = requestUriResponse.responseBody
        
        let header = try JWSHandler.extractDataJsonFromJws(jws: actualAuthorizationRequestObject,jwsPart: .header)
//        try validateAuthorizationRequestSigningAlgorithm(header: header)
        
        guard let algorithm = header["alg"] as? String else {
            throw InvalidData(message: "Request URI response validation failed - alg is not present in JWS header", className: className, code: OpenID4VPErrorCodes.invalidRequestObject)
        }
        
        // TODO: IN JWT header keyId is optional as per spec, for did only its mandatory
//        let publicKey = try await delegate.extractPublicKey(keyId: header["kid"] as? String, algorithm: "")
        let publicKey = try await delegate.extractPublicKey(keyId: header["kid"] as? String ?? "", algorithm: algorithm)
        //
        //            let keyResolver: PublicKeyResolver = DidPublicKeyResolver(networkManager: networkManager)
        //
        //            let header = try JWSHandler.extractDataJsonFromJws(jws: actualAuthorizationRequestObject,jwsPart: .header)
        //            try validateAuthorizationRequestSigningAlgorithm(header: header)
        //
//        try await JWSHandler.verify(jws: actualAuthorizationRequestObject , publicKeyResolver: publicKey)
        //
        //            let authorizationRequestObject =  try JWSHandler.extractDataJsonFromJws(jws: actualAuthorizationRequestObject, jwsPart: .payload)
        //
        //            // wallet_nonce is passed in the POST request to request_uri,so the Request URI response must have wallet_nonce and Wallet MUST validate whether the request object contains the respective nonce value in a wallet_nonce claim.
        //            let requestUriMethod = try determineHttpMethod(method: authorizationRequestParameters[AuthorizationRequestFieldConstants.requestUriMethod.rawValue] as? String ?? HttpMethod.get.rawValue)
        //            if( requestUriMethod == .post) {
        //                try validateWalletNonce(authorizationRequestObject, walletNonce)
        //            }
        //
        //            try validateAuthorizationRequestObjectAndParameters(params: authorizationRequestParameters as! [String:String], requestUriParams: authorizationRequestObject)
        //
        //            self.authorizationRequestParameters = authorizationRequestObject
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
        //TODO: Can we avoid extracting client id scheme twice? Can we get it from the delegate - delegate.clientIdScheme?
        let clientIdScheme = try extractClientIdScheme(authorizationRequestParams: authorizationRequestParameters)
        let walletSupportedClientIdSchemes = walletMetadata.clientIdSchemesSupported.compactMap { $0.rawValue }
        if !walletSupportedClientIdSchemes.contains(clientIdScheme) {
            throw InvalidData(
                message: "client_id_scheme is not supported by wallet",
                className: className
            )
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
