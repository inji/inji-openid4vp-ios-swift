import Foundation


protocol AbstractMethodsForClientIdPrefixBasedAuthorizationRequestHandler {
    func process(walletMetadata: WalletMetadata) throws -> WalletMetadata
    func isSignedRequestSupported() -> Bool
    func isUnsignedRequestSupported() throws -> Bool
    func extractPublicKey(keyId: String?, algorithm: String) async throws -> PublicKeyType
    func clientIdPrefix() -> String
}

class ClientIdPrefixBasedAuthorizationRequestHandlerBaseClass  {
    var delegate: AbstractMethodsForClientIdPrefixBasedAuthorizationRequestHandler!
    let clientId: String
    var authorizationRequestParameters: [String: Any]
    let walletMetadata: WalletMetadata?
    let setResponseUri: (String) -> Void
    let walletNonce: String
    let networkManager: NetworkManaging
    private var specVersionHandler: SpecVersionHandler = .specV1
    var specVersion: SpecVersion = .draft23
    var shouldValidateWithWalletMetadata: Bool = false
    var className = String(describing: ClientIdPrefixBasedAuthorizationRequestHandler.self)
    
    let errorMessageForMismatchedAcceptableType: String = "does not match any acceptable types"
    
    init(clientId: String,
         specVersion: SpecVersion,
         authorizationRequestParameters: [String: Any],
         walletMetadata: WalletMetadata?,
         setResponseUri: @escaping (String) -> Void,
         walletNonce: String,
         networkManager: NetworkManaging = NetworkManager()) {
        self.authorizationRequestParameters = authorizationRequestParameters
        self.setResponseUri = setResponseUri
        self.networkManager = networkManager
        self.walletMetadata = walletMetadata
        self.walletNonce = walletNonce
        self.clientId = clientId
        self.specVersion = specVersion
    }
    
    internal func setSpecVersionHandler(_ specVersion: SpecVersion) {
        self.specVersionHandler = SpecVersionHandler.from(specVersion)
    }
    
    func handle() async throws -> AuthorizationRequest {
        try self.validateClientId()
        try await self.fetchAuthorizationRequest()
        try self.setResponseUrl()
        // TODO: Add validation for DCQL query in validateAndParseRequestFields
        try await self.validateAndParseRequestFields()
        return self.createAuthorizationRequest()
    }
    
    func validateClientId() throws {
        return
    }
    
    func fetchAuthorizationRequest() async throws{
        let request = authorizationRequestParameters[AuthorizationRequestFieldConstants.request.rawValue] as? String
        let requestUri = authorizationRequestParameters[AuthorizationRequestFieldConstants.requestUri.rawValue] as? String
        
        if(request != nil && requestUri != nil){
            throw InvalidData(
                message: "Both 'request' and 'request_uri' cannot be present in same authorization request",
                className: className
            )
        }
        
        if let request = request {
            try await handleRequestObjectAsValue(request)
            specVersion = findSpecVersionUsingRequestParameters(authorizationRequestParameters)
            
        }
        else if let requestUri = requestUri {
            try await handleRequestObjectByReference(requestUri)
        } else {
            try handleUrlEncodedRequest()
        }
        
        // After fetching the VP request, populate version logic
        specVersionHandler = SpecVersionHandler.from(specVersion)
    }

    private func handleRequestObjectAsValue(_ request: String) async throws {
        try validate(request, fieldPath: AuthorizationRequestFieldConstants.request.rawValue, className: className)
        guard (delegate.isSignedRequestSupported()) else {
            throw InvalidData(
                message: "Signed request (via request) is not supported for given client_id_prefix - \(delegate.clientIdPrefix())",
                className: className
            )
        }
        
        try await validateJWTRequest(request)
        let authorizationRequestObject =  try JWSHandler.extractDataJsonFromJws(jws: request, jwsPart: .payload)
        
        try validateAuthorizationRequestObjectAndParameters(params: self.authorizationRequestParameters, requestObject: authorizationRequestObject)
        
        self.authorizationRequestParameters = authorizationRequestObject
    }
    
    private func handleRequestObjectByReference(_ requestUri: String) async throws {
        guard (delegate.isSignedRequestSupported()) else {
            throw InvalidData(
                message: "Signed request (via request_uri) is not supported for given client_id_prefix - \(delegate.clientIdPrefix())",
                className: className
            )
        }
        
        try validate(requestUri, fieldPath: AuthorizationRequestFieldConstants.requestUri.rawValue, className: className)
        guard isValidUri(requestUri)
        else {
            throw InvalidData(
                message: "request_uri \(requestUri) data is not valid",
                className: className
            )
        }
        
        let httpMethod = try requestUriMethod()
        
        var body: [String: String]? = nil
        var headers: [String: String] = [Header.accept.rawValue: ContentTypes.applicationJwt.rawValue]
        
        if httpMethod == .post {
            body = [AuthorizationRequestFieldConstants.walletNonce.rawValue: walletNonce]
            headers[Header.contentType.rawValue] = ContentTypes.applicationFormUrlEncoded.rawValue
            
            
            if let walletMetadata = walletMetadata {
                try isClientIdPrefixSupported(walletMetadata: walletMetadata)
                
                let processedWalletMetadata = try delegate.process(walletMetadata: walletMetadata)
                body?["wallet_metadata"] = try processedWalletMetadata.encode(specVersion: specVersion)
                shouldValidateWithWalletMetadata = true
            }
        }
        var response:  NetworkResponse
        do{
            response = try await networkManager.sendHTTPRequest(url: requestUri, method: httpMethod, bodyParams: body, headers: headers)
            if(!response.isOK){
                throw InvalidData(message: "Error while fetching request_uri: HTTP status code \(response.statusCode) & body: \(response.body)", className: className)
            }
        }
        catch let error as NetworkRequestException {
            let isMismatchedAcceptableType = error.localizedDescription.contains(errorMessageForMismatchedAcceptableType)
            if(isMismatchedAcceptableType){
                throw InvalidData(
                    message: "Authorization Request Object must have content type 'application/oauth-authz-req+jwt'", className: className)
            }
            throw GenericFailure(message: "Network error while fetching request_uri: \(error.localizedDescription)", className: className)
        } catch {
            throw GenericFailure(message: "Error while fetching request_uri: \(error.localizedDescription)", className: className)
        }
        self.authorizationRequestParameters = try await validateRequestUriResponse(response.body, httpMethod: httpMethod)
    }
    
    private func handleUrlEncodedRequest() throws {
        guard (try delegate.isUnsignedRequestSupported()) else {
            throw InvalidData(
                message: "unsigned request is not supported for given client_id_prefix - \(delegate.clientIdPrefix())",
                className: className
            )
        }
    }
    
    private func validateRequestUriResponse(_ requestUriResponse: String, httpMethod: HttpMethod) async throws -> [String: Any] {
        guard isJWS(requestUriResponse) else {
            throw InvalidData(
                message: "Authorization Request Object must be a signed JWT", className: className)
        }
        
        try await validateJWTRequest(requestUriResponse)
        
        let authorizationRequestObject =  try JWSHandler.extractDataJsonFromJws(jws: requestUriResponse, jwsPart: .payload)
        if(httpMethod == .post){
            try validateWalletNonce(authorizationRequestObject, walletNonce)
        }
        
        try validateAuthorizationRequestObjectAndParameters(params: authorizationRequestParameters, requestObject: authorizationRequestObject)
        
        return authorizationRequestObject
    }
    
    // If the key is not associated with the client or if signature validation fails, error code = invalid_request_object
    private func validateJWTRequest(_ jwtRequest: String) async throws {
        do {
            let header:  [String : Any]
            do {
                header = try JWSHandler.extractDataJsonFromJws(jws: jwtRequest, jwsPart: .header)
            } catch {
                throw VerificationFailure(
                    message: "JWS header extraction failed: \(error.localizedDescription)",
                    className: String(describing: type(of: self))
                )
            }
            
            let typ: String? = header["typ"] as? String
            if typ != "oauth-authz-req+jwt" {
                throw InvalidData(
                    message: "Invalid typ in JWS header. Expected 'oauth-authz-req+jwt', found '\(typ ?? "nil")'",
                    className: String(describing: type(of: self)),
                    code: OpenID4VPErrorCodes.invalidRequestObject
                )
            }
            
            guard let algorithm = header["alg"] as? String else {
                throw InvalidData(message: "alg is not present in JWS header", className: className, code: OpenID4VPErrorCodes.invalidRequestObject)
            }
            
            try validateAuthorizationRequestSigningAlgorithm(algorithm)
            
            let publicKey = try await delegate.extractPublicKey(keyId: header["kid"] as? String, algorithm: algorithm)
            try await JWSHandler.verify(jws: jwtRequest , publicKey: publicKey)
        } catch {
            throw InvalidData(message: "Request URI response validation failed - \(error.localizedDescription)", className: className, code: OpenID4VPErrorCodes.invalidRequestObject)
        }
    }
    
    func validateAndParseRequestFields() async throws {
        if authorizationRequestParameters[AuthorizationRequestFieldConstants.transactionData.rawValue] != nil {
            throw InvalidTransactionData(message: "Invalid Request: transaction_data is not supported in the authorization request", className: className)
        }
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
        
        authorizationRequestParameters = try specVersionHandler.parseAndValidateClientMetadata(authorizationRequest: authorizationRequestParameters, shouldValidateWithWalletMetadata: shouldValidateWithWalletMetadata, walletMetadata: walletMetadata)
        
        try await specVersionHandler.validatePresentationRequest(authorizationRequestParameters: &authorizationRequestParameters, networkManager: networkManager)
    }
    
    final func setResponseUrl() throws {
        let responseMode = getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.responseMode.rawValue])
        
        try ResponseModeBasedHandlerFactory.get(responseMode: responseMode).setResponseUrl(authorizationRequestParameters: authorizationRequestParameters,setResponseUri: setResponseUri)
    }
    
    private func isClientIdPrefixSupported(walletMetadata: WalletMetadata) throws {
        let clientIdPrefix = delegate.clientIdPrefix()
        var walletSupportedClientIdPrefixes = walletMetadata.clientIdPrefixesSupported.compactMap { $0.rawValue }
        if walletSupportedClientIdPrefixes.contains(ClientIdPrefix.decentralizedIdentifier.rawValue) {
            walletSupportedClientIdPrefixes.append(ClientIdPrefix.toClientIdScheme(.decentralizedIdentifier))
        }
        if !walletSupportedClientIdPrefixes.contains(clientIdPrefix) {
            throw InvalidData(
                message: "client_id_prefix is not supported by wallet",
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
            throw InvalidData(message: "wallet_nonce provided in the authorization request is not the same as shared by wallet", className: self.className)
        }
    }
    
    final func createAuthorizationRequest() -> AuthorizationRequest {
        return specVersionHandler.getAuthorizationRequest(authorizationRequestParameters: authorizationRequestParameters)
    }
    
    private enum SpecVersionHandler {
        case specV1, draft23
        
        static func from(_ specVersion: SpecVersion) -> SpecVersionHandler {
            return specVersion == .v1 ? .specV1 : .draft23
        }

        func parseAndValidateClientMetadata(authorizationRequest: [String: Any], shouldValidateWithWalletMetadata: Bool, walletMetadata: WalletMetadata?) throws -> [String: Any] {
            let clientMetadataHandler: ClientMetadataSpecVersionHandler = self == .draft23 ? .draft23 : .v1
            return try clientMetadataHandler.parseAndValidate(authorizationRequest: authorizationRequest, shouldValidateWithWalletMetadata: shouldValidateWithWalletMetadata, walletMetadata: walletMetadata)
        }

        func validatePresentationRequest(authorizationRequestParameters: inout [String: Any], networkManager: NetworkManaging) async throws {
            switch self {
            case .specV1:
                //                TODO: Parse and validate DCQL query
                // require_cryptographic_holder_binding - is false in all credential queries and not direct post then, state can be optional else required
                // TODO: add check for state parameter based on presence of require_cryptographic_holder_binding
                let responseMode = getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.responseMode.rawValue])
                if responseMode == ResponseMode.directPost.rawValue {
                    try validateAttribute(AuthorizationRequestFieldConstants.state.rawValue, values: authorizationRequestParameters)
                }
                return
            case .draft23:
                authorizationRequestParameters = try await parseAndValidatePresentationDefinition(authorizationRequestParameters, true, networkManager)
            }
        }
        
        func getAuthorizationRequest(authorizationRequestParameters: [String: Any]) -> AuthorizationRequest {
            switch self {
            case .draft23:
                return AuthorizationPresentationExchangeRequest(
                    clientId: getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.clientId.rawValue])!,
                    responseType: getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.responseType.rawValue])!,
                    responseMode: getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.responseMode.rawValue]),
                    responseUri: getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.responseUri.rawValue]),
                    redirectUri: getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.redirectUri.rawValue]),
                    nonce: getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.nonce.rawValue])!,
                    walletNonce: getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.walletNonce.rawValue]),
                    state: getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.state.rawValue]),
                    presentationDefinition: authorizationRequestParameters[AuthorizationRequestFieldConstants.presentationDefinition.rawValue]! as! PresentationDefinition,
                    clientMetadata: authorizationRequestParameters[AuthorizationRequestFieldConstants.clientMetadata.rawValue] as? ClientMetadataDraft23
                )
            case .specV1:
                return AuthorizationDcqlRequest(
                    clientId: getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.clientId.rawValue])!,
                    responseType: getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.responseType.rawValue])!,
                    responseMode: getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.responseMode.rawValue]),
                    responseUri: getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.responseUri.rawValue]),
                    redirectUri: getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.redirectUri.rawValue]),
                    nonce: getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.nonce.rawValue])!,
                    walletNonce: getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.walletNonce.rawValue]),
                    state: getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.state.rawValue]),
                    clientMetadata: authorizationRequestParameters[AuthorizationRequestFieldConstants.clientMetadata.rawValue] as? ClientMetadata
                )
            }
        }
    }
}

typealias ClientIdPrefixBasedAuthorizationRequestHandler = ClientIdPrefixBasedAuthorizationRequestHandlerBaseClass & AbstractMethodsForClientIdPrefixBasedAuthorizationRequestHandler
