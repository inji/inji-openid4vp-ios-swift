import Foundation


protocol AbstractMethodsForClientIdSchemeBasedAuthorizationRequestHandler {
    func validateRequestUriResponse() async throws
}

class ClientIdSchemeBasedAuthorizationRequestHandlerBaseClass  {
    var delegate: AbstractMethodsForClientIdSchemeBasedAuthorizationRequestHandler!
    var authorizationRequestParameters: [String: Any]
    let networkManager: NetworkManaging
    let setResponseUri: (String) -> Void
    var requestUriResponse: (body: String, httpUrlResponse: HTTPURLResponse)? = nil
    let className = String(describing: ClientIdSchemeBasedAuthorizationRequestHandlerBaseClass.self)
    
    init(authorizationRequestParam: [String: Any], networkManager: NetworkManaging, setResponseUri: @escaping (String) -> Void) {
        self.authorizationRequestParameters = authorizationRequestParam
        self.setResponseUri = setResponseUri
        self.networkManager = networkManager
    }
    
    func validateClientId() throws {
        try validateKey(AuthorizationRequestFieldConstants.clientId.rawValue, values: authorizationRequestParameters)
    }
    
    func fetchAuthRequest() async throws{
        if let requestUri = authorizationRequestParameters["request_uri"] as? String {
            guard isValidUri(requestUri)
            else {
                throw Logger.handleException(
                    exceptionType: "InvalidData",
                    message: "request_uri data is not valid",
                    className: AuthorizationRequest.className
                )
            }
            
            if !isNeitherNullNorEmpty(field: requestUri) || !(requestUri != "null") {
                throw Logger.handleException(exceptionType: "InvalidInput", fieldPath: ["requestUri"], className: AuthorizationRequest.className)
            }
            let requestUriMethod = authorizationRequestParameters["request_uri_method"] as? String ?? "get"
            let httpMethod = try determineHttpMethod(method: requestUriMethod)
            
            guard let url = URL(string: requestUri) else {
                throw Logger.handleException(exceptionType: "UrlCreationFailed", fieldPath: ["request_uri_method"], className: AuthorizationRequest.className)
            }
            
            let response = try await networkManager.sendHTTPRequest(url: url, method: httpMethod, bodyParams: nil, headers: nil)
            
            self.requestUriResponse = (response.responseBody, response.httpUrlResponse)
        }
        try await delegate.validateRequestUriResponse()
    }
    
    func setResponseUrlForSendingResponseToVerifier() throws {
        let responseMode = getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.responseMode.rawValue]) ?? ResponseMode.fragment.rawValue
        authorizationRequestParameters[AuthorizationRequestFieldConstants.responseMode.rawValue] = responseMode
        
        switch (responseMode) {
        case ResponseMode.directPost.rawValue:
            try validateKey(AuthorizationRequestFieldConstants.responseUri.rawValue, values: authorizationRequestParameters)
            guard isValidUri(authorizationRequestParameters[AuthorizationRequestFieldConstants.responseUri.rawValue] as! String)
            else {
                throw Logger.handleException(
                    exceptionType: "InvalidData",
                    message: "response_uri data is not valid",
                    className: AuthorizationRequest.className
                )
            }
            setResponseUri(authorizationRequestParameters[AuthorizationRequestFieldConstants.responseUri.rawValue] as! String)
        default:
            throw Logger.handleException(exceptionType: "invalidResponseMode", className: self.className)
        }
    }
    
    func validateAndParseRequestFields() async throws {
        let mandatoryFields = [AuthorizationRequestFieldConstants.responseType.rawValue,AuthorizationRequestFieldConstants.nonce.rawValue, AuthorizationRequestFieldConstants.state.rawValue
        ]
        for field in mandatoryFields {
            try validateKey(field, values: authorizationRequestParameters)
        }
        authorizationRequestParameters = try parseAndValidateClientMetadata(authorizationRequest: authorizationRequestParameters)
        authorizationRequestParameters = try await parseAndValidatePresentationDefinition(authorizationRequest: authorizationRequestParameters, networkManager: networkManager)
    }
    
    func createAuthorizationRequest() -> AuthorizationRequest {
        return AuthorizationRequest(
            clientId: getStringValue(authorizationRequestParameters["client_id"])!,
            clientIdScheme: getStringValue(authorizationRequestParameters["client_id_scheme"]) ?? ClientIdScheme.preRegistered.rawValue,
            presentationDefinition: authorizationRequestParameters["presentation_definition"]! as! PresentationDefinition,
            responseType: getStringValue(authorizationRequestParameters["response_type"])!,
            responseMode: getStringValue(authorizationRequestParameters["response_mode"]),
            nonce: getStringValue(authorizationRequestParameters["nonce"])!,
            state: getStringValue(authorizationRequestParameters["state"])!,
            redirectUri: getStringValue(authorizationRequestParameters["redirect_uri"]),
            responseUri: getStringValue(authorizationRequestParameters["response_uri"]),
            clientMetadata: authorizationRequestParameters["client_metadata"] as? ClientMetadata
        )
    }
}

typealias ClientIdSchemeBasedAuthorizationRequestHandler = ClientIdSchemeBasedAuthorizationRequestHandlerBaseClass & AbstractMethodsForClientIdSchemeBasedAuthorizationRequestHandler
