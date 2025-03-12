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
    static let className = String(describing: ClientIdSchemeBasedAuthorizationRequestHandler.self)
    
    init(authorizationRequestParameters: [String: Any], networkManager: NetworkManaging, setResponseUri: @escaping (String) -> Void) {
        self.authorizationRequestParameters = authorizationRequestParameters
        self.setResponseUri = setResponseUri
        self.networkManager = networkManager
    }
    
    func validateClientId() throws {
        try validateAttribute(AuthorizationRequestFieldConstants.clientId.rawValue, values: authorizationRequestParameters)
    }
    
    func fetchAuthorizationRequest() async throws{
        if let requestUri = authorizationRequestParameters["request_uri"] as? String {
            if !isNeitherNullNorEmpty(field: requestUri) || !(requestUri != "null") {
                throw Logger.handleException(exceptionType: "InvalidInput", fieldPath: ["requestUri"], className: ClientIdSchemeBasedAuthorizationRequestHandlerBaseClass.className)
            }
            guard isValidUri(requestUri)
            else {
                throw Logger.handleException(
                    exceptionType: "InvalidData",
                    message: "request_uri \(requestUri) data is not valid",
                    className: ClientIdSchemeBasedAuthorizationRequestHandlerBaseClass.className
                )
            }
            
            let requestUriMethod = authorizationRequestParameters["request_uri_method"] as? String ?? "get"
            let httpMethod = try determineHttpMethod(method: requestUriMethod)
            
            let response = try await networkManager.sendHTTPRequest(url: requestUri, method: httpMethod, bodyParams: nil, headers: nil)
            
            self.requestUriResponse = (response.responseBody, response.httpUrlResponse)
        }
        try await delegate.validateRequestUriResponse()
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
        
        authorizationRequestParameters = try parseAndValidateClientMetadata(authorizationRequest: authorizationRequestParameters)
        authorizationRequestParameters = try await parseAndValidatePresentationDefinition(authorizationRequest: authorizationRequestParameters, networkManager: networkManager)
    }
    
    final func setResponseUrl() throws {
        let responseMode = getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.responseMode.rawValue])
        
        try ResponseModeBasedHandlerFactory.get(responseMode: responseMode).setResponseUrl(authorizationRequestParameters: authorizationRequestParameters,setResponseUri: setResponseUri)
    }
    
    final func createAuthorizationRequest() -> AuthorizationRequest {
        return AuthorizationRequest(
            clientId: getStringValue(authorizationRequestParameters["client_id"])!,
            clientIdScheme: getStringValue(authorizationRequestParameters["client_id_scheme"]) ?? ClientIdScheme.preRegistered.rawValue,
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
