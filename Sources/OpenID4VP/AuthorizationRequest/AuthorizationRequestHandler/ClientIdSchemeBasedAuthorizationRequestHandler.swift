import Foundation


protocol AbstractMethodsForClientIdSchemeBasedAuthorizationRequestHandler {
    func fetchAuthRequestImpl() async throws  -> [String: Any]
}

class ClientIdSchemeBasedAuthorizationRequestHandlerBaseClass  {
    var delegate: AbstractMethodsForClientIdSchemeBasedAuthorizationRequestHandler!
    var authorizationRequestParameters: [String: Any]
    let networkManager: NetworkManaging
    let setResponseUri: (String) -> Void
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
        let authorizationRequestParameters = try await delegate.fetchAuthRequestImpl()
        self.authorizationRequestParameters = authorizationRequestParameters
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
        authorizationRequestParameters = try parseAndValidateClientMetadataInAuthorizationRequest(authorizationRequestParameters)
        authorizationRequestParameters = try await parseAndValidatePresentationDefinitionInAuthorizationRequest(params: authorizationRequestParameters, networkManager: networkManager)
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
