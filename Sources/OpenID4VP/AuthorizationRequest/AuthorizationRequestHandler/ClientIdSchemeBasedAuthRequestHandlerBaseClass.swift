import Foundation


protocol AbstractMethodsForClientIdSchemeBasedAuthRequestHandler {
    func gatherAuthRequestImpl() async throws  -> [String: Any]
}

class ClientIdSchemeBasedAuthRequestHandlerBaseClass  {
    var delegate: AbstractMethodsForClientIdSchemeBasedAuthRequestHandler!
    var authRequestParam: [String: Any]
    let networkManager: NetworkManaging
    let setResponseUri: (String) -> Void
    let className = String(describing: ClientIdSchemeBasedAuthRequestHandlerBaseClass.self)
    
    init(authRequestParam: [String: Any], networkManager: NetworkManaging, setResponseUri: @escaping (String) -> Void) {
        self.authRequestParam = authRequestParam
        self.setResponseUri = setResponseUri
        self.networkManager = networkManager
    }
    
    func validateClientId() throws {
        try validateKey(AuthorizationRequestFieldConstants.clientId.rawValue, values: authRequestParam)
    }
    
    func gatherAuthRequest() async throws{
        let authRequestParam = try await delegate.gatherAuthRequestImpl()
        self.authRequestParam = authRequestParam
    }
    
    func gatherInfoForSendingResponseToVerifier() throws {
        let responseMode = getStringValue(authRequestParam[AuthorizationRequestFieldConstants.responseMode.rawValue]) ?? ResponseMode.fragment.rawValue
        authRequestParam[AuthorizationRequestFieldConstants.responseMode.rawValue] = responseMode
        
        switch (responseMode) {
        case ResponseMode.directPost.rawValue:
            try validateKey(AuthorizationRequestFieldConstants.responseUri.rawValue, values: authRequestParam)
            setResponseUri(authRequestParam[AuthorizationRequestFieldConstants.responseUri.rawValue] as! String)
        case ResponseMode.fragment.rawValue:
            try validateKey(AuthorizationRequestFieldConstants.redirectUri.rawValue, values: authRequestParam)
            setResponseUri(authRequestParam[AuthorizationRequestFieldConstants.redirectUri.rawValue] as! String)
            throw Logger.handleException(exceptionType: "invalidResponseMode", className: self.className)
        default:
            throw Logger.handleException(exceptionType: "invalidResponseMode", className: self.className)
        }
    }
    
    func validateAndParseRequestFields() async throws {
        let mandatoryFields = [AuthorizationRequestFieldConstants.responseType.rawValue,AuthorizationRequestFieldConstants.nonce.rawValue, AuthorizationRequestFieldConstants.state.rawValue
        ]
        for field in mandatoryFields {
            try validateKey(field, values: authRequestParam)
        }
        authRequestParam = try parseAndValidateClientMetadataInAuthorizationRequest(authRequestParam)
        authRequestParam = try await parseAndValidatePresentationDefinitionInAuthorizationRequest(params: authRequestParam, networkManager: networkManager)
    }
}

typealias ClientIdSchemeBasedAuthRequestHandler = ClientIdSchemeBasedAuthRequestHandlerBaseClass & AbstractMethodsForClientIdSchemeBasedAuthRequestHandler
