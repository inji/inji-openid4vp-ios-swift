import Foundation

protocol ResponseModeBasedHandler {
    func validate(clientMetadata: ClientMetadata?) throws
    func sendAuthorizationResponse(
        authorizationRequest: AuthorizationRequest,
        authorizationResponse: AuthorizationResponse,
        url: String,
        networkManager: NetworkManaging
    ) async throws -> String
    func setResponseUrl(authorizationRequestParameters: [String : Any], setResponseUri: (String) -> Void) throws
}

extension ResponseModeBasedHandler {
    func setResponseUrl(authorizationRequestParameters: [String : Any], setResponseUri: (String) -> Void) throws {
        
        try validateAttribute(AuthorizationRequestFieldConstants.responseUri.rawValue, values: authorizationRequestParameters)
        
        guard isValidUri(authorizationRequestParameters[AuthorizationRequestFieldConstants.responseUri.rawValue] as! String)
        else {
            throw Logger.handleException(
                exceptionType: "InvalidData",
                message: "response_uri data is not valid",
                className: ClientIdSchemeBasedAuthorizationRequestHandlerBaseClass.className
            )
        }
        setResponseUri(authorizationRequestParameters[AuthorizationRequestFieldConstants.responseUri.rawValue] as! String)
    }
}
