import Foundation
class RedirectUriSchemeAuthorizationRequestHandler:  ClientIdSchemeBasedAuthorizationRequestHandler {
    override init(authorizationRequestParameters: [String: Any], networkManager: NetworkManaging, setResponseUri: @escaping (String) -> Void) {
        super.init(authorizationRequestParameters: authorizationRequestParameters, networkManager: networkManager, setResponseUri: setResponseUri)
        delegate = self
    }
    
    func validateRequestUriResponse() async throws {
        if let requestUriResponse = self.requestUriResponse {
            let isContentTypeNotJson = !requestUriResponse.httpUrlResponse.isHeaderContentType(equalTo: ContentTypes.applicationJson.rawValue)
            if (isContentTypeNotJson || isJWT(requestUriResponse.body)) {
                throw Logger.handleException(
                    exceptionType: "InvalidData",
                    message: "Authorization Request must not be signed for given client_id_scheme",
                    className: RedirectUriSchemeAuthorizationRequestHandler.className
                )
            }
            guard let responseBody = requestUriResponse.body.data(using: .utf8) else {
                throw Logger.handleException(
                    exceptionType: "InvalidData",
                    message: "Conversion failed",
                    className: RedirectUriSchemeAuthorizationRequestHandler.className
                )
            }
            guard let authorizationRequestObject = try JSONSerialization.jsonObject(with: responseBody, options: []) as? [String: Any]  else {
                throw Logger.handleException(
                    exceptionType: "InvalidData",
                    message: "Conversion failed",
                    className: RedirectUriSchemeAuthorizationRequestHandler.className
                )
            }

            try validateAuthorizationRequestObjectAndParameters(params: authorizationRequestParameters as! [String : String], requestUriParams: authorizationRequestObject)    
            
            self.authorizationRequestParameters = authorizationRequestObject
        }
    }
    
    override func validateAndParseRequestFields()async throws {
        try await super.validateAndParseRequestFields()
        let responseMode = getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.responseMode.rawValue])
        switch responseMode {
        case ResponseMode.directPost.rawValue:
            try validateUriCombinations(authorizationRequestParameters: authorizationRequestParameters, validAttribute: AuthorizationRequestFieldConstants.responseUri.rawValue, inValidAttribute: AuthorizationRequestFieldConstants.redirectUri.rawValue)
        default:
            throw Logger.handleException(
                exceptionType : "InvalidResponseMode",
                message : "Given response_mode \(String(describing: responseMode)) is not supported", className: RedirectUriSchemeAuthorizationRequestHandler.className
            )
        }
        
    }
    
    private func validateUriCombinations(authorizationRequestParameters: [String: Any], validAttribute: String, inValidAttribute: String) throws {
        if authorizationRequestParameters.keys.contains(inValidAttribute) {
            throw Logger.handleException(
                exceptionType: "invalidInput",
                message: "\(inValidAttribute) should not be present for given response_mode", className: RedirectUriSchemeAuthorizationRequestHandler.className
            )
        } else {
            try validateAttribute(validAttribute, values: self.authorizationRequestParameters)
        }
        
        if let validValue = authorizationRequestParameters[validAttribute], let clientIdValue = authorizationRequestParameters[AuthorizationRequestFieldConstants.clientId.rawValue] as? String, validValue as? String != clientIdValue {
            throw Logger.handleException(
                exceptionType: "InvalidVerifier",
                message: "\(validAttribute) should be equal to client_id for given client_id_scheme", className: RedirectUriSchemeAuthorizationRequestHandler.className
            )
        }
    }
}
