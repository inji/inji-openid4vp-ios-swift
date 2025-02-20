import Foundation
class DidSchemeAuthRequestHandler:  ClientIdSchemeBasedAuthorizationRequestHandler {
    override init(authorizationRequestParam authorizationRequestParameters: [String: Any], networkManager: NetworkManaging, setResponseUri: @escaping (String) -> Void) {
        super.init(authorizationRequestParam: authorizationRequestParameters, networkManager: networkManager, setResponseUri: setResponseUri)
        delegate = self
    }
    
    override func validateClientId() throws {
        try super.validateClientId()
        let clientId: String = authorizationRequestParameters["client_id"] as! String
        guard clientId.starts(with: "did") else {
            throw Logger.handleException(
                exceptionType: "InvalidVerifier",
                message: "client ID should start with did prefix if client_id_scheme is did", className: className
            )
        }
    }
    
    func validateRequestUriResponse() async throws {
        if let requestUriResponse = self.requestUriResponse {
            let isContentTypeJWT = requestUriResponse.httpUrlResponse.isHeaderContentType(equalTo: ContentTypes.applicationJwt.rawValue)
            if (isContentTypeJWT && isJWT(requestUriResponse.body)) {
                let clienId: String = authorizationRequestParameters["client_id"] as! String
                
                let keyResolver: KeyResolver = DidKeyResolver(didUrl: clienId, networkManager: networkManager)
                let jwtHandler = JWTHandler(jwt: requestUriResponse.body , keyResolver: keyResolver)
                
                try await jwtHandler.verify()
                
                let authorizationRequestObject =  try extractDataJsonFromJwt(jwtToken: requestUriResponse.body , jwtPart: .payload)
                
                try validateMatchOfAuthRequestObjectAndParams(params: authorizationRequestParameters as! [String:String], requestUriParams: authorizationRequestObject)
                
                self.authorizationRequestParameters = authorizationRequestObject
            }
            else {
                throw Logger.handleException(exceptionType: "InvalidData", message: "Authorization Request must be signed and contain JWT for given client_id_scheme", className: self.className)
            }
        } else {
            throw Logger.handleException(
                exceptionType: "MissingInput",
                message : "request_uri must be present for given client_id_scheme", fieldPath: ["request_uri"],
                className: self.className)
        }
    }
}
