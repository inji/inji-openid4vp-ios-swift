import Foundation
class DidSchemeAuthorizationRequestHandler:  ClientIdSchemeBasedAuthorizationRequestHandler {
    override init(authorizationRequestParameters: [String: Any],
                  walletMetadata: WalletMetadata? = nil,
                  setResponseUri: @escaping (String) -> Void,
                  networkManager: NetworkManaging) {
        super.init(authorizationRequestParameters: authorizationRequestParameters,
                   walletMetadata: walletMetadata,
                   setResponseUri: setResponseUri,
                   networkManager: networkManager)
        delegate = self
        super.className = String(describing: DidSchemeAuthorizationRequestHandler.self)
    }
    
    func validateRequestUriResponse(requestUriResponse:  (body: String, httpUrlResponse: HTTPURLResponse)?) async throws {
        if let requestUriResponse = requestUriResponse {
            let isContentTypeJWT = requestUriResponse.httpUrlResponse.isHeaderContentType(equalTo: ContentTypes.applicationJwt.rawValue)
            if (isContentTypeJWT && isJWS(requestUriResponse.body)) {
                let clienId: String = authorizationRequestParameters["client_id"] as! String
                
                let keyResolver: PublicKeyResolver = DidPublicKeyResolver(didUrl: clienId, networkManager: networkManager)
                let jwsHandler = JWSHandler(jws: requestUriResponse.body , publicKeyResolver: keyResolver)
                
                let header = try jwsHandler.extractDataJsonFromJws(jwsPart: .header)
                try validateAuthorizationRequestSigningAlgorithm(header: header)
                
                try await jwsHandler.verify()

                let authorizationRequestObject =  try jwsHandler.extractDataJsonFromJws(jwsPart: .payload)
                
                try validateAuthorizationRequestObjectAndParameters(params: authorizationRequestParameters as! [String:String], requestUriParams: authorizationRequestObject)
                
                self.authorizationRequestParameters = authorizationRequestObject
            }
            else {
                throw Logger.handleException(exceptionType: "InvalidData", message: "Authorization Request must be signed and contain JWT for given client_id_scheme - did", className: className)
            }
        } else {
            throw Logger.handleException(
                exceptionType: "MissingInput",
                message : "request_uri must be present for given client_id_scheme", fieldPath: ["request_uri"],
                className: className)
        }
    }
    
    func process(walletMetadata: WalletMetadata) throws -> WalletMetadata {
        if(walletMetadata.requestObjectSigningAlgValuesSupported == nil) {
            throw Logger.handleException(
                exceptionType: "InvalidData",
                message: "request_object_signing_alg_values_supported is not present in wallet metadata.",
                className: className)
        }
        return walletMetadata
    }
    
    func getHeadersForAuthorizationRequestUri() -> [String : String]? {
        return [Header.contentType.rawValue: ContentTypes.applicationFormUrlEncoded.rawValue,
                Header.accept.rawValue: ContentTypes.applicationJwt.rawValue]
    }
    
    private func validateAuthorizationRequestSigningAlgorithm(header: [String: Any]) throws {
        if shouldValidateWithWalletMetadata, let walletMetadata = walletMetadata {
            if let alg = header["alg"] as? String,
               let supportedAlgs = walletMetadata.requestObjectSigningAlgValuesSupported,
               !supportedAlgs.contains(alg) {
                throw Logger.handleException(
                    exceptionType: "InvalidData",
                    message: "request_object_signing_alg is not supported by wallet",
                    className: className
                )
            }
        }
    }
}
