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
    
    func validateRequestUriResponse(requestUriResponse:  (body: String, httpUrlResponse: HTTPURLResponse)?, isMismatchedAcceptableType: Bool) async throws {
        if let requestUriResponse = requestUriResponse {
            let isContentTypeJWT = requestUriResponse.httpUrlResponse.isHeaderContentType(equalTo: ContentTypes.applicationJwt.rawValue)
            if (!isMismatchedAcceptableType && isContentTypeJWT && isJWS(requestUriResponse.body)) {
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
                throw InvalidData(message: "Authorization Request must be signed and contain JWT for given client_id_scheme - did", className: className)
            }
        } else {
            throw MissingInput(fieldPath: ["request_uri"], message : "request_uri must be present for given client_id_scheme",
                className: className)
        }
    }
    
    func process(walletMetadata: WalletMetadata) throws -> WalletMetadata {
        if(walletMetadata.requestObjectSigningAlgValuesSupported == nil) {
            throw InvalidData(message: "request_object_signing_alg_values_supported is not present in wallet metadata.",
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
               let supportedAlgs = walletMetadata.requestObjectSigningAlgValuesSupported?.compactMap({$0.rawValue}) ,
               !supportedAlgs.contains(alg) {
                throw InvalidData(
                    message: "request_object_signing_alg is not supported by wallet",
                    className: className
                )
            }
        }
    }
}
