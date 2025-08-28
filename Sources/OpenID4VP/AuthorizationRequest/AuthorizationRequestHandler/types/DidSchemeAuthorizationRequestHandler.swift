import Foundation
class DidSchemeAuthorizationRequestHandler:  ClientIdSchemeBasedAuthorizationRequestHandler {
    override init(authorizationRequestParameters: [String: Any],
                  walletMetadata: WalletMetadata? = nil,
                  setResponseUri: @escaping (String) -> Void,
                  walletNonce: String,
                  networkManager: NetworkManaging) {
        super.init(authorizationRequestParameters: authorizationRequestParameters,
                   walletMetadata: walletMetadata,
                   setResponseUri: setResponseUri,
                   walletNonce: walletNonce,
                   networkManager: networkManager)
        delegate = self
        super.className = String(describing: DidSchemeAuthorizationRequestHandler.self)
    }
    
    func clientIdScheme() -> String {
        return ClientIdScheme.did.rawValue
    }
    
    func isRequestUriSupported() -> Bool {
        return true
    }
    
    
    func isRequestObjectSupported() -> Bool {
        return false
    }
    
    func extractPublicKey(keyId: String, algorithm: String) async throws -> PublicKeyType {
        let keyResolver: PublicKeyResolver = DidPublicKeyResolver(networkManager: networkManager)
        
        return try await keyResolver.resolve(uri: authorizationRequestParameters[AuthorizationRequestFieldConstants.clientId.rawValue] as! String, keyId: keyId)
    }
    
    func validateRequestUriResponse(requestUriResponse:  (body: String, httpUrlResponse: HTTPURLResponse)?,walletNonce: String, isMismatchedAcceptableType: Bool) async throws {
        if (isMismatchedAcceptableType) {
            throw InvalidData(
                message: "Authorization Request must be signed and contain JWT for given client_id_scheme - did",
                className: className
            )
        }
        if let requestUriResponse = requestUriResponse {
            let isContentTypeJWT = requestUriResponse.httpUrlResponse.isHeaderContentType(equalTo: ContentTypes.applicationJwt.rawValue)
            if (isContentTypeJWT && isJWS(requestUriResponse.body)) {
                let clientId: String = authorizationRequestParameters[AuthorizationRequestFieldConstants.clientId.rawValue] as! String
                let actualAuthorizationRequestObject = requestUriResponse.body
                
                let keyResolver: PublicKeyResolver = DidPublicKeyResolver(networkManager: networkManager)
                
                let header = try JWSHandler.extractDataJsonFromJws(jws: actualAuthorizationRequestObject,jwsPart: .header)
                try validateAuthorizationRequestSigningAlgorithm(header: header)
                
                try await JWSHandler.verify(jws: actualAuthorizationRequestObject , publicKeyResolver: keyResolver, verificationMethodUri: clientId)
                
                let authorizationRequestObject =  try JWSHandler.extractDataJsonFromJws(jws: actualAuthorizationRequestObject, jwsPart: .payload)
                
                // wallet_nonce is passed in the POST request to request_uri,so the Request URI response must have wallet_nonce and Wallet MUST validate whether the request object contains the respective nonce value in a wallet_nonce claim.
                let requestUriMethod = try determineHttpMethod(method: authorizationRequestParameters[AuthorizationRequestFieldConstants.requestUriMethod.rawValue] as? String ?? HttpMethod.get.rawValue)
                if( requestUriMethod == .post) {
                    try validateWalletNonce(authorizationRequestObject, walletNonce)
                }
                
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
