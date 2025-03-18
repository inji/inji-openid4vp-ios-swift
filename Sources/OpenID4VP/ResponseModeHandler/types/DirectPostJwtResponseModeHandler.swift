import Foundation


struct DirectPostJwtResponseModeHandler : ResponseModeBasedHandler {
    static let className = String(describing: DirectPostJwtResponseModeHandler.self)
    func validate(clientMetadata: ClientMetadata?) throws {
        guard let clientMetadataObject = clientMetadata else {
            throw Logger.handleException(
                exceptionType: "InvalidData",
                message: "client_metadata must be present for given response mode",
                className: DirectPostJwtResponseModeHandler.className
            )
        }
        guard let alg = clientMetadataObject.authorization_encrypted_response_alg else {
            throw Logger.handleException(
                exceptionType: "MissingInput",
                fieldPath: ["client_metadata", "authorization_encrypted_response_alg"],
                className: DirectPostJwtResponseModeHandler.className
            )
        }

        if (clientMetadataObject.authorization_encrypted_response_enc) == nil {
            throw Logger.handleException(
                exceptionType: "MissingInput",
                fieldPath: ["client_metadata", "authorization_encrypted_response_enc"],
                className: DirectPostJwtResponseModeHandler.className
            )
        }

        guard let jwks = clientMetadataObject.jwks else {
            throw Logger.handleException(
                exceptionType: "MissingInput",
                fieldPath: ["client_metadata", "jwks"],
                className: DirectPostJwtResponseModeHandler.className
            )
        }

        if !jwks.keys.contains(where: { $0.alg == alg }) {
            throw Logger.handleException(
                exceptionType: "InvalidData",
                message: "No jwk matching the specified algorithm found",
                fieldPath: ["jwks", "keys"],
                className: DirectPostJwtResponseModeHandler.className
            )
        }
    }
    
    func sendAuthorizationResponse(authorizationRequest: AuthorizationRequest, authorizationResponse: AuthorizationResponse, url: String, networkManager: any NetworkManaging) async throws -> String {
        let bodyParams = try authorizationResponse.toJsonEncodedMap()
        let clientMetadata = (authorizationRequest.clientMetadata)!
        let verifierPublicKey = try getJwk(clientMetadata.jwks!, clientMetadata.authorization_encrypted_response_alg!)
        
        let encryptedBody = try JWEHandler(contentEncryptionAlgorithm: clientMetadata.authorization_encrypted_response_enc!, keyEncryptionAlgorithm: clientMetadata.authorization_encrypted_response_alg!, publicKey: verifierPublicKey).generateEncryptedResponse(payload: bodyParams)
        
        let requestBody = ["response": encryptedBody]
        let response = try await networkManager.sendHTTPRequest(url: url, method: .post, bodyParams: requestBody, headers: [Header.contentType.rawValue : ContentTypes.applicationFormUrlEncoded])
        
        return response.responseBody
    }
    
    private func getJwk(_ jwks: JWKS, _ alg: String) throws -> JWK {
        return jwks.keys.first(where: { $0.alg == alg })!
    }
}
