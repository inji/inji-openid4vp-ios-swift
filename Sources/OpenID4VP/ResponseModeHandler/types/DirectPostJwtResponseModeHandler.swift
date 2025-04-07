import Foundation


struct DirectPostJwtResponseModeHandler : ResponseModeBasedHandler {
    
    let className = String(describing: DirectPostJwtResponseModeHandler.self)
    func validate(clientMetadata: ClientMetadata?,
                  walletMetadata: WalletMetadata?,
                  shouldValidateWithWalletMetadata: Bool) throws {
        
        guard let clientMetadataObject = clientMetadata else {
            throw Logger.handleException(
                exceptionType: "InvalidData",
                message: "client_metadata must be present for given response mode",
                className: className
            )
        }
        
        try validateMandatoryField(clientMetadata: clientMetadataObject)
        
        if shouldValidateWithWalletMetadata {
            try validateDataWithWalletMetadata(clientMetadata: clientMetadataObject, walletMetadata: walletMetadata)
        }
    }
    
    private func validateMandatoryField(clientMetadata: ClientMetadata) throws {
        guard let alg = clientMetadata.authorization_encrypted_response_alg else {
            return try throwMissingInputException(fieldName: "authorization_encrypted_response_alg")
        }
        guard clientMetadata.authorization_encrypted_response_enc != nil else {
            return try throwMissingInputException(fieldName: "authorization_encrypted_response_enc")
        }
        guard let jwks = clientMetadata.jwks else {
            return try throwMissingInputException(fieldName: "jwks")
        }

        if !jwks.keys.contains(where: { $0.alg == alg }) {
            try throwInvalidDataException(message: "No jwk matching the specified algorithm found")
        }
    }
    
    private func validateDataWithWalletMetadata(clientMetadata: ClientMetadata, walletMetadata: WalletMetadata?) throws  {
        guard let walletMetadata = walletMetadata else {
            return try throwInvalidDataException(message: "wallet_metadata must be present")
        }

        if let encSupported = walletMetadata.authorizationEncryptionEncValuesSupported {
            if !encSupported.contains(clientMetadata.authorization_encrypted_response_enc!) {
                return try throwInvalidDataException(message: "authorization_encrypted_response_enc is not supported")
            }
        } else {
            return try throwInvalidDataException(message: "authorization_encryption_enc_values_supported must be present in wallet_metadata")
        }

        if let algSupported = walletMetadata.authorizationEncryptionAlgValuesSupported {
            if !algSupported.contains(clientMetadata.authorization_encrypted_response_alg!) {
                return try throwInvalidDataException(message: "authorization_encrypted_response_alg is not supported")
            }
        } else {
            return try throwInvalidDataException(message: "authorization_encryption_alg_values_supported must be present in wallet_metadata")
        }
    }
    
    private func throwMissingInputException(fieldName: String) throws {
        throw Logger.handleException(
            exceptionType: "MissingInput",
            fieldPath: ["client_metadata", fieldName],
            className: className
        )
    }
    
    private func throwInvalidDataException(message: String) throws {
        throw Logger.handleException(
            exceptionType: "InvalidData",
            message: message,
            className: className
        )
    }
    
    func sendAuthorizationResponse(authorizationRequest: AuthorizationRequest, authorizationResponse: AuthorizationResponse, url: String, networkManager: any NetworkManaging) async throws -> String {
        let bodyParams = try authorizationResponse.toJsonEncodedMap()
        let clientMetadata = (authorizationRequest.clientMetadata)!
        let verifierPublicKey = try getJwk(clientMetadata.jwks!, clientMetadata.authorization_encrypted_response_alg!)
        
        let encryptedBody = try JWEHandler(contentEncryptionAlgorithm: clientMetadata.authorization_encrypted_response_enc!, keyEncryptionAlgorithm: clientMetadata.authorization_encrypted_response_alg!, publicKey: verifierPublicKey).generateEncryptedResponse(payload: bodyParams)
        
        let requestBody = ["response": encryptedBody]
        let response = try await networkManager.sendHTTPRequest(url: url, method: .post, bodyParams: requestBody, headers: [Header.contentType.rawValue : ContentTypes.applicationFormUrlEncoded.rawValue])
        
        return response.responseBody
    }
    
    private func getJwk(_ jwks: JWKS, _ alg: String) throws -> JWK {
        return jwks.keys.first(where: { $0.alg == alg })!
    }
}
