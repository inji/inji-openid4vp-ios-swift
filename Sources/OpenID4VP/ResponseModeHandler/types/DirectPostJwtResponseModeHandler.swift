import Foundation


struct DirectPostJwtResponseModeHandler : ResponseModeBasedHandler {
    
    let className = String(describing: DirectPostJwtResponseModeHandler.self)
    func validate(clientMetadata: ClientMetadata?,
                  walletMetadata: WalletMetadata?,
                  shouldValidateWithWalletMetadata: Bool) throws {
        
        guard clientMetadata != nil else {
            return try throwInvalidDataException(message: "client_metadata must be present for given response mode")
        }
        
        guard let alg = clientMetadata?.authorizationEncryptedResponseAlg else {
            return try throwMissingInputException(fieldName: "authorization_encrypted_response_alg")
        }
        guard let enc = clientMetadata?.authorizationEncryptedResponseEnc else {
            return try throwMissingInputException(fieldName: "authorization_encrypted_response_enc")
        }
        guard let jwks = clientMetadata?.jwks else {
            return try throwMissingInputException(fieldName: "jwks")
        }
        
        if shouldValidateWithWalletMetadata {
            try validateWithWalletMetadata(clientAlg: alg,
                                           clientEnc: enc,
                                           walletMetadata: walletMetadata)
        }
        
        if !jwks.keys.contains(where: { $0.alg == alg && $0.use == "enc"}) {
            try throwInvalidDataException(message: "No jwk matching the specified algorithm found for encryption")
        }
    }
    
    private func validateWithWalletMetadata(clientAlg: String,
                                    clientEnc: String,
                                    walletMetadata: WalletMetadata?
    ) throws {
        guard let walletMetadata = walletMetadata else {
            return try throwInvalidDataException(message: "wallet_metadata must be present")
        }
        
        guard let supportedEncryptionAlgorithms = walletMetadata.authorizationEncryptionAlgValuesSupported?.compactMap({$0.rawValue}) else {
            return try throwInvalidDataException(message: "authorization_encryption_alg_values_supported must be present in wallet_metadata")
        }
        
        guard supportedEncryptionAlgorithms.contains(clientAlg) else {
            return try throwInvalidDataException(message: "authorization_encrypted_response_alg is not supported")
        }
        
        guard let supportedEncryptions = walletMetadata.authorizationEncryptionEncValuesSupported else {
            return try throwInvalidDataException(message: "authorization_encryption_enc_values_supported must be present in wallet_metadata")
        }
        
        guard supportedEncryptions.contains(clientEnc) else {
            return try throwInvalidDataException(message: "authorization_encrypted_response_enc is not supported")
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
    
    func sendAuthorizationResponse(authorizationRequest: AuthorizationRequest, authorizationResponse: AuthorizationResponse, url: String, networkManager: any NetworkManaging, producerInfo: String,
    recepientInfo: String) async throws -> String {
        let bodyParams = try authorizationResponse.toJsonEncodedMap()
        let clientMetadata = (authorizationRequest.clientMetadata)!
        let verifierPublicKey = try getJwk(clientMetadata.jwks!, clientMetadata.authorizationEncryptedResponseAlg!)
        
        let encryptedBody = try JWEHandler(contentEncryptionAlgorithm: clientMetadata.authorizationEncryptedResponseEnc!, keyEncryptionAlgorithm: clientMetadata.authorizationEncryptedResponseAlg!, publicKey: verifierPublicKey, producerInfo: producerInfo, recipientInfo: recepientInfo).generateEncryptedResponse(payload: bodyParams)
        
        let requestBody = ["response": encryptedBody]
        let response = try await networkManager.sendHTTPRequest(url: url, method: .post, bodyParams: requestBody, headers: [Header.contentType.rawValue : ContentTypes.applicationFormUrlEncoded.rawValue])
        
        return response.responseBody
    }
    
    private func getJwk(_ jwks: JWKS, _ alg: String) throws -> JWK {
        return jwks.keys.first(where: { $0.alg == alg && $0.use == "enc"})!
    }
}
