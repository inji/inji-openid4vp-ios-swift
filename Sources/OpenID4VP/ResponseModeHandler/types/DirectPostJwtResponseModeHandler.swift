import Foundation
import JSONWebKey


struct DirectPostJwtResponseModeHandler : ResponseModeBasedHandler {

    let className = String(describing: DirectPostJwtResponseModeHandler.self)
    func validate(clientMetadata: ClientMetadata?,
                  walletMetadata: WalletMetadata?,
                  shouldValidateWithWalletMetadata: Bool) throws {

        guard clientMetadata != nil else {
            throw InvalidData(
                  message: "client_metadata must be present for given response mode",
                  className: className
              )
        }

        guard let alg = clientMetadata?.authorizationEncryptedResponseAlg else {
            throw MissingInput(fieldPath: ["client_metadata", "authorization_encrypted_response_alg"],
                               message: "",
                               className: className)
        }
        guard let enc = clientMetadata?.authorizationEncryptedResponseEnc else {
            throw MissingInput(fieldPath: ["client_metadata", "authorization_encrypted_response_enc"],
                                           message: "",
                                           className: className)
        }
        guard let jwks = clientMetadata?.jwks else {
            throw MissingInput(fieldPath: ["client_metadata", "jwks"],
                                 message: "",
                                 className: className)
        }

        if shouldValidateWithWalletMetadata {
            try validateWithWalletMetadata(clientAlg: alg,
                                           clientEnc: enc,
                                           walletMetadata: walletMetadata)
        }

        if !jwks.keys.contains(where: { $0.algorithm == alg && $0.publicKeyUse == .encryption}) {
            throw InvalidData(
                message: "No jwk matching the specified algorithm found for encryption",
                className: className
            )
        }
    }

    /// Validate that the client's key and content encryption algorithms are supported by the provided wallet metadata.
    /// - Parameters:
    ///   - clientAlg: The client's key encryption algorithm identifier (e.g., RSA-OAEP-256).
    ///   - clientEnc: The client's content encryption algorithm identifier (e.g., A256GCM).
    ///   - walletMetadata: Wallet metadata containing supported encryption algorithms and encodings.
    /// - Throws: `InvalidData` when:
    ///   - `walletMetadata` is `nil` (`"wallet_metadata must be present"`).
    ///   - `authorization_encryption_alg_values_supported` is missing from `walletMetadata` (`"authorization_encryption_alg_values_supported must be present in wallet_metadata"`).
    ///   - `clientAlg` is not listed in `authorization_encryption_alg_values_supported` (`"authorization_encrypted_response_alg is not supported"`).
    ///   - `authorization_encryption_enc_values_supported` is missing from `walletMetadata` (`"authorization_encryption_enc_values_supported must be present in wallet_metadata"`).
    ///   - `clientEnc` is not listed in `authorization_encryption_enc_values_supported` (`"authorization_encrypted_response_enc is not supported"`).
    private func validateWithWalletMetadata(clientAlg: String,
                                            clientEnc: String,
                                            walletMetadata: WalletMetadata?) throws {
        guard let walletMetadata = walletMetadata else {
            throw InvalidData(message: "wallet_metadata must be present", className: className)
        }

        guard let supportedEncryptionAlgorithms = walletMetadata.authorizationEncryptionAlgValuesSupported?.compactMap({$0.rawValue}) else {
            throw InvalidData(message: "authorization_encryption_alg_values_supported must be present in wallet_metadata", className: className)
        }

        guard supportedEncryptionAlgorithms.contains(clientAlg) else {
            throw InvalidData(message: "authorization_encrypted_response_alg is not supported", className: className)
        }

        guard let supportedEncryptions = walletMetadata.authorizationEncryptionEncValuesSupported?.compactMap({$0.rawValue}) else {
            throw InvalidData(message: "authorization_encryption_enc_values_supported must be present in wallet_metadata", className: className)
        }

        guard supportedEncryptions.contains(clientEnc) else {
            throw InvalidData(message: "authorization_encrypted_response_enc is not supported", className: className)
        }
    }

    /// Sends the authorization response as a JWE-encrypted form POST to the given endpoint.
    /// 
    /// The function serializes the authorization response, encrypts it using the client's declared key algorithms and JWKS, and posts it as the "response" form field.
    /// - Parameters:
    ///   - authorizationRequest: The original authorization request containing client metadata and JWKS.
    ///   - authorizationResponse: The authorization response payload to be serialized and encrypted.
    ///   - url: The destination URL for the POST request.
    ///   - networkManager: Network manager used to perform the HTTP request.
    ///   - producerInfo: Identifier or metadata for the message producer included in the JWE envelope.
    ///   - recepientInfo: Identifier or metadata for the message recipient included in the JWE envelope.
    /// - Returns: The HTTP `NetworkResponse` returned by the network manager after sending the POST request.
    func sendAuthorizationResponse(authorizationRequest: AuthorizationRequest, authorizationResponse: AuthorizationResponse, url: String, networkManager: any NetworkManaging, producerInfo: String,
                                   recepientInfo: String) async throws -> NetworkResponse {
        let bodyParams = try authorizationResponse.toJsonEncodedMap()
        let clientMetadata = (authorizationRequest.clientMetadata)!
        let verifierPublicKey = try getJwk(clientMetadata.jwks!, clientMetadata.authorizationEncryptedResponseAlg!)

        let encryptedBody = try JWEHandler(contentEncryptionAlgorithm: clientMetadata.authorizationEncryptedResponseEnc!, keyEncryptionAlgorithm: clientMetadata.authorizationEncryptedResponseAlg!, publicKey: verifierPublicKey, producerInfo: producerInfo, recipientInfo: recepientInfo).generateEncryptedResponse(payload: bodyParams)

        let requestBody = ["response": encryptedBody]
        let response = try await networkManager.sendHTTPRequest(url: url, method: .post, bodyParams: requestBody, headers: [Header.contentType.rawValue : ContentTypes.applicationFormUrlEncoded.rawValue])

        return response
    }

    /// Selects the first JSON Web Key in the provided set whose algorithm matches `alg` and whose use is encryption.
    /// - Parameters:
    ///   - jwks: The JWK set to search.
    ///   - alg: The key algorithm identifier to match.
    /// - Returns: The first `JWK` whose `algorithm` equals `alg` and whose `publicKeyUse` is `.encryption`.
    private func getJwk(_ jwks: JWKSet, _ alg: String) throws -> JWK {
        return jwks.keys.first(where: { $0.algorithm == alg && $0.publicKeyUse == .encryption})!
    }
}