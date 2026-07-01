import Foundation
import JSONWebKey


struct DirectPostJwtResponseModeHandler : ResponseModeBasedHandler {
    let className = String(describing: DirectPostJwtResponseModeHandler.self)
    
    func validate(clientMetadata: ClientMetadataDraft23?,
                  walletConfig: WalletConfig,
                  shouldValidateWithWalletMetadata: Bool) throws {
        guard clientMetadata != nil else {
            throw InvalidData(
                  message: "client_metadata must be present for given response mode",
                  className: className
              )
        }

        guard let encryptedResponseAlgorithm = clientMetadata?.authorizationEncryptedResponseAlg else {
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

        try validateEncryption(verifierEncryptionAlg: [encryptedResponseAlgorithm], verifierEnc: enc, jwks: jwks, walletConfig: walletConfig, shouldValidate: shouldValidateWithWalletMetadata)
        _ = try getEncryptionKey(jwks, [encryptedResponseAlgorithm])
    }
    
    func validate(clientMetadata: ClientMetadata?,
                  walletConfig: WalletConfig,
                  shouldValidateWithWalletMetadata: Bool) throws {
        guard clientMetadata != nil else {
            throw InvalidData(
                  message: "client_metadata must be present for given response mode",
                  className: className
              )
        }

        guard let enc = clientMetadata?.encryptedResponseEncValuesSupported else {
            throw MissingInput(fieldPath: ["client_metadata", "encrypted_response_enc_values_supported"],
                                           message: "",
                                           className: className)
        }
        if enc.count == 0 {
            throw InvalidData(message: "encrypted_response_enc_values_supported must be a non-empty array", className: className)
        }
        
        guard let jwks = clientMetadata?.jwks else {
            throw MissingInput(fieldPath: ["client_metadata", "jwks"],
                                 message: "",
                                 className: className)
        }
        
        let encryptionKeys = jwks.keys.filter { $0.publicKeyUse == .encryption }
        guard !encryptionKeys.isEmpty else {
            throw InvalidData(message: "No encryption jwk found in client_metadata.jwks", className: className)
        }
        let verifierEncrptionAlgorithms = encryptionKeys.compactMap { $0.algorithm }
        try validateEncryption(verifierEncryptionAlg: verifierEncrptionAlgorithms, verifierEnc: enc, jwks: jwks, walletConfig: walletConfig, shouldValidate: shouldValidateWithWalletMetadata)
        _ = try getEncryptionKey(jwks, walletConfig.authorizationEncryptionAlgValuesSupported?.compactMap { $0.rawValue } ?? [EncryptionAlgorithm.ecdhES.rawValue])
    }
    
    private func validateEncryption(verifierEncryptionAlg: [String], verifierEnc: Any, jwks: JWKSet, walletConfig: WalletConfig, shouldValidate: Bool) throws {
        if shouldValidate {
            guard let supportedEncryptionAlgorithms = walletConfig.authorizationEncryptionAlgValuesSupported?.compactMap({$0.rawValue}) else {
                throw InvalidData(message: "authorization_encryption_alg_values_supported must be present in wallet_metadata", className: className)
            }

            guard verifierEncryptionAlg.contains(where: { supportedEncryptionAlgorithms.contains($0) }) else {
                throw InvalidData(message: "Authorization response encryption algorithm is not supported", className: className)
            }

            guard let supportedEncryptions = walletConfig.authorizationEncryptionEncValuesSupported?.compactMap({$0.rawValue}) else {
                throw InvalidData(message: "authorization_encryption_enc_values_supported must be present in wallet_metadata", className: className)
            }

            let verifierEncArray = (verifierEnc as? String).map { [$0] } ?? (verifierEnc as? [String]) ?? []
            guard verifierEncArray.contains(where: { encValue in supportedEncryptions.contains(encValue) }) else {
                throw InvalidData(message: "authorization_encrypted_response_enc is not supported", className: className)
            }
        }
    }
    
    func getAuthorizationResponse(
        authorizationRequest: AuthorizationRequest,
        authorizationResponse: AuthorizationResponse,
        walletNonce: String,
        walletConfig: WalletConfig
    ) throws -> [String: String] {
        let responseParams = try authorizationResponse.payloadData()
        return try encryptResponse(
            authorizationRequest: authorizationRequest,
            responseParams: responseParams,
            walletNonce: walletNonce,
            walletConfig: walletConfig
        )
    }
    
    func sendAuthorizationResponse(authorizationRequest: AuthorizationRequest, authorizationResponse: AuthorizationResponse, url: String, networkManager: any NetworkManaging, producerInfo: String,
                                   recipientInfo: String, walletConfig: WalletConfig) async throws -> NetworkResponse {
        let requestBody = try getAuthorizationResponse(authorizationRequest: authorizationRequest, authorizationResponse: authorizationResponse, walletNonce: producerInfo, walletConfig: walletConfig)
        let response = try await networkManager.sendHTTPRequest(url: url, method: .post, bodyParams: requestBody, headers: [Header.contentType.rawValue : ContentTypes.applicationFormUrlEncoded.rawValue])

        return response
    }
    
    func getAuthorizationErrorResponse(
        authorizationRequest: AuthorizationRequest?,
        authorizationResponse: AuthorizationErrorResponse,
        walletNonce: String
    ) throws -> [String: String] {
        return authorizationResponse.toJsonEncodedMap()
    }
    
    func getVerifierPublicKeyForEncryption(
        authorizationRequest: AuthorizationRequest,
        walletConfig: WalletConfig
    ) throws -> JWK? {
        return try SpecVersionHandler.from(authorizationRequest)
            .getVerifierPublicKey(authorizationRequest: authorizationRequest, walletConfig: walletConfig, className: className)
    }
    
    func getResponseEndpoint(authorizationRequest: AuthorizationRequest) throws -> String {
        return try authorizationRequest.responseUri ?? {
            throw InvalidData(message: "response_uri is required in authorization request for response mode 'direct_post.jwt'", className: className)
        }()
    }

    private func encryptResponse(
        authorizationRequest: AuthorizationRequest,
        responseParams: [String: String],
        walletNonce: String,
        walletConfig: WalletConfig
    ) throws -> [String: String] {
        let specVersionHandler = SpecVersionHandler.from(authorizationRequest)
        let jweHandler = try specVersionHandler.getJWEHandler(authorizationRequest: authorizationRequest, walletNonce: walletNonce, walletConfig: walletConfig, className: className)
        let encryptedBody = try jweHandler.encrypt(responseParams)
        return ["response": encryptedBody]
    }
    
    private func encryptResponse(
        authorizationRequest: AuthorizationRequest,
        responseParams: Data,
        walletNonce: String,
        walletConfig: WalletConfig
    ) throws -> [String: String] {
        let specVersionHandler = SpecVersionHandler.from(authorizationRequest)
        let jweHandler = try specVersionHandler.getJWEHandler(authorizationRequest: authorizationRequest, walletNonce: walletNonce, walletConfig: walletConfig, className: className)
        let encryptedBody = try jweHandler.encrypt(responseParams)
        return ["response": encryptedBody]
    }

    private func validateWithWalletMetadata(verifierEncryptionAlg: [String],
                                            verifierEnc: Any,
                                            walletConfig: WalletConfig) throws {
        guard let supportedEncryptionAlgorithms = walletConfig.authorizationEncryptionAlgValuesSupported?.compactMap({$0.rawValue}) else {
            throw InvalidData(message: "authorization_encryption_alg_values_supported must be present in wallet_metadata", className: className)
        }

        guard verifierEncryptionAlg.contains(where: { supportedEncryptionAlgorithms.contains($0) }) else {
            throw InvalidData(message: "Authorization response encryption algorithm is not supported", className: className)
        }

        guard let supportedEncryptions = walletConfig.authorizationEncryptionEncValuesSupported?.compactMap({$0.rawValue}) else {
            throw InvalidData(message: "authorization_encryption_enc_values_supported must be present in wallet_metadata", className: className)
        }

        let verifierEncArray = (verifierEnc as? String).map { [$0] } ?? (verifierEnc as? [String]) ?? []
        guard verifierEncArray.contains(where: { encValue in supportedEncryptions.contains(encValue) }) else {
            throw InvalidData(message: "authorization_encrypted_response_enc is not supported", className: className)
        }
    }
    
    private enum SpecVersionHandler {
        case v1
        case draft23
        
        static func from(_ authorizationRequest: AuthorizationRequest) -> SpecVersionHandler {
            return authorizationRequest is AuthorizationPresentationExchangeRequest ? .draft23 : .v1
        }
        
        func getVerifierPublicKey(authorizationRequest: AuthorizationRequest, walletConfig: WalletConfig, className: String) throws -> JWK {
            switch self {
            case .draft23:
                guard let clientMetadata = (authorizationRequest as? AuthorizationPresentationExchangeRequest)?.clientMetadata else {
                    throw InvalidData(message: "client_metadata must be present for given response mode", className: className)
                }
                guard let verifierJwks = clientMetadata.jwks else {
                    throw MissingInput(fieldPath: ["client_metadata", "jwks"], message: "", className: className)
                }
                return try getEncryptionKey(verifierJwks, [clientMetadata.authorizationEncryptedResponseAlg!])
            case .v1:
                guard let clientMetadata = (authorizationRequest as? AuthorizationDcqlRequest)?.clientMetadata else {
                    throw InvalidData(message: "client_metadata must be present for given response mode", className: className)
                }
                guard let verifierJwks = clientMetadata.jwks else {
                    throw MissingInput(fieldPath: ["client_metadata", "jwks"], message: "", className: className)
                }
                return try getEncryptionKey(verifierJwks, walletConfig.authorizationEncryptionAlgValuesSupported?.compactMap { $0.rawValue } ?? [EncryptionAlgorithm.ecdhES.rawValue])
            }
        }

        func getJWEHandler(authorizationRequest: AuthorizationRequest, walletNonce: String, walletConfig: WalletConfig, className: String) throws -> JWEHandler {
            switch self {
            case .draft23:
                let clientMetadata = ((authorizationRequest as? AuthorizationPresentationExchangeRequest)?.clientMetadata)!
                let verifierPublicKey = try getVerifierPublicKey(authorizationRequest: authorizationRequest, walletConfig: walletConfig, className: className)
                return JWEHandler(contentEncryptionAlgorithm: clientMetadata.authorizationEncryptedResponseEnc!, keyEncryptionAlgorithm: clientMetadata.authorizationEncryptedResponseAlg!, publicKey: verifierPublicKey, producerInfo: walletNonce, recipientInfo: authorizationRequest.nonce)
            case .v1:
                guard let clientMetadata = (authorizationRequest as? AuthorizationDcqlRequest)?.clientMetadata else {
                    throw InvalidData(message: "client_metadata must be present for given response mode", className: className)
                }
                guard clientMetadata.jwks != nil else {
                    throw MissingInput(fieldPath: ["client_metadata", "jwks"], message: "", className: className)
                }
                guard let clientEncValues = clientMetadata.encryptedResponseEncValuesSupported, !clientEncValues.isEmpty else {
                    throw InvalidData(message: "Unsupported content encryption algorithm", className: className)
                }
                let walletEncValues = walletConfig.authorizationEncryptionEncValuesSupported?.compactMap { $0.rawValue } ?? [EncryptionMethod.a256GCM.rawValue]
                guard let contentEncryptionAlgorithm = walletEncValues.first(where: { clientEncValues.contains($0) }) else {
                    throw InvalidData(message: "Unsupported content encryption algorithm", className: className)
                }
                let verifierPublicKey = try getVerifierPublicKey(authorizationRequest: authorizationRequest, walletConfig: walletConfig, className: className)
                guard let verifierPublicKeyAlgorithm = verifierPublicKey.algorithm else {
                    throw InvalidData(message: "Algorithm must be specified for the encryption key in jwks", className: className)
                }
                return JWEHandler(contentEncryptionAlgorithm: contentEncryptionAlgorithm, keyEncryptionAlgorithm: verifierPublicKeyAlgorithm, publicKey: verifierPublicKey, producerInfo: walletNonce, recipientInfo: authorizationRequest.nonce)
            }
        }
    }
}
