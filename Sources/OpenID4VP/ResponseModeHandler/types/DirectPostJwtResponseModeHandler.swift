import Foundation
import JSONWebKey


struct DirectPostJwtResponseModeHandler : ResponseModeBasedHandler {

    let className = String(describing: DirectPostJwtResponseModeHandler.self)
    
    func validate(clientMetadata: ClientMetadataDraft23?,
                  walletMetadata: WalletMetadata?,
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

        try validateEncryption(verifierEncryptionAlg: [encryptedResponseAlgorithm], verifierEnc: enc, jwks: jwks, walletMetadata: walletMetadata, shouldValidate: shouldValidateWithWalletMetadata)
        
        if !jwks.keys.contains(where: { $0.algorithm == encryptedResponseAlgorithm && $0.publicKeyUse == .encryption}) {
            throw InvalidData(
                message: "No jwk matching the specified algorithm found for encryption",
                className: className
            )
        }
    }
    
    func validate(clientMetadata: ClientMetadata?,
                  walletMetadata: WalletMetadata?,
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
        try validateEncryption(verifierEncryptionAlg: verifierEncrptionAlgorithms, verifierEnc: enc, jwks: jwks, walletMetadata: walletMetadata, shouldValidate: shouldValidateWithWalletMetadata)
    }
    
    private func validateEncryption(verifierEncryptionAlg: [String], verifierEnc: Any, jwks: JWKSet, walletMetadata: WalletMetadata?, shouldValidate: Bool) throws {
        if shouldValidate {
            guard let walletMetadata = walletMetadata else {
                throw InvalidData(message: "wallet_metadata must be present", className: className)
            }

            guard let supportedEncryptionAlgorithms = walletMetadata.authorizationEncryptionAlgValuesSupported?.compactMap({$0.rawValue}) else {
                throw InvalidData(message: "authorization_encryption_alg_values_supported must be present in wallet_metadata", className: className)
            }

            guard verifierEncryptionAlg.contains(where: { supportedEncryptionAlgorithms.contains($0) }) else {
                throw InvalidData(message: "Authorization response encryption algorithm is not supported", className: className)
            }

            guard let supportedEncryptions = walletMetadata.authorizationEncryptionEncValuesSupported?.compactMap({$0.rawValue}) else {
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
        walletMetadata: WalletMetadata?
    ) throws -> [String: String] {
        let responseParams = try authorizationResponse.toJsonEncodedMap()
        return try encryptResponse(
            authorizationRequest: authorizationRequest,
            responseParams: responseParams,
            walletNonce: walletNonce,
            walletMetadata: walletMetadata
        )
    }
    
    func sendAuthorizationResponse(authorizationRequest: AuthorizationRequest, authorizationResponse: AuthorizationResponse, url: String, networkManager: any NetworkManaging, producerInfo: String,
                                   recipientInfo: String, walletMetadata: WalletMetadata?) async throws -> NetworkResponse {
        let requestBody = try getAuthorizationResponse(authorizationRequest: authorizationRequest, authorizationResponse: authorizationResponse, walletNonce: producerInfo, walletMetadata: walletMetadata)
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
        walletMetadata: WalletMetadata?
    ) throws -> JWK? {
        return try SpecVersionHandler.from(authorizationRequest)
            .getVerifierPublicKey(authorizationRequest: authorizationRequest, walletMetadata: walletMetadata, className: className)
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
        walletMetadata: WalletMetadata?
    ) throws -> [String: String] {
        let specVersionHandler = SpecVersionHandler.from(authorizationRequest)
        let jweHandler = try specVersionHandler.getJWEHandler(authorizationRequest: authorizationRequest, walletNonce: walletNonce, walletMetadata: walletMetadata, className: className)
        let encryptedBody = try jweHandler.generateEncryptedResponse(payload: responseParams)
        return ["response": encryptedBody]
    }

    private func validateWithWalletMetadata(verifierEncryptionAlg: [String],
                                            verifierEnc: Any,
                                            walletMetadata: WalletMetadata?) throws {
        guard let walletMetadata = walletMetadata else {
            throw InvalidData(message: "wallet_metadata must be present", className: className)
        }

        guard let supportedEncryptionAlgorithms = walletMetadata.authorizationEncryptionAlgValuesSupported?.compactMap({$0.rawValue}) else {
            throw InvalidData(message: "authorization_encryption_alg_values_supported must be present in wallet_metadata", className: className)
        }

        guard verifierEncryptionAlg.contains(where: { supportedEncryptionAlgorithms.contains($0) }) else {
            throw InvalidData(message: "Authorization response encryption algorithm is not supported", className: className)
        }

        guard let supportedEncryptions = walletMetadata.authorizationEncryptionEncValuesSupported?.compactMap({$0.rawValue}) else {
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
        
        func getVerifierPublicKey(authorizationRequest: AuthorizationRequest, walletMetadata: WalletMetadata?, className: String) throws -> JWK {
            switch self {
            case .draft23:
                let clientMetadata = ((authorizationRequest as? AuthorizationPresentationExchangeRequest)?.clientMetadata)!
                return try getEncryptionKey(clientMetadata.jwks!, [clientMetadata.authorizationEncryptedResponseAlg!])
            case .v1:
                guard let clientMetadata = (authorizationRequest as? AuthorizationDcqlRequest)?.clientMetadata else {
                    throw InvalidData(message: "client_metadata must be present for given response mode", className: className)
                }
                guard let verifierJwks = clientMetadata.jwks else {
                    throw MissingInput(fieldPath: ["client_metadata", "jwks"], message: "", className: className)
                }
                return try getEncryptionKey(verifierJwks, walletMetadata?.authorizationEncryptionAlgValuesSupported?.compactMap { $0.rawValue } ?? [KeyManagementAlgorithm.ecdhEs.rawValue])
            }
        }

        func getJWEHandler(authorizationRequest: AuthorizationRequest, walletNonce: String, walletMetadata: WalletMetadata?, className: String) throws -> JWEHandler {
            switch self {
            case .draft23:
                let clientMetadata = ((authorizationRequest as? AuthorizationPresentationExchangeRequest)?.clientMetadata)!
                let verifierPublicKey = try getVerifierPublicKey(authorizationRequest: authorizationRequest, walletMetadata: walletMetadata, className: className)
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
                let walletEncValues = walletMetadata?.authorizationEncryptionEncValuesSupported?.compactMap { $0.rawValue } ?? [ContentEncryptionAlgorithm.A256GCM.rawValue]
                guard let contentEncryptionAlgorithm = walletEncValues.first(where: { clientEncValues.contains($0) }) else {
                    throw InvalidData(message: "Unsupported content encryption algorithm", className: className)
                }
                let verifierPublicKey = try getVerifierPublicKey(authorizationRequest: authorizationRequest, walletMetadata: walletMetadata, className: className)
                guard let verifierPublicKeyAlgorithm = verifierPublicKey.algorithm else {
                    throw InvalidData(message: "Algorithm must be specified for the encryption key in jwks", className: className)
                }
                return JWEHandler(contentEncryptionAlgorithm: contentEncryptionAlgorithm, keyEncryptionAlgorithm: verifierPublicKeyAlgorithm, publicKey: verifierPublicKey, producerInfo: walletNonce, recipientInfo: authorizationRequest.nonce)
            }
        }
    }
}
