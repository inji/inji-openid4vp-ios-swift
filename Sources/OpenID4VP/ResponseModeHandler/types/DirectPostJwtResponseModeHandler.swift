import Foundation
import JSONWebKey


struct DirectPostJwtResponseModeHandler : ResponseModeBasedHandler {

    let className = String(describing: DirectPostJwtResponseModeHandler.self)
    
    func validate(clientMetadata: ClientMetadataSpecVersionDraft23?,
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

        try validateEncryption(alg: [encryptedResponseAlgorithm], enc: enc, jwks: jwks, walletMetadata: walletMetadata, shouldValidate: shouldValidateWithWalletMetadata)
        
        if !jwks.keys.contains(where: { $0.algorithm == encryptedResponseAlgorithm && $0.publicKeyUse == .encryption}) {
            throw InvalidData(
                message: "No jwk matching the specified algorithm found for encryption",
                className: className
            )
        }
    }
    
    func validate(clientMetadata: ClientMetadataSpecVersion1?,
                  walletMetadata: WalletMetadata?,
                  shouldValidateWithWalletMetadata: Bool) throws {
        guard clientMetadata != nil else {
            throw InvalidData(
                  message: "client_metadata must be present for given response mode",
                  className: className
              )
        }

        guard let enc = clientMetadata?.authorizationEncryptedResponseEncValuesSupported else {
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
        
        let verifierEncrptionAlgorithms: [String] = jwks.keys.filter { $0.publicKeyUse == .encryption }.compactMap { $0.algorithm }
        try validateEncryption(alg: verifierEncrptionAlgorithms, enc: enc, jwks: jwks, walletMetadata: walletMetadata, shouldValidate: shouldValidateWithWalletMetadata)
    }
    
    private func validateEncryption(alg: [String], enc: Any, jwks: JWKSet, walletMetadata: WalletMetadata?, shouldValidate: Bool) throws {
        if shouldValidate {
            try validateWithWalletMetadata(clientAlg: alg, clientEnc: enc, walletMetadata: walletMetadata)
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
        walletNonce: String,
    ) throws -> [String: String] {
        return authorizationResponse.toJsonEncodedMap()
    }
    
    private func encryptResponse(
        authorizationRequest: AuthorizationRequest,
        responseParams: [String: String],
        walletNonce: String,
        walletMetadata: WalletMetadata?
    ) throws -> [String: String] {
        let versionLogic = VersionLogic.from(authorizationRequest)
        let jweHandler = try versionLogic.getJWEHandler(authorizationRequest: authorizationRequest, walletNonce: walletNonce, walletMetadata: walletMetadata, className: className)
        let encryptedBody = try jweHandler.generateEncryptedResponse(payload: responseParams)
        return ["response": encryptedBody]
    }

    private func validateWithWalletMetadata(clientAlg: [String],
                                            clientEnc: Any,
                                            walletMetadata: WalletMetadata?) throws {
        guard let walletMetadata = walletMetadata else {
            throw InvalidData(message: "wallet_metadata must be present", className: className)
        }

        guard let supportedEncryptionAlgorithms = walletMetadata.authorizationEncryptionAlgValuesSupported?.compactMap({$0.rawValue}) else {
            throw InvalidData(message: "authorization_encryption_alg_values_supported must be present in wallet_metadata", className: className)
        }

        guard clientAlg.contains(where: { supportedEncryptionAlgorithms.contains($0) }) else {
            throw InvalidData(message: "Authorization response encryption algorithm is not supported", className: className)
        }

        guard let supportedEncryptions = walletMetadata.authorizationEncryptionEncValuesSupported?.compactMap({$0.rawValue}) else {
            throw InvalidData(message: "authorization_encryption_enc_values_supported must be present in wallet_metadata", className: className)
        }

        let clientEncArray = (clientEnc as? String).map { [$0] } ?? (clientEnc as? [String]) ?? []
        guard clientEncArray.contains(where: { encValue in supportedEncryptions.contains(encValue) }) else {
            throw InvalidData(message: "authorization_encrypted_response_enc is not supported", className: className)
        }
    }
    
    private enum VersionLogic {
        case v1
        case draft23
        
        static func from(_ authorizationRequest: AuthorizationRequest) -> VersionLogic {
            return authorizationRequest is AuthorizationRequestSpecVersionDraft23 ? .draft23 : .v1
        }
        
        func getJWEHandler(authorizationRequest: AuthorizationRequest, walletNonce: String, walletMetadata: WalletMetadata?, className: String) throws -> JWEHandler {
            switch self {
            case .draft23:
                let clientMetadata = ((authorizationRequest as? AuthorizationRequestSpecVersionDraft23)?.clientMetadata)!
                let verifierPublicKey = try getEncryptionKey(clientMetadata.jwks!, [clientMetadata.authorizationEncryptedResponseAlg!])
                return JWEHandler(contentEncryptionAlgorithm: clientMetadata.authorizationEncryptedResponseEnc!, keyEncryptionAlgorithm: clientMetadata.authorizationEncryptedResponseAlg!, publicKey: verifierPublicKey, producerInfo: walletNonce, recipientInfo: authorizationRequest.nonce)
            case .v1:
                let clientMetadata = ((authorizationRequest as? AuthorizationRequestSpecVersion1)?.clientMetadata)!
                let authorizationEncryptedResponseEnc = clientMetadata.authorizationEncryptedResponseEncValuesSupported?.contains(ContentEncryptionAlgorithm.A256GCM.rawValue) == true ? ContentEncryptionAlgorithm.A256GCM.rawValue : try {
                    throw InvalidData(message: "Unsupported content encryption algorithm", className: className)
                }()
                
                let verifierPublicKey = try getEncryptionKey(clientMetadata.jwks!, walletMetadata?.authorizationEncryptionAlgValuesSupported?.compactMap({$0.rawValue}) ?? [KeyManagementAlgorithm.ecdhEs.rawValue])
                return JWEHandler(contentEncryptionAlgorithm: authorizationEncryptedResponseEnc, keyEncryptionAlgorithm: "", publicKey: verifierPublicKey, producerInfo: walletNonce, recipientInfo: authorizationRequest.nonce)
            }
        }
    }
}
