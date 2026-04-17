import Foundation
import JSONWebKey

struct DirectPostResponseModeHandler : ResponseModeBasedHandler {
    static let className = String(describing: DirectPostResponseModeHandler.self)
    
    func validate(clientMetadata: ClientMetadataDraft23?,
                  walletMetadata: WalletMetadata?,
                  shouldValidateWithWalletMetadata: Bool) throws {
        if (clientMetadata?.authorizationEncryptedResponseEnc != nil || clientMetadata?.authorizationEncryptedResponseAlg != nil) {
            throw InvalidData(message: "encrypted_response_enc_values_supported or authorization_encrypted_response_alg SHOULD not be present for response mode 'direct_post'", className: Self.className)
        }
    }
    
    func validate(clientMetadata: ClientMetadata?,
                  walletMetadata: WalletMetadata?,
                  shouldValidateWithWalletMetadata: Bool) throws {
        if clientMetadata?.encryptedResponseEncValuesSupported != nil {
            throw InvalidData(message: "encrypted_response_enc_values_supported SHOULD not be present for response mode 'direct_post'", className: Self.className)
        }
    }
    
    func getAuthorizationResponse(
        authorizationRequest: AuthorizationRequest,
        authorizationResponse: AuthorizationResponse,
        walletNonce: String,
        walletMetadata: WalletMetadata?
    ) throws -> [String: String] {
        return try authorizationResponse.toJsonEncodedMap()
    }

    func getAuthorizationErrorResponse(
        authorizationRequest: AuthorizationRequest?,
        authorizationResponse: AuthorizationErrorResponse,
        walletNonce: String
    ) -> [String: String] {
        return authorizationResponse.toJsonEncodedMap()
    }
    
    func sendAuthorizationResponse(
        authorizationRequest: AuthorizationRequest,
        authorizationResponse: AuthorizationResponse,
        url: String,
        networkManager: any NetworkManaging,
        producerInfo: String,
        recipientInfo: String,
        walletMetadata: WalletMetadata?
    ) async throws -> NetworkResponse {
        let requestBody: [String: String] = try authorizationResponse.toJsonEncodedMap()
        return try await networkManager.sendHTTPRequest(
            url: url,
            method: .post,
            bodyParams: requestBody,
            headers: [Header.contentType.rawValue: ContentTypes.applicationFormUrlEncoded.rawValue]
        )
    }

    func getVerifierPublicKeyForEncryption(
        authorizationRequest: AuthorizationRequest,
        walletMetadata: WalletMetadata?
    ) throws -> JWK? {
        return nil
    }
    
    func getResponseEndpoint(authorizationRequest: AuthorizationRequest) throws -> String {
        return try authorizationRequest.responseUri ?? {
            throw InvalidData(message: "response_uri is required in authorization request for response mode 'direct_post'", className: Self.className)
        }()
    }
}
