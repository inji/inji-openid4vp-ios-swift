import Foundation

struct DirectPostResponseModeHandler : ResponseModeBasedHandler {
    static let className = String(describing: DirectPostResponseModeHandler.self)
    
    func validate(clientMetadata: ClientMetadataSpecVersionDraft23?,
                  walletMetadata: WalletMetadata?,
                  shouldValidateWithWalletMetadata: Bool) throws {
        if clientMetadata?.authorizationEncryptedResponseEnc != nil {
            throw InvalidData(message: "encrypted_response_enc_values_supported SHOULD not be present for response mode 'direct_post'", className: Self.className)
        }
    }
    
    func validate(clientMetadata: ClientMetadataSpecVersion1?,
                  walletMetadata: WalletMetadata?,
                  shouldValidateWithWalletMetadata: Bool) throws {
        if clientMetadata?.authorizationEncryptedResponseEncValuesSupported != nil {
            throw InvalidData(message: "encrypted_response_enc_values_supported SHOULD not be present for response mode 'direct_post'", className: Self.className)
        }
    }
    
    func getAuthorizationResponse(
        authorizationRequest: AuthorizationRequest,
        authorizationResponse: AuthorizationResponse,
        walletNonce: String
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
        recipientInfo: String
    ) async throws -> NetworkResponse {
        let requestBody: [String: String] = try authorizationResponse.toJsonEncodedMap()

        return try await networkManager.sendHTTPRequest(
            url: url,
            method: .post,
            bodyParams: requestBody,
            headers: [Header.contentType.rawValue: ContentTypes.applicationFormUrlEncoded.rawValue]
        )
    }
}
