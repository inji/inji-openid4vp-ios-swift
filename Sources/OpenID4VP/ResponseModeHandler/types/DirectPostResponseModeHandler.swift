import Foundation

struct DirectPostResponseModeHandler : ResponseModeBasedHandler {
    let className = String(describing: DirectPostResponseModeHandler.self)
    
    func validate(clientMetadata: ClientMetadata?,
                  walletMetadata: WalletMetadata?,
                  shouldValidateWithWalletMetadata: Bool) throws {
        return
    }
    
    func validate(clientMetadata: ClientMetadataV2?,
                  walletMetadata: WalletMetadataV2?,
                  shouldValidateWithWalletMetadata: Bool) throws {
        if let enc = clientMetadata?.authorizationEncryptedResponseEncValuesSupported {
            throw InvalidData(message: "encrypted_response_enc_values_supported SHOULD not be present for response mode 'direct_post'", className: className)
        }
    }
    
    func getAuthorizationResponse(
        authorizationRequest: AuthorizationRequestV2,
        authorizationResponse: AuthorizationResponseV2,
        walletNonce: String
    ) throws -> [String: String] {
        return try authorizationResponse.toJsonEncodedMap()
    }

    func getAuthorizationErrorResponse(
        authorizationRequest: AuthorizationRequestV2?,
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
    
    func sendAuthorizationResponse(
        authorizationRequest: AuthorizationRequestV2,
        authorizationResponse: AuthorizationResponseV2,
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
