import Foundation

struct DirectPostResponseModeHandler : ResponseModeBasedHandler {
    func validate(clientMetadata: ClientMetadata?,
                  walletMetadata: WalletMetadata?,
                  shouldValidateWithWalletMetadata: Bool) throws {
        return
    }
    
    /// Sends the given authorization response to the specified URL using an application/x-www-form-urlencoded POST and returns the full network response.
    /// - Parameters:
    ///   - authorizationResponse: The authorization response to encode and send; will be converted to an x-www-form-urlencoded body.
    ///   - url: The destination URL for the POST request.
    ///   - producerInfo: Metadata about the message producer (passed through for caller correlation).
    ///   - recepientInfo: Metadata about the intended recipient (passed through for caller correlation).
    /// - Returns: The complete `NetworkResponse` produced by the network manager.
    /// - Throws: Any error thrown while encoding the authorization response or while performing the HTTP request.
    func sendAuthorizationResponse(
        authorizationRequest: AuthorizationRequest,
        authorizationResponse: AuthorizationResponse,
        url: String,
        networkManager: any NetworkManaging,
        producerInfo: String,
        recepientInfo recipientInfo: String
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