import Foundation

struct DirectPostResponseModeHandler : ResponseModeBasedHandler {
    func validate(clientMetadata: ClientMetadata?,
                  walletMetadata: WalletMetadata?,
                  shouldValidateWithWalletMetadata: Bool) throws {
        return
    }
    
    func sendAuthorizationResponse(authorizationRequest: AuthorizationRequest, authorizationResponse: AuthorizationResponse, url: String, networkManager: any NetworkManaging, producerInfo: String, recepientInfo: String) async throws -> String {
        let requestBody: [String: String] = try authorizationResponse.toJsonEncodedMap()
        
        let response = try await networkManager.sendHTTPRequest(url: url, method: .post, bodyParams: requestBody, headers: [Header.contentType.rawValue: ContentTypes.applicationFormUrlEncoded.rawValue])
        
        return response.responseBody
    }
}
