import Foundation

struct DirectPostResponseModeHandler : ResponseModeBasedHandler {
    func validate(clientMetadata: ClientMetadata?) throws {
        return
    }
    
    func sendAuthorizationResponse(authorizationRequest: AuthorizationRequest, authorizationResponse: AuthorizationResponse, url: String, networkManager: any NetworkManaging) async throws -> String {
        let requestBody: [String: String] = try authorizationResponse.toJsonEncodedMap(shouldEncode: false)
        
        let response = try await networkManager.sendHTTPRequest(url: url, method: HTTP_METHOD.POST, bodyParams: requestBody, headers: ["Content-Type" : .applicationFormUrlEncoded])
        
        return response.responseBody
    }
}
