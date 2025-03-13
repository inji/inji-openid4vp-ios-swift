import Foundation

struct DirectPostResponseModeHandler : ResponseModeBasedHandler {
    func validate(clientMetadata: ClientMetadata?) throws {
        return
    }
    
    func sendAuthorizationResponse(vpToken: VPToken, authorizationRequest: AuthorizationRequest, presentationSubmission: PresentationSubmission, state: String?, url: String, networkManager: NetworkManaging) async throws -> String {
        let requestBody: [String: String] = try constructBodyParams(vpToken: vpToken, presentationSubmission: presentationSubmission, state: state) as! [String: String]
        
        let response = try await networkManager.sendHTTPRequest(url: url, method: HTTP_METHOD.POST, bodyParams: requestBody, headers: ["Content-Type" : .applicationFormUrlEncoded])
        
        return response.responseBody
    }
}
