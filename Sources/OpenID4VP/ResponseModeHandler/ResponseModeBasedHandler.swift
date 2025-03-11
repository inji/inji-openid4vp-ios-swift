import Foundation

protocol ResponseModeBasedHandler {
    func validate(clientMetadata: ClientMetadata?) throws
    func sendAuthorizationResponse(
            vpToken: VPToken,
            authorizationRequest: AuthorizationRequest,
            presentationSubmission: PresentationSubmission,
            state: String?,
            url: String,
            networkManager: NetworkManaging
        ) async throws -> String
}
