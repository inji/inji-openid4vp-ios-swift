import Foundation

public class OpenID4VP {
    public let traceabilityId: String
    let networkManager: NetworkManaging
    var authorizationRequest: AuthorizationRequest?
    private var responseUri: String?

    public init(traceabilityId: String, networkManager: NetworkManaging? = nil) {
        self.traceabilityId = traceabilityId
        self.networkManager = networkManager ?? NetworkManager.shared
    }

    public func updateAuthorizationRequest(_ presentationDefinition: PresentationDefinition, _ clientMetadata: ClientMetadata?) {
        self.authorizationRequest?.presentationDefinition = presentationDefinition as PresentationDefinition
       
        if let clientMetadata = clientMetadata {
            self.authorizationRequest?.clientMetadata = clientMetadata
        }
    }

    public func setResponseUri(_ responseUri: String) {
        self.responseUri = responseUri
    }

    public func authenticateVerifier(encodedAuthorizationRequest: String, trustedVerifierJSON: [Verifier]) async throws -> AuthorizationRequest {

        Logger.setLogTag(className:String(describing: type(of: self)), traceabilityId: traceabilityId)

        do {
            authorizationRequest =  try AuthorizationRequest.validateAndGetAuthorizationRequest(encodedAuthorizationRequest: encodedAuthorizationRequest, setResponseUri: setResponseUri)
            
            try AuthenticationResponse.validateAuthorizationRequestPartially(authorizationRequest!, trustedVerifierJSON, updateAuthorizationRequest: updateAuthorizationRequest)
            
            return authorizationRequest!

        } catch(let exception) {
            await sendErrorToVerifier(error: exception)
            throw exception
        }
    }

    public func constructVerifiablePresentationToken(credentialsMap: [String: [String]]) async throws ->  String? {

        return try AuthorizationResponse.constructVpForSigning(credentialsMap)
    }

    public func shareVerifiablePresentation(vpResponseMetadata: VPResponseMetadata) async throws -> String? {

        do {
            return try await AuthorizationResponse.shareVp(vpResponseMetadata: vpResponseMetadata,nonce: authorizationRequest!.nonce, responseUri: authorizationRequest!.responseUri,presentationDefinitionId: (authorizationRequest?.presentationDefinition as! PresentationDefinition).id, networkManager: networkManager)
        } catch(let exception) {
            await sendErrorToVerifier(error: exception)
            throw exception
        }
    }

    public func sendErrorToVerifier(error: Error) async {

        Logger.getLogTag(className: String(describing: type(of: self)))

        guard let url = URL(string: responseUri!) else { return }

        let errorInfo = """
        {
            "error": \(error),
            "traceabilityId": \(traceabilityId)
        }
        """

        do {
            let response =  try await networkManager.sendHTTPPostRequest(requestBody: errorInfo, url: url)
            print("\(String(describing: response))")
        } catch {
            Logger.error("Unexpected error occurred while sending the error to verifier: \(error)")
        }
    }
}
