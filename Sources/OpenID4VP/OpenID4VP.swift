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

    public func setResponseUri(_ responseUri: String) {
        self.responseUri = responseUri
    }

    public func authenticateVerifier(urlEncodedAuthorizationRequest: String, trustedVerifierJSON: [Verifier], shouldValidateClient: Bool = false) async throws -> AuthorizationRequest {

        Logger.setTraceabilityId(className:String(describing: type(of: self)), traceabilityId: traceabilityId)

        do {
            authorizationRequest =  try await AuthorizationRequest.validateAndCreateAuthorizationRequest(urlEncodedAuthorizationRequest: urlEncodedAuthorizationRequest,setResponseUri: setResponseUri, shouldValidateClient: shouldValidateClient, trustedVerifierJSON: trustedVerifierJSON, networkManager: networkManager as NetworkManaging)
            
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
            return try await AuthorizationResponse.shareVp(vpResponseMetadata: vpResponseMetadata,nonce: authorizationRequest!.nonce, state: authorizationRequest?.state, responseUri: authorizationRequest!.responseUri!,presentationDefinitionId: authorizationRequest!.clientId, networkManager: networkManager)
        } catch(let exception) {
            await sendErrorToVerifier(error: exception)
            throw exception
        }
    }

    public func sendErrorToVerifier(error: Error) async {
        guard let url = URL(string: responseUri ?? "") else { return }
        let logTag = Logger.getLogTag(String(describing: OpenID4VP.self))
        
        let errorInfo = """
        {
            "error": \(error),
            "traceabilityId": \(traceabilityId)
        }
        """

        do {
            _ =  try await networkManager.sendHTTPRequest(url: url, method: HTTP_METHOD.POST, bodyParams: errorInfo, headers: ["Content_Type" : "application/x-www-form-urlencoded"])
        } catch {
            Logger.error(logTag, NetworkRequestException.invalidResponse(message: "Unexpected error occurred while sending the error to verifier: \(error)"))
        }
    }
}
