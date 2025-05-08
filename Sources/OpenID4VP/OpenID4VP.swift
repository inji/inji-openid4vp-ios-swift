import Foundation

public class OpenID4VP {
    public let traceabilityId: String
    let networkManager: NetworkManaging
    var authorizationRequest: AuthorizationRequest?
    private var responseUri: String?
    private var authorizationResponseHandler: AuthorizationResponseHandler

    public init(traceabilityId: String, networkManager: NetworkManaging? = nil) {
        self.traceabilityId = traceabilityId
        self.networkManager = networkManager ?? NetworkManager.shared
        self.authorizationResponseHandler = AuthorizationResponseHandler(networkManager: self.networkManager)
    }

    public func setResponseUri(_ responseUri: String) {
        self.responseUri = responseUri
    }

    public func authenticateVerifier(urlEncodedAuthorizationRequest: String,
                                     trustedVerifierJSON: [Verifier],
                                     walletMetadata: WalletMetadata? = nil,
                                     shouldValidateClient: Bool = false
                                    ) async throws -> AuthorizationRequest {

        Logger.setTraceabilityId(className:String(describing: type(of: self)), traceabilityId: traceabilityId)

        do {
            self.authorizationRequest =  try await AuthorizationRequest.validateAndCreateAuthorizationRequest(
                                                                        urlEncodedAuthorizationRequest: urlEncodedAuthorizationRequest,
                                                                        trustedVerifierJSON: trustedVerifierJSON,
                                                                        walletMetadata: walletMetadata,
                                                                        setResponseUri: setResponseUri,
                                                                        shouldValidateClient: shouldValidateClient,
                                                                        networkManager: networkManager as NetworkManaging)
            return authorizationRequest!

        } catch(let exception) {
            await sendErrorToVerifier(error: exception)
            throw exception
        }
    }

    public func constructUnsignedVPToken(credentialsMap: [String: [FormatType: Array<Any>]]) async throws ->  [FormatType: UnsignedVPToken] {
        return try authorizationResponseHandler.constructUnsignedVPToken(credentialsMap: credentialsMap, authorizationRequest: self.authorizationRequest!, responseUri: self.responseUri!)
    }

    public func shareVerifiablePresentation(vpTokenSigningResults: [FormatType: VpTokenSigningResult]) async throws -> String? {
        do {
            return try await self.authorizationResponseHandler.shareVP(authorizationRequest: self.authorizationRequest!, vpTokenSigningResults: vpTokenSigningResults, responseUri: self.responseUri!)
        } catch(let exception) {
            await sendErrorToVerifier(error: exception)
            throw exception
        }
    }

    public func sendErrorToVerifier(error: Error) async {
        let logTag = Logger.getLogTag(String(describing: OpenID4VP.self))

        let errorInfo =
        [
            "error": "\(error)",
            "traceabilityId": "\(traceabilityId)"
        ]
        do {
            _ =  try await networkManager.sendHTTPRequest(url: responseUri ?? "", method: .post, bodyParams: errorInfo, headers: ["Content_Type" : ContentTypes.applicationFormUrlEncoded.rawValue])
        } catch {
            Logger.error(logTag, NetworkRequestException.invalidResponse(message: "Unexpected error occurred while sending the error to verifier: \(error)"))
        }
    }
}
