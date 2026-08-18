import Foundation
import JSONWebKey
@testable import OpenID4VP

final class MockNonceProvider: NonceProvider {
    override func generateNonce(entropy: Int = 16) -> String {
        return "mock-nonce"
    }
}

final class MockAuthorizationResponseHandler: AuthorizationResponseHandler {
    var expectedResponse: [String: String] = [:]
    var expectedErrorResponse: [String: String] = [:]
    var expectedUnsignedVPTokens: [UnsignedVPToken] = []
    var expectedVPResponse: [String: String] = [:]
    
    override func constructAuthorizationErrorResponse(
        dispatchInfo: ResponseDispatchInfo?,
        error: Error,
        walletNonce: String,
        authorizationRequest: AuthorizationRequest?
    ) -> [String: Any] {
        return expectedErrorResponse
    }
    
    override func constructUnsignedVPToken(
        selectedCredentials: [String: [Credential]],
        authorizationRequest: AuthorizationRequest,
        walletNonce: String
    ) async throws -> [UnsignedVPToken] {
        return expectedUnsignedVPTokens
    }
    
    override func constructVPResponse(
        signingResults: [VPTokenSigningResult],
        authorizationRequest: AuthorizationRequest,
        dispatchInfo: ResponseDispatchInfo?
    ) throws -> [String: String] {
        if(!expectedErrorResponse.isEmpty) {
            return expectedErrorResponse
        }
        return expectedVPResponse
    }
}

class MockResponseModeHandler: ResponseModeBasedHandler {
    var expectedSuccessResponse: [String: String] = [:]
    var expectedErrorResponse: [String: String] = [:]
    
    func validate(clientMetadata: ClientMetadataDraft23?,
                  walletConfig: WalletConfig,
                  shouldValidateWithWalletMetadata: Bool) throws -> ResponseEncryptionSpecification? {
        return nil
    }
    
    func validate(clientMetadata: ClientMetadata?,
                  walletConfig: WalletConfig,
                  shouldValidateWithWalletMetadata: Bool) throws -> ResponseEncryptionSpecification? {
        return nil
    }
    
    func getVerifierPublicKeyForEncryption(
        authorizationRequest: AuthorizationRequest,
        walletConfig: WalletConfig
    ) throws -> JWK? {
        return nil
    }
    
    func getResponseEndpoint(authorizationRequestParameters: [String : Any]) throws -> String {
        return authorizationRequestParameters[AuthorizationRequestFieldConstants.responseUri] as? String ?? "https://example.com/callback"
    }
    
    func getAuthorizationErrorResponse(
        dispatchInfo: ResponseDispatchInfo,
        authorizationResponse: AuthorizationErrorResponse,
        authorizationRequest: AuthorizationRequest?
    ) throws -> [String: String] {
        return expectedErrorResponse
    }
    
    func sendAuthorizationError(
        dispatchInfo: ResponseDispatchInfo,
        authorizationResponse: AuthorizationErrorResponse,
        authorizationRequest: AuthorizationRequest?,
        networkManager: NetworkManaging
    ) async throws -> NetworkResponse {
        fatalError("Not needed for unit testing")
    }
    
    func getAuthorizationResponse(
        dispatchInfo: ResponseDispatchInfo,
        authorizationResponse: AuthorizationResponse,
        authorizationRequest: AuthorizationRequest
    ) throws -> [String: String] {
        return expectedSuccessResponse
    }
    
    func sendAuthorizationResponse(
        dispatchInfo: ResponseDispatchInfo,
        authorizationResponse: AuthorizationResponse,
        authorizationRequest: AuthorizationRequest,
        networkManager: NetworkManaging
    ) async throws -> NetworkResponse {
        fatalError("Not needed for unit testing")
    }
}

final class MockBrowserURLOpener: BrowserURLOpening {
    var installedSchemes: Set<String>
    var openSucceeds: Bool

    private(set) var openedURLs: [URL] = []
    private(set) var probedURLs: [URL] = []

    init(installedSchemes: Set<String> = [], openSucceeds: Bool = true) {
        self.installedSchemes = installedSchemes
        self.openSucceeds = openSucceeds
    }

    func canOpen(_ url: URL) async -> Bool {
        probedURLs.append(url)
        guard let scheme = url.scheme?.lowercased() else { return false }
        return installedSchemes.contains(scheme)
    }

    @discardableResult
    func open(_ url: URL) async -> Bool {
        openedURLs.append(url)
        return openSucceeds
    }
}
