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
        authorizationRequest: AuthorizationRequest?,
        exception: Error,
        walletNonce: String
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
        authorizationRequest: AuthorizationRequest
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
                  shouldValidateWithWalletMetadata: Bool) throws {}
    
    func validate(clientMetadata: ClientMetadata?,
                  walletConfig: WalletConfig,
                  shouldValidateWithWalletMetadata: Bool) throws {}
    
    func sendAuthorizationResponse(
        authorizationRequest: AuthorizationRequest,
        authorizationResponse: AuthorizationResponse,
        url: String,
        networkManager: any NetworkManaging,
        producerInfo: String,
        recipientInfo: String,
        walletConfig: WalletConfig
    ) async throws -> NetworkResponse {
        fatalError("Not needed for unit testing constructAuthorizationResponse")
    }

    func setResponseUrl(authorizationRequestParameters: [String : Any], setResponseUri: (String) -> Void) throws {}
    
    func getAuthorizationResponse(
        authorizationRequest: AuthorizationRequest,
        authorizationResponse: AuthorizationResponse,
        walletNonce: String,
        walletConfig: WalletConfig
    ) throws -> [String: String] {
        return expectedSuccessResponse
    }

    func getVerifierPublicKeyForEncryption(
        authorizationRequest: AuthorizationRequest,
                walletConfig: WalletConfig
    ) throws -> JWK? {
        return nil
    }
    
    func getResponseEndpoint(authorizationRequest: AuthorizationRequest) throws -> String {
        return authorizationRequest.responseUri ?? "https://example.com/callback"
    }

    func getAuthorizationErrorResponse(
        authorizationRequest: AuthorizationRequest?,
        authorizationResponse: AuthorizationErrorResponse,
        walletNonce: String
    ) throws -> [String: String] {
        return expectedErrorResponse
    }
}
