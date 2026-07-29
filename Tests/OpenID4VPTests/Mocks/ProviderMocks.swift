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
    
    func setResponseUrl(authorizationRequestParameters: [String : Any]) throws -> String {
        return authorizationRequestParameters[AuthorizationRequestFieldConstants.responseUri] as? String ?? "https://example.com/callback"
    }
    
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
    
    func getResponseEndpoint(authorizationRequestParameters: [String : Any]) throws -> String {
        return authorizationRequestParameters[AuthorizationRequestFieldConstants.responseUri] as? String ?? "https://example.com/callback"
    }
    
    func getAuthorizationErrorResponse(
        authorizationRequest: AuthorizationRequest?,
        authorizationResponse: AuthorizationErrorResponse,
        walletNonce: String
    ) throws -> [String: String] {
        return expectedErrorResponse
    }
    
    func getAuthorizationErrorResponse(
        dispatchInfo: ResponseDispatchInfo,
        authorizationResponse: AuthorizationErrorResponse
    ) throws -> [String: String] {
        return expectedErrorResponse
    }
    
    func sendAuthorizationError(
        dispatchInfo: ResponseDispatchInfo,
        authorizationResponse: AuthorizationErrorResponse,
        networkManager: NetworkManaging
    ) async throws -> NetworkResponse {
        fatalError("Not needed for unit testing")
    }
    
    func getAuthorizationResponse(
        dispatchInfo: ResponseDispatchInfo,
        authorizationResponse: AuthorizationResponse
    ) throws -> [String: String] {
        return expectedSuccessResponse
    }
    
    func sendAuthorizationResponse(
        dispatchInfo: ResponseDispatchInfo,
        authorizationResponse: AuthorizationResponse,
        networkManager: NetworkManaging
    ) async throws -> NetworkResponse {
        fatalError("Not needed for unit testing")
    }
}
