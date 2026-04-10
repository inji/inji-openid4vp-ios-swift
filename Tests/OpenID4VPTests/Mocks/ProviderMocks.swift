import Foundation
@testable import OpenID4VP

final class MockNonceProvider: NonceProvider {
    override func generateNonce(entropy: Int = 16) -> String {
        return "mock-nonce"
    }
}

final class MockAuthorizationResponseHandler: AuthorizationResponseHandler {
    var expectedResponse: [String: String] = [:]
    var expectedErrorResponse: [String: String] = [:]
    var expectedUnsignedVPTokensV2: [UnsignedVPTokenV2] = []
    var expectedVPResponseV2: [String: Any] = [:]

    override func constructAuthorizationResponse(authorizationRequest authRequest: AuthorizationRequest,
                                                 vpTokenSigningResults signingResult: [FormatType: VPTokenSigningResult]) -> [String: String] {
        return expectedResponse
    }

    override func constructAuthorizationErrorResponse(
        authorizationRequest: AuthorizationRequest?,
        exception: Error,
        walletNonce: String
    ) -> [String: Any] {
        return expectedErrorResponse
    }

    override func constructUnsignedVPTokenV2(
        credentialsMap: [String: [FormatType: [AnyCodable]]],
        authorizationRequest: AuthorizationRequest,
        responseUri: String,
        holderId: String?,
        signatureSuite: String?,
        walletNonce: String
    ) async throws -> [UnsignedVPTokenV2] {
        return expectedUnsignedVPTokensV2
    }

    override func constructVPResponseV2(
        signingResults: [VPTokenSigningResultV2],
        authorizationRequest: AuthorizationRequest
    ) throws -> [String: String] {
        return expectedVPResponseV2 as! [String: String]
    }
}

class MockResponseModeHandler: ResponseModeBasedHandler {
    var expectedSuccessResponse: [String: String] = [:]
    var expectedErrorResponse: [String: String] = [:]

    func validate(clientMetadata: ClientMetadataSpecVersionDraft23?,
                  walletMetadata: WalletMetadata?,
                  shouldValidateWithWalletMetadata: Bool) throws {}
    
    func validate(clientMetadata: ClientMetadataSpecVersion1?,
                  walletMetadata: WalletMetadata?,
                  shouldValidateWithWalletMetadata: Bool) throws {}
    
    func sendAuthorizationResponse(
        authorizationRequest: AuthorizationRequest,
        authorizationResponse: AuthorizationResponse,
        url: String,
        networkManager: any NetworkManaging,
        producerInfo: String,
        recipientInfo: String,
        walletMetadata: WalletMetadata?
    ) async throws -> NetworkResponse {
        fatalError("Not needed for unit testing constructAuthorizationResponse")
    }

    func setResponseUrl(authorizationRequestParameters: [String : Any], setResponseUri: (String) -> Void) throws {}
    
    func getAuthorizationResponse(
        authorizationRequest: AuthorizationRequest,
        authorizationResponse: AuthorizationResponse,
        walletNonce: String,
        walletMetadata: WalletMetadata?
    ) throws -> [String: String] {
        return expectedSuccessResponse
    }

    func getAuthorizationErrorResponse(
        authorizationRequest: AuthorizationRequest?,
        authorizationResponse: AuthorizationErrorResponse,
        walletNonce: String
    ) throws -> [String: String] {
        return expectedErrorResponse
    }
}
