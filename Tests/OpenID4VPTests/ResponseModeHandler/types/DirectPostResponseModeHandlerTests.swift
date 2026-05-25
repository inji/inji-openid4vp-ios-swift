@testable import OpenID4VP
import XCTest

final class DirectPostResponseModeHandlerTests: XCTestCase {
    let mockVPTokens = VPTokenType.vpTokenElement(LdpVPToken(context: ["context"], type: ["typ1"], verifiableCredential: [AnyCodable(ldpVC())], id: "identifier", holder: "holder", proof: Proof(type: "Ed25519Signature2018", created: "2021-03-19T15:30:15Z", challenge: "n-0S6_WzA2Mj", domain: "https://client.example.org/cb", jws: "eyJhbG...IAoDA", proofPurpose: .vpProofPurpose, verificationMethod: "did:example:holder#key-1")))

    let mockPresentationSubmission = PresentationSubmission(definitionId: "client-identifier", descriptorMap: [DescriptorMap(id: "input_1", format: .ldp_vp, path: "$", pathNested: PathNested(id: "input_1", format: .ldp_vc, path: "$.verifiableCredential[0]"))])

    private let mockNetworkManager = MockNetworkManager()
    private let responseUri = "https://mock-verifier.com"

    private var walletConfig: WalletConfig!

    override func setUpWithError() throws {
        walletConfig = createWalletConfig()
    }

    func testValidationClientMetadatadaNotThrowErrorForDirectPost() throws {
        let directPostAuthorizationResponseModeHandler = DirectPostResponseModeHandler()

        XCTAssertNoThrow(try directPostAuthorizationResponseModeHandler.validate(clientMetadata: mockClientMetadataSpecVersionDraft23[.directPost], walletConfig: walletConfig, shouldValidateWithWalletMetadata: true))
    }

    func testSendAuthorizationResponseForDirectPostResponseMode() async throws {
        let directPostAuthorizationResponseModeHandler = DirectPostResponseModeHandler()
        let authorizationResponse: AuthorizationResponse = .presentationExchange(vpToken: mockVPTokens, presentationSubmission: mockPresentationSubmission, state: "state")
        mockNetworkManager.clearResponses()
        mockNetworkManager.setMockResponse(for: responseUri, responseBody: "Response has been shared successfully here.")

        do {
            let result = try await directPostAuthorizationResponseModeHandler.sendAuthorizationResponse(authorizationRequest: mockAuthorizationRequestObjectWithDirectPostResponseMode, authorizationResponse: authorizationResponse, url: mockAuthorizationRequestObjectWithDirectPostResponseMode.responseUri!, networkManager: mockNetworkManager,
                                                                                                        producerInfo: "mock-nonce",
                                                                                                        recipientInfo: "verifier-nonce",
                                                                                                        walletConfig: walletConfig)

            let recordedRequest = mockNetworkManager.recordedRequests[responseUri]
            XCTAssertEqual(HttpMethod.post, recordedRequest?.requestMethod)
            XCTAssertTrue(recordedRequest?.requestBody?.keys.count == 3)
            XCTAssertTrue((recordedRequest?.requestBody?.keys.allSatisfy(["vp_token", "presentation_submission", "state"].contains(_:))) != nil)
            assertDictionariesEqual(expected: ["Content-Type": ContentTypes.applicationFormUrlEncoded.rawValue], actual: recordedRequest?.requestHeaders)
            XCTAssertEqual("Response has been shared successfully here.", result.body)
        }
    }

    func testShouldThrowErrorIfNoJwkMatchingUseKeyIsFound() throws {
            
            let clientMetadataStr = """
            {
                "client_name": "Requestername",
                "logo_uri": "<logo_uri>",
                "authorization_encrypted_response_alg": "ECDH-ES",
                "authorization_encrypted_response_enc": "A256GCM",
                "jwks": {
                    "keys": [
                        {
                            "kty": "OKP",
                            "crv": "X25519",
                            "use": "sig",
                            "x": "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
                            "alg": "ECDH-ES",
                            "kid": "ed-key1"
                        }
                    ]
                },
                "vp_formats": {
                    "mso_mdoc": {
                        "alg": ["ES256"]
                    }
                }
            }
            """

            let clientMetadata = try JSONDecoder().decode(ClientMetadataDraft23.self, from: Data(clientMetadataStr.utf8))
            let handler = DirectPostJwtResponseModeHandler()

            
            let expectedMessage = "No jwk matching the specified algorithm found for encryption"

            XCTAssertThrowsError(
                try handler.validate(
                    clientMetadata: clientMetadata,
                    walletConfig: walletConfig,
                    shouldValidateWithWalletMetadata: false
                )
            ) { error in
                assertOpenID4VPException(
                    error,
                    expectedMessage: expectedMessage,
                    expectedCode: OpenID4VPErrorCodes.invalidRequest
                )
            }
        }
    
    func testShouldReturnGetAuthorizationSuccessResponseSuccesfully() throws {
        let handler = DirectPostResponseModeHandler()

        let authorizationResponse: AuthorizationResponse = AuthorizationResponse.presentationExchange(
            vpToken: mockVPTokens,
            presentationSubmission: mockPresentationSubmission,
            state: "sample-state"
        )

        let result = try handler.getAuthorizationResponse(
            authorizationRequest: mockAuthorizationRequestObjectWithDirectPostResponseMode,
            authorizationResponse: authorizationResponse,
            walletNonce: "mock-nonce",
            walletConfig: walletConfig
        )

        XCTAssertEqual(result["state"], "sample-state")
        XCTAssertNotNil(result["vp_token"])
        XCTAssertNotNil(result["presentation_submission"])
    }

    func testShouldReturnGetAuthorizationErrorResponseSuccesfully() throws {
        let handler = DirectPostResponseModeHandler()

        let errorResponse = AuthorizationErrorResponse(
            error: "invalid_request",
            errorDescription: "Something went wrong",
            state: "error-state"
        )

        let result = handler.getAuthorizationErrorResponse(
            authorizationRequest: mockAuthorizationRequestObjectWithDirectPostResponseMode,
            authorizationResponse: errorResponse,
            walletNonce: "mock-nonce"
        )

        XCTAssertEqual(result["error"], "invalid_request")
        XCTAssertEqual(result["error_description"], "Something went wrong")
        XCTAssertEqual(result["state"], "error-state")
    }

    func testThrowErrorWhenEncryptionRelatedPropertiesAvailableInVerifierMetadata() throws {
        let handler = DirectPostResponseModeHandler()

        let baseFields = """
            "client_name": "Test",
            "logo_uri": "https://example.com/logo.png",
            "jwks": { "keys": [{ "kty": "OKP", "crv": "Ed25519", "use": "sig", "alg": "ECDH-ES", "kid": "key1", "x": "5tvU4k_TGAfDAru3LfS53qbfHzghjc0kvPGAb2VUwWc" }] },
            "vp_formats": { "ldp_vc": { "proof_type": ["Ed25519Signature2020"] } }
        """

        let draft23EncryptionFields: [String] = [
            "\"authorization_encrypted_response_alg\": \"ECDH-ES\"",
            "\"authorization_encrypted_response_enc\": \"A256GCM\"",
            "\"authorization_encrypted_response_alg\": \"ECDH-ES\", \"authorization_encrypted_response_enc\": \"A256GCM\""
        ]

        for encryptionField in draft23EncryptionFields {
            let json = "{ \(baseFields), \(encryptionField) }"
            let draft23ClientMetadata = try JSONDecoder().decode(ClientMetadataDraft23.self, from: Data(json.utf8))
            XCTAssertThrowsError(
                try handler.validate(clientMetadata: draft23ClientMetadata, walletConfig: walletConfig, shouldValidateWithWalletMetadata: false)
            ) { error in
                assertOpenID4VPException(error, expectedMessage: "encrypted_response_enc_values_supported or authorization_encrypted_response_alg SHOULD not be present for response mode 'direct_post'", expectedCode: OpenID4VPErrorCodes.invalidRequest)
            }
        }

        let v1ClientMetadataStr = """
        {
            "authorization_encrypted_response_alg": "ECDH-ES",
            "encrypted_response_enc_values_supported": ["A256GCM"],
            "jwks": { "keys": [{ "kty": "OKP", "crv": "Ed25519", "use": "sig", "alg": "ECDH-ES", "kid": "key1", "x": "5tvU4k_TGAfDAru3LfS53qbfHzghjc0kvPGAb2VUwWc" }] },
            "vp_formats_supported": { "ldp_vc": { "proof_type_values": ["Ed25519Signature2020"] } }
        }
        """
        let v1ClientMetadata = try JSONDecoder().decode(ClientMetadata.self, from: Data(v1ClientMetadataStr.utf8))
        XCTAssertThrowsError(
            try handler.validate(clientMetadata: v1ClientMetadata, walletConfig: walletConfig, shouldValidateWithWalletMetadata: false)
        ) { error in
            assertOpenID4VPException(error, expectedMessage: "encrypted_response_enc_values_supported SHOULD not be present for response mode 'direct_post'", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }
    
    func testGetVerifierPublicKeyForEncryptionReturnsNilForBothSpecVersions() throws {
        let handler = DirectPostResponseModeHandler()

        for specVersion: SpecVersion in [.draft23, .v1] {
            let result = try handler.getVerifierPublicKeyForEncryption(
                authorizationRequest: getMockAuthorizationRequest(responseMode: .directPost, specVersion: specVersion),
                        walletConfig: walletConfig
            )
            XCTAssertNil(result)
        }
    }

    func testGetVerifierPublicKeyForEncryptionReturnsNilWithNilWalletMetadata() throws {
        let handler = DirectPostResponseModeHandler()
        let result = try handler.getVerifierPublicKeyForEncryption(
            authorizationRequest: getMockAuthorizationRequest(responseMode: .directPost, specVersion: .v1),
                    walletConfig: WalletConfig()
        )
        XCTAssertNil(result)
    }
}
