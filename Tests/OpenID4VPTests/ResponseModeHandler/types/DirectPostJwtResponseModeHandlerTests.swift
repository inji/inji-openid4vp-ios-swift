import XCTest
@testable import OpenID4VP

final class DirectPostJwtResponseModeHandlerTests: XCTestCase {
    private let directPostJwtResponseModeHandler = DirectPostJwtResponseModeHandler()
    let mockVPTokens = VPTokenType.vpTokenElement(LdpVpToken(context: ["context"], type: ["typ1"], verifiableCredential: ["VC1"], id: "identifier", holder: "holder", proof: Proof(type: "Ed25519Signature2018", created: "2021-03-19T15:30:15Z", challenge: "n-0S6_WzA2Mj", domain: "https://client.example.org/cb", jws: "eyJhbG...IAoDA", proofPurpose: .vpProofPurpose, verificationMethod: "did:example:holder#key-1")))

    let mockPresentationSubmission = PresentationSubmission(definition_id: "client-identifier", descriptor_map: [DescriptorMap(id: "input_1", format: .ldp_vp, path: "$", pathNested: PathNested(id: "input_1", format: .ldp_vp, path: "$.verifiableCredential[0]"))])
    private let mockNetworkManager = MockNetworkManager()
    private let responseUri = "https://mock-verifier.com"

/// client metadata validation tests
    
    func testThrowErrorWhenClientMetadataIsNil() throws {
        XCTAssertThrowsError(try directPostJwtResponseModeHandler.validate(clientMetadata: nil)) { error in
            XCTAssertEqual("client_metadata must be present for given response mode", error.localizedDescription)
        }
    }
    
    func testThrowErrorWhenClientMetadataDoesNotHaveAuthorizationEncryptedResponseAlg() throws {
        let invalidClientMetadataForDirectPostJwt: [String: Any] = [
            "client_name": "Requester name",
            "logo_uri": "https://mock-verifier.com/logo",
            "authorization_encrypted_response_enc": "A256GCM",
            "jwks": [
                "keys": [[
                    "kty": "OKP",
                    "crv": "X25519",
                    "use": "enc",
                    "x": "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
                    "alg": "ECDH-ES",
                    "kid": "ed-key1"
                ]]
            ],
            "vp_formats": [
                "mso_mdoc": [
                    "alg": [
                        "ES256",
                        "EdDSA"
                    ]
                ],
                "ldp_vp": [
                    "proof_type": [
                        "Ed25519Signature2018",
                        "Ed25519Signature2020",
                        "RsaSignature2018"
                    ]
                ]
            ]
        ]

        XCTAssertThrowsError(try directPostJwtResponseModeHandler.validate(clientMetadata: createInstance(invalidClientMetadataForDirectPostJwt, as: ClientMetadata.self))) { error in
            XCTAssertEqual("Missing Input: client_metadata->authorization_encrypted_response_alg param is required", error.localizedDescription)
        }
    }
    
    func testThrowErrorWhenClientMetadataDoesNotHaveAuthorizationEncryptedResponseEnc() throws {
        let invalidClientMetadataForDirectPostJwt: [String: Any] = [
            "client_name": "Requester name",
            "logo_uri": "https://mock-verifier.com/logo",
            "authorization_encrypted_response_alg": "ECDH-ES",
            "jwks": [
                "keys": [[
                    "kty": "OKP",
                    "crv": "X25519",
                    "use": "enc",
                    "x": "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
                    "alg": "ECDH-ES",
                    "kid": "ed-key1"
                ]]
            ],
            "vp_formats": [
                "mso_mdoc": [
                    "alg": [
                        "ES256",
                        "EdDSA"
                    ]
                ],
                "ldp_vp": [
                    "proof_type": [
                        "Ed25519Signature2018",
                        "Ed25519Signature2020",
                        "RsaSignature2018"
                    ]
                ]
            ]
        ]

        XCTAssertThrowsError(try directPostJwtResponseModeHandler.validate(clientMetadata: createInstance(invalidClientMetadataForDirectPostJwt, as: ClientMetadata.self))) { error in
            XCTAssertEqual("Missing Input: client_metadata->authorization_encrypted_response_enc param is required", error.localizedDescription)
        }
    }
    
    func testThrowErrorWhenClientMetadataDoesNotHaveJwks() throws {
        let invalidClientMetadataForDirectPostJwt: [String: Any] = [
            "client_name": "Requester name",
            "logo_uri": "https://mock-verifier.com/logo",
            "authorization_encrypted_response_alg": "ECDH-ES",
            "authorization_encrypted_response_enc": "A256GCM",
            "vp_formats": [
                "mso_mdoc": [
                    "alg": [
                        "ES256",
                        "EdDSA"
                    ]
                ],
                "ldp_vp": [
                    "proof_type": [
                        "Ed25519Signature2018",
                        "Ed25519Signature2020",
                        "RsaSignature2018"
                    ]
                ]
            ]
        ]

        XCTAssertThrowsError(try directPostJwtResponseModeHandler.validate(clientMetadata: createInstance(invalidClientMetadataForDirectPostJwt, as: ClientMetadata.self))) { error in
            XCTAssertEqual("Missing Input: client_metadata->jwks param is required", error.localizedDescription)
        }
    }
    
    func testThrowErrorWhenClientMetadataDoesNotHaveJwkWithAlgorithmMentioned() throws {
        let invalidClientMetadataForDirectPostJwt: [String: Any] = [
            "client_name": "Requester name",
            "logo_uri": "https://mock-verifier.com/logo",
            "authorization_encrypted_response_alg": "ECDH-ES",
            "authorization_encrypted_response_enc": "A256GCM",
            "jwks": [
                "keys": [[
                    "kty": "OKP",
                    "crv": "X25519",
                    "use": "enc",
                    "x": "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
                    "alg": "ECH-ES",
                    "kid": "ed-key1"
                ]]
            ],
            "vp_formats": [
                "mso_mdoc": [
                    "alg": [
                        "ES256",
                        "EdDSA"
                    ]
                ],
                "ldp_vp": [
                    "proof_type": [
                        "Ed25519Signature2018",
                        "Ed25519Signature2020",
                        "RsaSignature2018"
                    ]
                ]
            ]
        ]

        XCTAssertThrowsError(try directPostJwtResponseModeHandler.validate(clientMetadata: createInstance(invalidClientMetadataForDirectPostJwt, as: ClientMetadata.self))) { error in
            XCTAssertEqual("No jwk matching the specified algorithm found", error.localizedDescription)
        }
    }
    
    func testShouldNotThrowErrorForValidClientMetadataOnValidation() {
        XCTAssertNoThrow(try directPostJwtResponseModeHandler.validate(clientMetadata: mockClientMetadataObject))
    }
    
 /// Send authorization response tests

    func testSendAuthorizationResponseForDirectPostJwtResponseMode()  async throws {
        mockNetworkManager.setMockResponse(for: responseUri, responseBody: "Response has been shared successfully here.")
        let authorizationResponse: AuthorizationResponse = AuthorizationResponse(vpToken: mockVPTokens, presentation_submission: mockPresentationSubmission, state: "state")
        
        do {
            let result = try await directPostJwtResponseModeHandler.sendAuthorizationResponse(authorizationRequest: mockAuthorizationRequestObjectWithDirectPostJwtResponseMode, authorizationResponse: authorizationResponse, url: mockAuthorizationRequestObjectWithDirectPostJwtResponseMode.responseUri!, networkManager: mockNetworkManager)
            
            let recordedRequest = mockNetworkManager.recordedRequests[responseUri]
            XCTAssertEqual(HttpMethod.post, recordedRequest?.requestMethod)
            XCTAssertTrue(recordedRequest?.requestBody?.keys.count == 1)
            XCTAssertTrue(((recordedRequest?.requestBody?.keys.allSatisfy(["request"].contains(_:))) != nil))
            assertDictionariesEqual(expected: ["Content-Type":ContentTypes.applicationFormUrlEncoded.rawValue], actual: recordedRequest?.requestHeaders)
            XCTAssertEqual("Response has been shared successfully here.", result)
        }
    }
}
