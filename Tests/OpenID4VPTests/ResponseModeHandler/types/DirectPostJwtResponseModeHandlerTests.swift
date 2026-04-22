import XCTest
@testable import OpenID4VP

final class DirectPostJwtResponseModeHandlerTests: XCTestCase {
    private let directPostJwtResponseModeHandler = DirectPostJwtResponseModeHandler()
    let mockVPTokens = VPTokenType.vpTokenElement(LdpVPToken(context: ["context"], type: ["typ1"], verifiableCredential: [AnyCodable(ldpVC())], id: "identifier", holder: "holder", proof: Proof(type: "Ed25519Signature2018", created: "2021-03-19T15:30:15Z", challenge: "n-0S6_WzA2Mj", domain: "https://client.example.org/cb", jws: "eyJhbG...IAoDA", proofPurpose: .vpProofPurpose, verificationMethod: "did:example:holder#key-1")))
    
    let mockPresentationSubmission = PresentationSubmission(definitionId: "client-identifier", descriptorMap: [DescriptorMap(id: "input_1", format: .ldp_vp, path: "$", pathNested: PathNested(id: "input_1", format: .ldp_vc, path: "$.verifiableCredential[0]"))])
    private let mockNetworkManager = MockNetworkManager()
    private let responseUri = "https://mock-verifier.com"
    
    private var walletMetadata: WalletMetadata!
    
    override func setUpWithError() throws {
        walletMetadata = try createWalletMetadata()
    }
    
    /// client metadata validation tests
    
    func testThrowErrorWhenClientMetadataIsNil() throws {
        XCTAssertThrowsError(try directPostJwtResponseModeHandler.validate(clientMetadata: nil as ClientMetadata?, walletMetadata: walletMetadata, shouldValidateWithWalletMetadata: true)) { error in
            XCTAssertEqual("client_metadata must be present for given response mode", error.localizedDescription)
        }
        
        XCTAssertThrowsError(try directPostJwtResponseModeHandler.validate(clientMetadata: nil as ClientMetadataDraft23?, walletMetadata: walletMetadata, shouldValidateWithWalletMetadata: true)) { error in
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
                "mso_mdoc": ["alg": ["ES256", "EdDSA"]],
                "ldp_vp": ["proof_type": ["Ed25519Signature2018", "Ed25519Signature2020", "RsaSignature2018"]]
            ]
        ]

        XCTAssertThrowsError(try directPostJwtResponseModeHandler.validate(clientMetadata: createInstance(invalidClientMetadataForDirectPostJwt, as: ClientMetadataDraft23.self), walletMetadata: walletMetadata, shouldValidateWithWalletMetadata: true)) { error in
            XCTAssertEqual("Missing Input: client_metadata->authorization_encrypted_response_alg param is required", error.localizedDescription)
        }

        let invalidClientMetadataV1: [String: Any] = [
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
            "vp_formats_supported": ["ldp_vc": ["proof_type_values": ["Ed25519Signature2020"]]]
        ]

        XCTAssertThrowsError(try directPostJwtResponseModeHandler.validate(clientMetadata: createInstance(invalidClientMetadataV1, as: ClientMetadata.self), walletMetadata: walletMetadata, shouldValidateWithWalletMetadata: true)) { error in
            XCTAssertEqual("Missing Input: client_metadata->encrypted_response_enc_values_supported param is required", error.localizedDescription)
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
                "mso_mdoc": ["alg": ["ES256", "EdDSA"]],
                "ldp_vp": ["proof_type": ["Ed25519Signature2018", "Ed25519Signature2020", "RsaSignature2018"]]
            ]
        ]

        XCTAssertThrowsError(try directPostJwtResponseModeHandler.validate(clientMetadata: createInstance(invalidClientMetadataForDirectPostJwt, as: ClientMetadataDraft23.self), walletMetadata: walletMetadata, shouldValidateWithWalletMetadata: true)) { error in
            XCTAssertEqual("Missing Input: client_metadata->authorization_encrypted_response_enc param is required", error.localizedDescription)
        }

        let invalidClientMetadataV1: [String: Any] = [
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
            "vp_formats_supported": ["ldp_vc": ["proof_type_values": ["Ed25519Signature2020"]]]
        ]

        XCTAssertThrowsError(try directPostJwtResponseModeHandler.validate(clientMetadata: createInstance(invalidClientMetadataV1, as: ClientMetadata.self), walletMetadata: walletMetadata, shouldValidateWithWalletMetadata: true)) { error in
            XCTAssertEqual("Missing Input: client_metadata->encrypted_response_enc_values_supported param is required", error.localizedDescription)
        }
    }
    
    func testThrowErrorWhenClientMetadataDoesNotHaveJwks() throws {
        let invalidClientMetadataForDirectPostJwt: [String: Any] = [
            "client_name": "Requester name",
            "logo_uri": "https://mock-verifier.com/logo",
            "authorization_encrypted_response_alg": "ECDH-ES",
            "authorization_encrypted_response_enc": "A256GCM",
            "vp_formats": [
                "mso_mdoc": ["alg": ["ES256", "EdDSA"]],
                "ldp_vp": ["proof_type": ["Ed25519Signature2018", "Ed25519Signature2020", "RsaSignature2018"]]
            ]
        ]

        XCTAssertThrowsError(try directPostJwtResponseModeHandler.validate(clientMetadata: createInstance(invalidClientMetadataForDirectPostJwt, as: ClientMetadataDraft23.self), walletMetadata: walletMetadata, shouldValidateWithWalletMetadata: true)) { error in
            XCTAssertEqual("Missing Input: client_metadata->jwks param is required", error.localizedDescription)
        }

        let invalidClientMetadataV1: [String: Any] = [
            "authorization_encrypted_response_alg": "ECDH-ES",
            "encrypted_response_enc_values_supported": ["A256GCM"],
            "vp_formats_supported": ["ldp_vc": ["proof_type_values": ["Ed25519Signature2020"]]]
        ]

        XCTAssertThrowsError(try directPostJwtResponseModeHandler.validate(clientMetadata: createInstance(invalidClientMetadataV1, as: ClientMetadata.self), walletMetadata: walletMetadata, shouldValidateWithWalletMetadata: true)) { error in
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
                "mso_mdoc": ["alg": ["ES256", "EdDSA"]],
                "ldp_vp": ["proof_type": ["Ed25519Signature2018", "Ed25519Signature2020", "RsaSignature2018"]]
            ]
        ]

        XCTAssertThrowsError(try directPostJwtResponseModeHandler.validate(clientMetadata: createInstance(invalidClientMetadataForDirectPostJwt, as: ClientMetadataDraft23.self), walletMetadata: walletMetadata, shouldValidateWithWalletMetadata: true)) { error in
            XCTAssertEqual("No jwk matching the specified algorithm found for encryption", error.localizedDescription)
        }

        let invalidClientMetadataV1: [String: Any] = [
            "authorization_encrypted_response_alg": "ECDH-ES",
            "encrypted_response_enc_values_supported": ["A256GCM"],
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
            "vp_formats_supported": ["ldp_vc": ["proof_type_values": ["Ed25519Signature2020"]]]
        ]

        XCTAssertThrowsError(try directPostJwtResponseModeHandler.validate(clientMetadata: createInstance(invalidClientMetadataV1, as: ClientMetadata.self), walletMetadata: walletMetadata, shouldValidateWithWalletMetadata: true)) { error in
            XCTAssertEqual("Authorization response encryption algorithm is not supported", error.localizedDescription)
        }
    }
    
    func testThrowErrorWhenClientMetadataResponseEncDoesNotMatchWithWalletMetadataResponseEnc() throws {
        let invalidClientMetadataForDirectPostJwt: [String: Any] = [
            "client_name": "Requester name",
            "logo_uri": "https://mock-verifier.com/logo",
            "authorization_encrypted_response_alg": "ECDH-ES",
            "authorization_encrypted_response_enc": "A128GCM",
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
                "ldp_vp": ["proof_type": ["Ed25519Signature2018", "Ed25519Signature2020", "RsaSignature2018"]]
            ]
        ]

        XCTAssertThrowsError(try directPostJwtResponseModeHandler.validate(clientMetadata: createInstance(invalidClientMetadataForDirectPostJwt, as: ClientMetadataDraft23.self), walletMetadata: walletMetadata, shouldValidateWithWalletMetadata: true)) { error in
            XCTAssertEqual("authorization_encrypted_response_enc is not supported", error.localizedDescription)
        }

        let invalidClientMetadataV1: [String: Any] = [
            "encrypted_response_enc_values_supported": ["A128GCM"],
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
            "vp_formats_supported": ["ldp_vc": ["proof_type_values": ["Ed25519Signature2020"]]]
        ]

        XCTAssertThrowsError(try directPostJwtResponseModeHandler.validate(clientMetadata: createInstance(invalidClientMetadataV1, as: ClientMetadata.self), walletMetadata: walletMetadata, shouldValidateWithWalletMetadata: true)) { error in
            XCTAssertEqual("authorization_encrypted_response_enc is not supported", error.localizedDescription)
        }
    }
    
    func testThrowErrorWhenClientMetadataResponseAlgDoesNotMatchWithWalletMetadataResponseAlg() throws {
        let invalidClientMetadataForDirectPostJwt: [String: Any] = [
            "client_name": "Requester name",
            "logo_uri": "https://mock-verifier.com/logo",
            "authorization_encrypted_response_alg": "ECDH-AS",
            "authorization_encrypted_response_enc": "A256GCM",
            "jwks": [
                "keys": [[
                    "kty": "OKP",
                    "crv": "X25519",
                    "use": "enc",
                    "x": "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
                    "alg": "ECDH-AS",
                    "kid": "ed-key1"
                ]]
            ],
            "vp_formats": [
                "ldp_vp": ["proof_type": ["Ed25519Signature2018", "Ed25519Signature2020", "RsaSignature2018"]]
            ]
        ]

        let mismatchingWalletMetadata = try createWalletMetadata()

        XCTAssertThrowsError(try directPostJwtResponseModeHandler.validate(clientMetadata: createInstance(invalidClientMetadataForDirectPostJwt, as: ClientMetadataDraft23.self), walletMetadata: mismatchingWalletMetadata, shouldValidateWithWalletMetadata: true)) { error in
            XCTAssertEqual("Authorization response encryption algorithm is not supported", error.localizedDescription)
        }

        let invalidClientMetadataV1: [String: Any] = [
            "authorization_encrypted_response_alg": "ECDH-AS",
            "encrypted_response_enc_values_supported": ["A256GCM"],
            "jwks": [
                "keys": [[
                    "kty": "OKP",
                    "crv": "X25519",
                    "use": "enc",
                    "x": "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
                    "alg": "ECDH-AS",
                    "kid": "ed-key1"
                ]]
            ],
            "vp_formats_supported": ["ldp_vc": ["proof_type_values": ["Ed25519Signature2020"]]]
        ]

        XCTAssertThrowsError(try directPostJwtResponseModeHandler.validate(clientMetadata: createInstance(invalidClientMetadataV1, as: ClientMetadata.self), walletMetadata: mismatchingWalletMetadata, shouldValidateWithWalletMetadata: true)) { error in
            XCTAssertEqual("Authorization response encryption algorithm is not supported", error.localizedDescription)
        }
    }
    
    func testThrowErrorWhenWalletMetadataIsNilAndIfRequiredValuesAreNil() throws {
        let validClientMetadataForDirectPostJwt: [String: Any] = [
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
                    "alg": "ECDH-ES",
                    "kid": "ed-key1"
                ]]
            ],
            "vp_formats": [
                "ldp_vp": [
                    "proof_type": [
                        "Ed25519Signature2018",
                        "Ed25519Signature2020",
                        "RsaSignature2018"
                    ]
                ]
            ]
        ]

        let validClientMetadataV1: [String: Any] = [
            "authorization_encrypted_response_alg": "ECDH-ES",
            "encrypted_response_enc_values_supported": ["A256GCM"],
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
            "vp_formats_supported": ["ldp_vc": ["proof_type_values": ["Ed25519Signature2020"]]]
        ]

        XCTAssertThrowsError(try directPostJwtResponseModeHandler.validate(clientMetadata: createInstance(validClientMetadataForDirectPostJwt, as: ClientMetadataDraft23.self), walletMetadata: nil, shouldValidateWithWalletMetadata: true)) { error in
            assertOpenID4VPException(error, expectedMessage: "wallet_metadata must be present", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
        XCTAssertThrowsError(try directPostJwtResponseModeHandler.validate(clientMetadata: createInstance(validClientMetadataV1, as: ClientMetadata.self), walletMetadata: nil, shouldValidateWithWalletMetadata: true)) { error in
            assertOpenID4VPException(error, expectedMessage: "wallet_metadata must be present", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }

        var invalidWalletMetadata = try createWalletMetadata(authorizationEncryptionAlgValuesSupported: nil)
        XCTAssertThrowsError(try directPostJwtResponseModeHandler.validate(clientMetadata: createInstance(validClientMetadataForDirectPostJwt, as: ClientMetadataDraft23.self), walletMetadata: invalidWalletMetadata, shouldValidateWithWalletMetadata: true)) { error in
            assertOpenID4VPException(error, expectedMessage: "authorization_encryption_alg_values_supported must be present in wallet_metadata", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
        XCTAssertThrowsError(try directPostJwtResponseModeHandler.validate(clientMetadata: createInstance(validClientMetadataV1, as: ClientMetadata.self), walletMetadata: invalidWalletMetadata, shouldValidateWithWalletMetadata: true)) { error in
            assertOpenID4VPException(error, expectedMessage: "authorization_encryption_alg_values_supported must be present in wallet_metadata", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }

        invalidWalletMetadata = try createWalletMetadata(authorizationEncryptionEncValuesSupported: nil)
        XCTAssertThrowsError(try directPostJwtResponseModeHandler.validate(clientMetadata: createInstance(validClientMetadataForDirectPostJwt, as: ClientMetadataDraft23.self), walletMetadata: invalidWalletMetadata, shouldValidateWithWalletMetadata: true)) { error in
            assertOpenID4VPException(error, expectedMessage: "authorization_encryption_enc_values_supported must be present in wallet_metadata", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
        XCTAssertThrowsError(try directPostJwtResponseModeHandler.validate(clientMetadata: createInstance(validClientMetadataV1, as: ClientMetadata.self), walletMetadata: invalidWalletMetadata, shouldValidateWithWalletMetadata: true)) { error in
            assertOpenID4VPException(error, expectedMessage: "authorization_encryption_enc_values_supported must be present in wallet_metadata", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }
    
    func testShouldNotThrowErrorForValidClientMetadataOnValidation() {
        XCTAssertNoThrow(try directPostJwtResponseModeHandler.validate(clientMetadata: mockClientMetadataSpecVersionDraft23[.directPostJwt], walletMetadata: walletMetadata, shouldValidateWithWalletMetadata: true))
        XCTAssertNoThrow(try directPostJwtResponseModeHandler.validate(clientMetadata: mockClientMetadataSpecVersion1[.directPostJwt], walletMetadata: walletMetadata, shouldValidateWithWalletMetadata: true))
    }

    func testShouldNotThrowErrorWhenShouldValidateWithWalletMetadataIsFalse() {
        XCTAssertNoThrow(try directPostJwtResponseModeHandler.validate(clientMetadata: mockClientMetadataSpecVersionDraft23[.directPostJwt], walletMetadata: nil, shouldValidateWithWalletMetadata: false))
        XCTAssertNoThrow(try directPostJwtResponseModeHandler.validate(clientMetadata: mockClientMetadataSpecVersion1[.directPostJwt], walletMetadata: nil, shouldValidateWithWalletMetadata: false))
    }

    func testThrowErrorWhenEncValuesIsEmptyArrayForSpecVersion1() throws {
        let invalidClientMetadataV1: [String: Any] = [
            "authorization_encrypted_response_alg": "ECDH-ES",
            "encrypted_response_enc_values_supported": [],
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
            "vp_formats_supported": ["ldp_vc": ["proof_type_values": ["Ed25519Signature2020"]]]
        ]
        XCTAssertThrowsError(try directPostJwtResponseModeHandler.validate(clientMetadata: createInstance(invalidClientMetadataV1, as: ClientMetadata.self), walletMetadata: walletMetadata, shouldValidateWithWalletMetadata: false)) { error in
            assertOpenID4VPException(error, expectedMessage: "encrypted_response_enc_values_supported must be a non-empty array", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    func testThrowErrorWhenV1ClientMetadataEncDoesNotContainSupportedValue() throws {
        let invalidClientMetadataV1: [String: Any] = [
            "authorization_encrypted_response_alg": "ECDH-ES",
            "encrypted_response_enc_values_supported": ["A128GCM"],
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
            "vp_formats_supported": ["ldp_vc": ["proof_type_values": ["Ed25519Signature2020"]]]
        ]
        let v1Request = getMockAuthorizationRequest(responseMode: .directPostJwt, specVersion: .v1)
        let authorizationResponse = AuthorizationResponse.presentationExchange(vpToken: mockVPTokens, presentationSubmission: mockPresentationSubmission, state: "state")
        XCTAssertThrowsError(try directPostJwtResponseModeHandler.getAuthorizationResponse(authorizationRequest: AuthorizationDcqlRequest(clientId: v1Request.clientId, responseType: v1Request.responseType, responseMode: v1Request.responseMode, responseUri: v1Request.responseUri, redirectUri: v1Request.redirectUri, nonce: v1Request.nonce, walletNonce: v1Request.walletNonce, state: v1Request.state, dcqlQuery: validDcqlQuery, clientMetadata: createInstance(invalidClientMetadataV1, as: ClientMetadata.self)), authorizationResponse: authorizationResponse, walletNonce: "mock-nonce", walletMetadata: nil)) { error in
            assertOpenID4VPException(error, expectedMessage: "Unsupported content encryption algorithm", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }
    
    func testGetAuthorizationResponseThrowsWhenV1ClientMetadataIsNil() throws {
        let v1Request = getMockAuthorizationRequest(responseMode: .directPostJwt, specVersion: .v1)
        let requestWithNilMetadata = AuthorizationDcqlRequest(
            clientId: v1Request.clientId,
            responseType: v1Request.responseType,
            responseMode: v1Request.responseMode,
            responseUri: v1Request.responseUri,
            redirectUri: v1Request.redirectUri,
            nonce: v1Request.nonce,
            walletNonce: v1Request.walletNonce,
            state: v1Request.state,
            dcqlQuery: validDcqlQuery,
            clientMetadata: nil
        )
        let authorizationResponse = AuthorizationResponse.presentationExchange(vpToken: mockVPTokens, presentationSubmission: mockPresentationSubmission, state: "state")

        XCTAssertThrowsError(try directPostJwtResponseModeHandler.getAuthorizationResponse(authorizationRequest: requestWithNilMetadata, authorizationResponse: authorizationResponse, walletNonce: "mock-nonce", walletMetadata: nil)) { error in
            assertOpenID4VPException(error, expectedMessage: "client_metadata must be present for given response mode", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    func testGetAuthorizationResponseThrowsWhenV1ClientMetadataHasNoJwks() throws {
        let clientMetadataWithoutJwks: [String: Any] = [
            "encrypted_response_enc_values_supported": ["A256GCM"],
            "vp_formats_supported": ["ldp_vc": ["proof_type_values": ["Ed25519Signature2020"]]]
        ]
        let v1Request = getMockAuthorizationRequest(responseMode: .directPostJwt, specVersion: .v1)
        let requestWithNoJwks = AuthorizationDcqlRequest(
            clientId: v1Request.clientId,
            responseType: v1Request.responseType,
            responseMode: v1Request.responseMode,
            responseUri: v1Request.responseUri,
            redirectUri: v1Request.redirectUri,
            nonce: v1Request.nonce,
            walletNonce: v1Request.walletNonce,
            state: v1Request.state,
            dcqlQuery: validDcqlQuery,
            clientMetadata: createInstance(clientMetadataWithoutJwks, as: ClientMetadata.self)
        )
        let authorizationResponse = AuthorizationResponse.presentationExchange(vpToken: mockVPTokens, presentationSubmission: mockPresentationSubmission, state: "state")

        XCTAssertThrowsError(try directPostJwtResponseModeHandler.getAuthorizationResponse(authorizationRequest: requestWithNoJwks, authorizationResponse: authorizationResponse, walletNonce: "mock-nonce", walletMetadata: nil)) { error in
            assertOpenID4VPException(error, expectedMessage: "Missing Input: client_metadata->jwks param is required", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    func testGetAuthorizationResponseThrowsWhenV1EncryptionKeyHasNoAlgorithm() throws {
        let clientMetadataWithKeyWithoutAlg: [String: Any] = [
            "encrypted_response_enc_values_supported": ["A256GCM"],
            "jwks": [
                "keys": [[
                    "kty": "OKP",
                    "crv": "X25519",
                    "use": "enc",
                    "x": "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
                    "kid": "ed-key1"
                ]]
            ],
            "vp_formats_supported": ["ldp_vc": ["proof_type_values": ["Ed25519Signature2020"]]]
        ]
        let v1Request = getMockAuthorizationRequest(responseMode: .directPostJwt, specVersion: .v1)
        let requestWithKeyWithoutAlg = AuthorizationDcqlRequest(
            clientId: v1Request.clientId,
            responseType: v1Request.responseType,
            responseMode: v1Request.responseMode,
            responseUri: v1Request.responseUri,
            redirectUri: v1Request.redirectUri,
            nonce: v1Request.nonce,
            walletNonce: v1Request.walletNonce,
            state: v1Request.state,
            dcqlQuery: validDcqlQuery,
            clientMetadata: createInstance(clientMetadataWithKeyWithoutAlg, as: ClientMetadata.self)
        )
        let authorizationResponse = AuthorizationResponse.presentationExchange(vpToken: mockVPTokens, presentationSubmission: mockPresentationSubmission, state: "state")

        XCTAssertThrowsError(try directPostJwtResponseModeHandler.getAuthorizationResponse(authorizationRequest: requestWithKeyWithoutAlg, authorizationResponse: authorizationResponse, walletNonce: "mock-nonce", walletMetadata: nil)) { error in
            assertOpenID4VPException(error, expectedMessage: "No encryption key with alg [\"ECDH-ES\"] found in JWK Set", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    // MARK: - getVerifierPublicKeyForEncryption tests

    func testGetVerifierPublicKeyForEncryptionReturnsDraft23EncKey() throws {
        let handler = DirectPostJwtResponseModeHandler()
        let key = try handler.getVerifierPublicKeyForEncryption(
            authorizationRequest: getMockAuthorizationRequest(responseMode: .directPostJwt, specVersion: .draft23),
            walletMetadata: walletMetadata
        )
        XCTAssertNotNil(key)
        XCTAssertEqual(key?.algorithm, "ECDH-ES")
        XCTAssertEqual(key?.publicKeyUse, .encryption)
    }

    func testGetVerifierPublicKeyForEncryptionReturnsV1EncKey() throws {
        let handler = DirectPostJwtResponseModeHandler()
        let key = try handler.getVerifierPublicKeyForEncryption(
            authorizationRequest: getMockAuthorizationRequest(responseMode: .directPostJwt, specVersion: .v1),
            walletMetadata: walletMetadata
        )
        XCTAssertNotNil(key)
        XCTAssertEqual(key?.publicKeyUse, .encryption)
    }

    func testGetVerifierPublicKeyForEncryptionThrowsWhenV1ClientMetadataIsNil() throws {
        let handler = DirectPostJwtResponseModeHandler()
        let v1Request = getMockAuthorizationRequest(responseMode: .directPostJwt, specVersion: .v1)
        let requestWithNilMetadata = AuthorizationDcqlRequest(
            clientId: v1Request.clientId, responseType: v1Request.responseType,
            responseMode: v1Request.responseMode, responseUri: v1Request.responseUri,
            redirectUri: v1Request.redirectUri, nonce: v1Request.nonce,
            walletNonce: v1Request.walletNonce, state: v1Request.state,
            dcqlQuery: validDcqlQuery,
            clientMetadata: nil
        )
        XCTAssertThrowsError(try handler.getVerifierPublicKeyForEncryption(
            authorizationRequest: requestWithNilMetadata, walletMetadata: walletMetadata
        )) { error in
            assertOpenID4VPException(error,
                expectedMessage: "client_metadata must be present for given response mode",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testGetVerifierPublicKeyForEncryptionThrowsWhenV1JwksIsNil() throws {
        let handler = DirectPostJwtResponseModeHandler()
        let v1Request = getMockAuthorizationRequest(responseMode: .directPostJwt, specVersion: .v1)
        let requestWithNoJwks = AuthorizationDcqlRequest(
            clientId: v1Request.clientId, responseType: v1Request.responseType,
            responseMode: v1Request.responseMode, responseUri: v1Request.responseUri,
            redirectUri: v1Request.redirectUri, nonce: v1Request.nonce,
            walletNonce: v1Request.walletNonce, state: v1Request.state,
            dcqlQuery: validDcqlQuery,
            clientMetadata: createInstance([
                "encrypted_response_enc_values_supported": ["A256GCM"],
                "vp_formats_supported": ["ldp_vc": ["proof_type_values": ["Ed25519Signature2020"]]]
            ], as: ClientMetadata.self)
        )
        XCTAssertThrowsError(try handler.getVerifierPublicKeyForEncryption(
            authorizationRequest: requestWithNoJwks, walletMetadata: walletMetadata
        )) { error in
            assertOpenID4VPException(error,
                expectedMessage: "Missing Input: client_metadata->jwks param is required",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testGetVerifierPublicKeyForEncryptionThrowsWhenNoEncKeyFoundInV1Jwks() throws {
        let handler = DirectPostJwtResponseModeHandler()
        let v1Request = getMockAuthorizationRequest(responseMode: .directPostJwt, specVersion: .v1)
        let requestWithSigOnlyJwks = AuthorizationDcqlRequest(
            clientId: v1Request.clientId, responseType: v1Request.responseType,
            responseMode: v1Request.responseMode, responseUri: v1Request.responseUri,
            redirectUri: v1Request.redirectUri, nonce: v1Request.nonce,
            walletNonce: v1Request.walletNonce, state: v1Request.state,
            dcqlQuery: validDcqlQuery,
            clientMetadata: createInstance([
                "encrypted_response_enc_values_supported": ["A256GCM"],
                "jwks": ["keys": [["kty": "OKP", "crv": "Ed25519", "use": "sig", "alg": "EdDSA", "kid": "sig-key", "x": "5tvU4k_TGAfDAru3LfS53qbfHzghjc0kvPGAb2VUwWc"]]],
                "vp_formats_supported": ["ldp_vc": ["proof_type_values": ["Ed25519Signature2020"]]]
            ], as: ClientMetadata.self)
        )
        XCTAssertThrowsError(try handler.getVerifierPublicKeyForEncryption(
            authorizationRequest: requestWithSigOnlyJwks, walletMetadata: walletMetadata
        )) { error in
            assertOpenID4VPException(error,
                expectedMessage: "No encryption key with alg [\"ECDH-ES\"] found in JWK Set",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    /// Send authorization response tests

    func testSendAuthorizationResponseForDirectPostJwtResponseMode() async throws {
        mockNetworkManager.setMockResponse(for: responseUri, responseBody: "Response has been shared successfully here.")
        let authorizationResponse: AuthorizationResponse = AuthorizationResponse.presentationExchange(vpToken: mockVPTokens, presentationSubmission: mockPresentationSubmission, state: "state")

        let draft23Request = getMockAuthorizationRequest(responseMode: .directPostJwt, specVersion: .draft23)
        let presentationExchangeAuthorizationResponseResult = try await directPostJwtResponseModeHandler.sendAuthorizationResponse(authorizationRequest: draft23Request, authorizationResponse: authorizationResponse, url: draft23Request.responseUri!, networkManager: mockNetworkManager, producerInfo: "mock-nonce", recipientInfo: "verifier-nonce", walletMetadata: nil)
        let draft23RecordedRequest = mockNetworkManager.recordedRequests[responseUri]
        XCTAssertEqual(HttpMethod.post, draft23RecordedRequest?.requestMethod)
        XCTAssertEqual(1, draft23RecordedRequest?.requestBody?.keys.count)
        XCTAssertTrue(draft23RecordedRequest?.requestBody?.keys.allSatisfy(["response"].contains(_:)) == true)
        assertDictionariesEqual(expected: ["Content-Type": ContentTypes.applicationFormUrlEncoded.rawValue], actual: draft23RecordedRequest?.requestHeaders)
        XCTAssertEqual("Response has been shared successfully here.", presentationExchangeAuthorizationResponseResult.body)

        mockNetworkManager.clearResponses()
        mockNetworkManager.setMockResponse(for: responseUri, responseBody: "Response has been shared successfully here.")

        let v1Request = getMockAuthorizationRequest(responseMode: .directPostJwt, specVersion: .v1)
        let dcqlAuthorizationResult = try await directPostJwtResponseModeHandler.sendAuthorizationResponse(authorizationRequest: v1Request, authorizationResponse: authorizationResponse, url: v1Request.responseUri!, networkManager: mockNetworkManager, producerInfo: "mock-nonce", recipientInfo: "verifier-nonce", walletMetadata: nil)
        let v1RecordedRequest = mockNetworkManager.recordedRequests[responseUri]
        XCTAssertEqual(HttpMethod.post, v1RecordedRequest?.requestMethod)
        XCTAssertEqual(1, v1RecordedRequest?.requestBody?.keys.count)
        XCTAssertTrue(v1RecordedRequest?.requestBody?.keys.allSatisfy(["response"].contains(_:)) == true)
        assertDictionariesEqual(expected: ["Content-Type": ContentTypes.applicationFormUrlEncoded.rawValue], actual: v1RecordedRequest?.requestHeaders)
        XCTAssertEqual("Response has been shared successfully here.", dcqlAuthorizationResult.body)
    }

    func testShouldReturnEncryptedResponseForSuccessAuthorizationResponse() throws {
        let handler = DirectPostJwtResponseModeHandler()
        let authorizationResponse = AuthorizationResponse.presentationExchange(vpToken: mockVPTokens, presentationSubmission: mockPresentationSubmission, state: "test-state")

        let presentationExchangeAuthorizationResponseResult = try handler.getAuthorizationResponse(authorizationRequest: getMockAuthorizationRequest(responseMode: .directPostJwt, specVersion: .draft23), authorizationResponse: authorizationResponse, walletNonce: "mock-nonce", walletMetadata: nil)
        XCTAssertEqual(1, presentationExchangeAuthorizationResponseResult.keys.count)
        XCTAssertNotNil(presentationExchangeAuthorizationResponseResult["response"])
        XCTAssertFalse(presentationExchangeAuthorizationResponseResult["response"]!.isEmpty)
        XCTAssertTrue(presentationExchangeAuthorizationResponseResult["response"]!.contains("."))

        let dcqlAuthorizationResult = try handler.getAuthorizationResponse(authorizationRequest: getMockAuthorizationRequest(responseMode: .directPostJwt, specVersion: .v1), authorizationResponse: authorizationResponse, walletNonce: "mock-nonce", walletMetadata: nil)
        XCTAssertEqual(1, dcqlAuthorizationResult.keys.count)
        XCTAssertNotNil(dcqlAuthorizationResult["response"])
        XCTAssertFalse(dcqlAuthorizationResult["response"]!.isEmpty)
        XCTAssertTrue(dcqlAuthorizationResult["response"]!.contains("."))
    }

    func testGetAuthorizationResponseShouldReturnPlainErrorMapWhenErrorResponseGiven() throws {
        let handler = DirectPostJwtResponseModeHandler()
        let errorResponse = AuthorizationErrorResponse(error: "invalid_request", errorDescription: "something went wrong", state: "error-state")

        for specVersion: SpecVersion in [.draft23, .v1] {
            let result = try handler.getAuthorizationErrorResponse(authorizationRequest: getMockAuthorizationRequest(responseMode: .directPostJwt, specVersion: specVersion), authorizationResponse: errorResponse, walletNonce: "mock-nonce")
            XCTAssertEqual(result["error"], "invalid_request")
            XCTAssertEqual(result["error_description"], "something went wrong")
            XCTAssertEqual(result["state"], "error-state")
            XCTAssertNil(result["response"])
        }
    }

    func testGetAuthorizationResponseShouldReturnPlainErrorMapWhenErrorResponseGivenAndStateIsNil() throws {
        let handler = DirectPostJwtResponseModeHandler()
        let errorResponse = AuthorizationErrorResponse(error: "invalid_request", errorDescription: "something went wrong", state: nil)

        for specVersion: SpecVersion in [.draft23, .v1] {
            let result = try handler.getAuthorizationErrorResponse(authorizationRequest: getMockAuthorizationRequest(responseMode: .directPostJwt, specVersion: specVersion), authorizationResponse: errorResponse, walletNonce: "mock-nonce")
            XCTAssertEqual(result["error"], "invalid_request")
            XCTAssertEqual(result["error_description"], "something went wrong")
            XCTAssertNil(result["state"])
            XCTAssertNil(result["response"])
        }
    }

    func testThrowErrorWhenJwksContainsNoEncryptionKey() throws {
           let clientMetadataWithSigOnlyJwks: [String: Any] = [
               "encrypted_response_enc_values_supported": ["A256GCM"],
               "jwks": [
                   "keys": [[
                       "kty": "OKP",
                       "crv": "Ed25519",
                       "use": "sig",
                       "x": "5tvU4k_TGAfDAru3LfS53qbfHzghjc0kvPGAb2VUwWc",
                       "alg": "EdDSA",
                       "kid": "sig-key1"
                   ]]
               ],
               "vp_formats_supported": ["ldp_vc": ["proof_type_values": ["Ed25519Signature2020"]]]
           ]

           XCTAssertThrowsError(try directPostJwtResponseModeHandler.validate(
               clientMetadata: createInstance(clientMetadataWithSigOnlyJwks, as: ClientMetadata.self),
               walletMetadata: walletMetadata,
               shouldValidateWithWalletMetadata: false
           )) { error in
               assertOpenID4VPException(
                   error,
                   expectedMessage: "No encryption jwk found in client_metadata.jwks",
                   expectedCode: OpenID4VPErrorCodes.invalidRequest
               )
           }
       }

    // MARK: - getResponseEndpoint

    func testGetResponseEndpointThrowsWhenResponseUriIsNil() throws {
        let requestWithNoResponseUri = AuthorizationPresentationExchangeRequest(
            clientId: "client_id",
            responseType: "vp_token",
            responseMode: ResponseMode.directPostJwt.rawValue,
            responseUri: nil,
            redirectUri: nil,
            nonce: "nonce",
            walletNonce: nil,
            state: "state",
            presentationDefinition: mockPresentationDefinitionObject,
            clientMetadata: mockClientMetadataSpecVersionDraft23[.directPostJwt]
        )

        XCTAssertThrowsError(try directPostJwtResponseModeHandler.getResponseEndpoint(authorizationRequest: requestWithNoResponseUri)) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "response_uri is required in authorization request for response mode 'direct_post.jwt'",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
}
