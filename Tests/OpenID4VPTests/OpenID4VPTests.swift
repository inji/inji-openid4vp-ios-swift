import XCTest
@testable import OpenID4VP

class OpenID4VPTests: XCTestCase {
    var openID4VP: OpenID4VP!
    var mockNetworkManager: MockNetworkManager!
    var authorizationRequest: AuthorizationRequest!

    let jws = "wemcn3234ns"
    let signatureAlgoType = "JsonWebSignature2020"
    let publicKey = "-----BEGIN PUBLIC KEY-----\\nMIIBIjANBggvSPv73S\\nG5ToTt07NZPdKDrg9lSjetZup39oj12u0YoyRMlMhY0xYL6c8X1BexM7Wlp+c13o\\n1QIDAQAB\\n-----END PUBLIC KEY-----\\n"
    let domain = "https://example"
    let descriptorMap: [DescriptorMap] = [
        DescriptorMap(id: "bank_input", format: .ldp_vp, path: "$", pathNested: PathNested(id: "input_1", format: .ldp_vc, path: "$.verifiableCredential[0]")),
        DescriptorMap(id: "bank_input", format: .ldp_vp, path: "$", pathNested: PathNested(id: "input_1", format: .ldp_vc, path: "$.verifiableCredential[0]"))
    ]

    let decodedPresentationDefinition = "{\"id\":\"#2345333\",\"input_descriptors\":[{\"id\":\"banking_input_1\",\"name\":\"Bank Account Information\",\"purpose\":\"We can\",\"constraints\":{\"fields\":[{\"path\":[\"$.crede\"],\"purpose\":\"We can use for  # verification purpose # for anything\",\"filter\":{\"type\":\"string\",\"pattern\":\"^$\"}},{\"path\":[\"$.vc.credential\",\"$.vc.credentialSubject.account[*].route\",\"$.account[*].route\"],\"purpose\":\"We can use for verification purpose\",\"filter\":{\"type\":\"string\",\"pattern\":\"^\"}}]}}]}"

    let decodedClientMetadata =
        "{\"name\":\"dummyClient\"}"

    override func setUp() {
        super.setUp()
        mockNetworkManager = MockNetworkManager()
        openID4VP = OpenID4VP(traceabilityId: "AXESWSAW123", networkManager: mockNetworkManager)
        openID4VP.setResponseUri("https://mock-verifier.com")
        openID4VP.authorizationRequest = authorizationRequest
    }

    override func tearDown() {
        openID4VP = nil
        mockNetworkManager = nil
        super.tearDown()
    }
    
    func testWalletNonceIsDifferentForEveryAuthenticateVerifierCall() async {
        let openID4VP = OpenID4VP(traceabilityId: "trace-id")
        _ = try! await openID4VP.authenticateVerifier(urlEncodedAuthorizationRequest: testValidUrlEncodedVPRequestWithRedirectUri, trustedVerifierJSON: preRegisteredVerifiers, shouldValidateClient: true)
        let firstMirror = Mirror(reflecting: openID4VP as Any)
        let firstNonce = firstMirror.children.first(where: { $0.label == "walletNonce" })?.value as? String
        
        _ = try! await openID4VP.authenticateVerifier(urlEncodedAuthorizationRequest: testValidUrlEncodedVPRequestWithRedirectUri, trustedVerifierJSON: preRegisteredVerifiers, shouldValidateClient: true)
        let secondMirror = Mirror(reflecting: openID4VP as Any)
        let secondNonce = secondMirror.children.first(where: { $0.label == "walletNonce" })?.value as? String
        
        XCTAssertNotEqual(firstNonce, secondNonce, "Wallet nonce should be different for every authenticateVerifier call")
    }

    //client_id_scheme = redirect_uri
    func testAuthorizationRequestJsonStringConversion() async {
        do {
            let decoded = try await openID4VP.authenticateVerifier(urlEncodedAuthorizationRequest: testValidUrlEncodedVPRequestWithRedirectUri, trustedVerifierJSON: preRegisteredVerifiers, shouldValidateClient: true)
            let jsonData = try JSONEncoder().encode(decoded)
            let authorizationRequestJsonString = String(decoding: jsonData, as: UTF8.self)

            assertJsonString(expected: "{\"state\":\"+mRQe1d6pBoJqF6Ab28klg==\",\"response_type\":\"vp_token\",\"redirect_uri\":null,\"client_metadata\":{\"logo_uri\":\"https:\\/\\/mock-verifier.com\\/logo\",\"client_name\":\"Requester name\",\"authorization_encrypted_response_enc\":\"A256GCM\",\"vp_formats\":{\"ldp_vp\":{\"proof_type\":[\"Ed25519Signature2018\",\"Ed25519Signature2020\"]}},\"authorization_encrypted_response_alg\":\"ECDH-ES\",\"jwks\":{\"keys\":[{\"kty\":\"OKP\",\"use\":\"enc\",\"kid\":\"ed-key1\",\"x\":\"BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4\",\"alg\":\"ECDH-ES\",\"crv\":\"X25519\"}]}},\"presentation_definition\":{\"input_descriptors\":[{\"purpose\":\"To verify identity using Linked Data Proofs\",\"id\":\"input_1\",\"constraints\":{\"fields\":[{\"path\":[\"$.credentialSubject.email\"],\"filter\":{\"pattern\":\"@gmail.com\",\"type\":\"string\"}}]},\"format\":{\"ldp_vc\":{\"proof_type\":[\"Ed25519Signature2018\",\"RsaSignature2018\"]}},\"name\":\"Verifiable Credential\"}],\"id\":\"vp_presentation_definition\"},\"nonce\":\"VbRRB\\/LTxLiXmVNZuyMO8A==\",\"client_id\":\"redirect_uri:https:\\/\\/mock-verifier.com\",\"response_uri\":\"https:\\/\\/mock-verifier.com\",\"response_mode\":\"direct_post\"}", actual: authorizationRequestJsonString)
        } catch {
            XCTFail("Should not get error but got error - \(error)")
        }
    }

    // client_id_scheme = redirect_uri, response_mode = fragment
    func testInvalidResponseModeWithRedirectUriScheme() async {
        let result = await Task {
            try await openID4VP.authenticateVerifier(urlEncodedAuthorizationRequest: testVPRequestWithRedirectUriAndClientIdNotEqual, trustedVerifierJSON: preRegisteredVerifiers, shouldValidateClient: true)
        }.result

        switch result {
        case .failure(let error):
            assertOpenID4VPException(
                error,
                expectedMessage: "Given response_mode - fragment is not supported",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        case .success:
            XCTFail("Expected error for unsupported response_mode but got success")
        }
    }



    // client_id_scheme = pre-registered
    func testReturnDataForValidRequestWithResponseUri() async {
        let decoded: Any?

        do {
            decoded = try await openID4VP.authenticateVerifier(urlEncodedAuthorizationRequest: testValidUrlEncodedVPRequestWithResponseUri, trustedVerifierJSON: preRegisteredVerifiers, shouldValidateClient: true)
        } catch {
            decoded = nil
            XCTFail("Should not get error but got error - \(error)")
        }
        XCTAssertTrue(decoded is AuthorizationRequest, "decodedResponse should be an instance of AuthenticationResponse")
        XCTAssertTrue(decoded != nil, "decodedResponse should not be null")
    }

    //client_id_scheme = pre-registered, validation of client via shouldValidateClient

    func testAuthenticateVerifierWithShouldValidateClientFalse() async throws {
        await assertAsyncNoThrowsError(try await openID4VP.authenticateVerifier(
            urlEncodedAuthorizationRequest: testUrlEncodedAuthRequestOfUntrustedVerifier,
            trustedVerifierJSON: preRegisteredVerifiers,
            shouldValidateClient: false
        ), "should not throw even though the client ID isn't in the trusted list because shouldValidateClient is false")
    }

    func testAuthenticateVerifierWithShouldValidateClientTrue() async throws {
        await assertAsyncThrowsError(try await openID4VP.authenticateVerifier(
            urlEncodedAuthorizationRequest: testUrlEncodedAuthRequestOfUntrustedVerifier,
            trustedVerifierJSON: preRegisteredVerifiers,
            shouldValidateClient: true
        )) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Verifier is not trusted by the wallet",
                expectedCode: OpenID4VPErrorCodes.invalidClient
            )
        
        }
    }

    func testAuthenticateVerifierWithoutShouldValidateClientParam() async throws {
        await assertAsyncThrowsError(try await openID4VP.authenticateVerifier(
            urlEncodedAuthorizationRequest: testUrlEncodedAuthRequestOfUntrustedVerifier,
            trustedVerifierJSON: preRegisteredVerifiers
        )) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Verifier is not trusted by the wallet",
                expectedCode: OpenID4VPErrorCodes.invalidClient
            )
        }
    }

    // client_id_scheme = pre-registered draft 21
    func testReturnDataForValidRequestWithResponseUriDraft21() async {
        let decoded: Any?

        do {
            decoded = try await openID4VP.authenticateVerifier(urlEncodedAuthorizationRequest: testValidUrlEncodedVPRequestWithResponseUriDraft21, trustedVerifierJSON: preRegisteredVerifiers, shouldValidateClient: true)
        } catch {
            decoded = nil
            XCTFail("Should not get error but got error - \(error)")
        }
        XCTAssertTrue(decoded is AuthorizationRequest, "decodedResponse should be an instance of AuthenticationResponse")
        XCTAssertTrue(decoded != nil, "decodedResponse should not be null")
    }

    //client_id_scheme = pre_registered, ClientMetadata mandatory values are not present
    func testMissingClientMetadataRequiredFieldsInRequest() async {
        let result = await Task {
            try await openID4VP.authenticateVerifier(urlEncodedAuthorizationRequest: urlEncodedAuthorizationRequestWithInvalidClientMetadata, trustedVerifierJSON: preRegisteredVerifiers, shouldValidateClient: true)
        }.result

        switch result {
        case .failure(let error):
            assertOpenID4VPException(
                error,
                expectedMessage: "Missing Input: client_metadata->vp_formats param is required",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        case .success:
            XCTFail("Expected failure but got success")
        }
    }


    func testShouldConstructAuthorizationRequestSuccessfullyWhenPresentationDefinitionIsSentByReference() async {
        mockNetworkManager.setMockResponse(for: "https://mock-verifier.com/presentation-definition", responseBody: convertToJsonString(presentationDefinition))
        do {
            let authorizationRequest = try await openID4VP.authenticateVerifier(urlEncodedAuthorizationRequest: urlEncodedAuthRequestWithPresentationDefinitionUri, trustedVerifierJSON: preRegisteredVerifiers, shouldValidateClient: false)
            XCTAssertNotNil(authorizationRequest)
            XCTAssertEqual("mock-client", authorizationRequest.clientId)
        } catch {
            XCTFail("should not get error but got error \(error)")
        }
    }

    // client_id_scheme = did
    func testReturnDataForValidRequestWithDid() async {
        mockNetworkManager.setMockResponse(for: "https://mock-verifier.com/verifier/get-auth-request-obj",response: (validJwtResponse, httpUrlResponseForJWS))
        mockNetworkManager.setMockResponse(for: didDocumentUrl,responseBody: didResponse)

        let decodedAuthorizationRequest: Any?
        do {
            decodedAuthorizationRequest = try await openID4VP.authenticateVerifier(urlEncodedAuthorizationRequest: testValidSignedVPRequestWithDid, trustedVerifierJSON: preRegisteredVerifiers, shouldValidateClient: true)
        } catch {
            decodedAuthorizationRequest = nil
            XCTFail("Should not get error but got error - \(error)")
        }

        XCTAssertTrue(decodedAuthorizationRequest is AuthorizationRequest, "decodedResponse should be an instance of AuthenticationResponse")
        XCTAssertTrue(decodedAuthorizationRequest != nil, "decodedResponse should not be null")
    }

    // jwt -> client_id_scheme = did, Invalid did
    func testThrowErrorForInValidSignatureInRequest() async {
        mockNetworkManager.setMockResponse(
            for: "https://mock-verifier.com/verifier/get-auth-request-obj",
            response: (invalidJwtResponse, httpUrlResponseForJWS)
        )
        mockNetworkManager.setMockResponse(
            for: didDocumentUrl,
            responseBody: didResponse
        )

        let result = await Task {
            try await openID4VP.authenticateVerifier(urlEncodedAuthorizationRequest: testValidSignedVPRequestWithDid, trustedVerifierJSON: preRegisteredVerifiers, shouldValidateClient: true)
        }.result
        switch result {
        case .failure(let error):
            assertOpenID4VPException(
                error,
                expectedMessage: "JWS proof verification failed",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        case .success:
            XCTFail("Expected proof verification failure, but got success")
        }
    }


    // jwt -> client_id_scheme = did, Mismatching clientId's in QR data and Request Uri response
    func testThrowErrorIfClientIdIsMismatchingWithQrDataAndRequest() async {
               mockNetworkManager.setMockResponse(
                   for: "https://mock-verifier.com/verifier/get-auth-request-obj",
                   response: (validJwtResponse, httpUrlResponseForJWS)
               )
               mockNetworkManager.setMockResponse(for: didDocumentUrl, responseBody: didResponse)

        let result = await Task {
            try await openID4VP.authenticateVerifier(urlEncodedAuthorizationRequest: testInValidSignedVPRequestWithDidAndClientIdDifferent, trustedVerifierJSON: preRegisteredVerifiers, shouldValidateClient: true)
        }.result

        switch result {
        case .failure(let error):
            assertOpenID4VPException(
                error,
                expectedMessage: "Client Id is mismatching in QR data and Request Uri response",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        case .success:
            XCTFail("Expected client_id mismatch error but got success")
        }
    }


    // jwt -> client_id_scheme = did, Kid is empty in the JWT header
    func testThrowErrorIfKidExtractionFailedFromJws() async {
        mockNetworkManager.setMockResponse(for: "https://mock-verifier.com/verifier/get-auth-request-obj",response: (invalidJwtResponseWithoutKid, httpUrlResponseForJWS))
        mockNetworkManager.setMockResponse(for: didDocumentUrl,responseBody: didResponse)

        let result = await Task {
            try await openID4VP.authenticateVerifier(urlEncodedAuthorizationRequest: testValidSignedVPRequestWithDid, trustedVerifierJSON: preRegisteredVerifiers, shouldValidateClient: true)
        }.result

        switch result {
        case .failure(let error):
            assertOpenID4VPException(
                error,
                expectedMessage: "Kid extraction from did document failed",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        case .success:
            XCTFail("Expected OpenID4VPException but got success response")
        }
    }


    //client_id_scheme = redirect_uri, Client id validation is false
    func testReturnDataForValidRequestWhenClientValidationIsFalse() async {
        let decoded: Any?

        do {
            decoded = try await openID4VP.authenticateVerifier(urlEncodedAuthorizationRequest: testValidUrlEncodedVPRequestWithRedirectUri, trustedVerifierJSON: preRegisteredVerifiers, shouldValidateClient: false)
        } catch {
            decoded = nil
            XCTFail("should not get error but got error \(error)")
        }
        XCTAssertTrue(decoded is AuthorizationRequest, "decodedResponse should be an instance of AuthenticationResponse")
        XCTAssertTrue(decoded != nil, "decodedResponse should not be null")
    }

    func testMissingPresentationDefinitionFields() async {
        let result = await Task {
            try await openID4VP.authenticateVerifier(urlEncodedAuthorizationRequest: testInvalidPresentationDefinitionVPRequest, trustedVerifierJSON: preRegisteredVerifiers, shouldValidateClient: true)
        }.result

        switch result {
        case .failure(let error):
            assertOpenID4VPException(
                error,
                expectedMessage: "Missing Input: presentation_definition->id param is required",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        case .success:
            XCTFail("Expected OpenID4VPException but got success response")
        }
    }


    // Construct and return VP token for signing
    func testShareVerifiablePresentation() async {
        var received: [FormatType: UnsignedVPToken]? = nil

        do {
            _ = try await openID4VP.authenticateVerifier(
                urlEncodedAuthorizationRequest: mockUrlEncodedVPRequestWithDirectPostJwt,
                trustedVerifierJSON: preRegisteredVerifiers,
                shouldValidateClient: true
            )

            let mockCredentials: [String: [FormatType: [AnyCodable]]] = [
                "input_1": [
                    .ldp_vc: [AnyCodable(ldpVC())]
                ]
            ]

            received = try await openID4VP.constructUnsignedVPToken(
                verifiableCredentials: mockCredentials,
                holderId: "did:example:123",
                signatureSuite: "JsonWebSignature2020"
            )
        } catch {
            XCTFail("Unexpected error: \(error)")
        }

        XCTAssertNotNil(received, "The response should not be nil for valid credentials map")
    }



    // NetworkManager Tests Success
    func testSendVPSuccess() async throws {
        mockNetworkManager.setMockResponse(
            for: "https://mock-verifier.com",
            responseBody: "Success: Request completed successfully."
        )

        _ = try await openID4VP.authenticateVerifier(
            urlEncodedAuthorizationRequest: mockUrlEncodedVPRequestWithDirectPostJwt,
            trustedVerifierJSON: preRegisteredVerifiers,
            shouldValidateClient: true
        )

        _ = try await openID4VP.constructUnsignedVPToken(
            verifiableCredentials: verifiableCredentialsList,
            holderId: "did:example:123",
            signatureSuite: "JsonWebSignature2020"
        )

        let vpTokenSigningResults: [FormatType: VPTokenSigningResult] = [
            .ldp_vc: LdpVPTokenSigningResult(
                jws: jws,
                proofValue: "test", signatureAlgorithm: signatureAlgoType
            )
        ]

        let response = try await openID4VP.shareVerifiablePresentation(vpTokenSigningResults: vpTokenSigningResults)

        XCTAssertEqual(response, "Success: Request completed successfully.")
    }


    // NetworkManager Tests Failure
    func testSendVPFailure() async {
        let errorMessage = "Network Request failed with error response: response"
        mockNetworkManager.setMockResponse(for: "https://mock-verifier.com", error: NetworkRequestException.networkRequestFailed(message: errorMessage))
        let vpTokenSigningResults = [FormatType.ldp_vc: LdpVPTokenSigningResult(jws: jws, proofValue:"test",signatureAlgorithm: signatureAlgoType)]

        do {
            authorizationRequest = try await openID4VP.authenticateVerifier(urlEncodedAuthorizationRequest: mockUrlEncodedVPRequestWithDirectPostJwt, trustedVerifierJSON: preRegisteredVerifiers, shouldValidateClient: true)
            _ = try! await openID4VP.constructUnsignedVPToken(verifiableCredentials: verifiableCredentialsList, holderId: "wallet-holder-id", signatureSuite: "JsonWebSignature2020")

            let _ = try await openID4VP.shareVerifiablePresentation(vpTokenSigningResults: vpTokenSigningResults)
        } catch let error as NetworkRequestException {
            switch error {
            case .networkRequestFailed(let message):
                XCTAssertEqual(message, errorMessage, "Unexpected error message: \(message)")
            default:
                XCTFail("Expected NetworkRequestException.networkRequestFailed but got \(error)")
            }
        } catch {
            XCTFail("Expected NetworkRequestException.networkRequestFailed but got \(error)")
        }
    }

    func testShareVPSuccessWhenResponseModeIsDirectPostJwt() async throws {
        mockNetworkManager.setMockResponse(for: "https://mock-verifier.com", responseBody: "Success: Request completed successfully.")

        authorizationRequest = try await openID4VP.authenticateVerifier(urlEncodedAuthorizationRequest: mockUrlEncodedVPRequestWithDirectPostJwt, trustedVerifierJSON: preRegisteredVerifiers, shouldValidateClient: true)
        _ = try! await openID4VP.constructUnsignedVPToken(verifiableCredentials: verifiableCredentialsList, holderId: "wallet-holder-id", signatureSuite: "JsonWebSignature2020")
        let vpTokenSigningResults = [FormatType.ldp_vc: LdpVPTokenSigningResult(jws:"test-jws-valid",proofValue: "test", signatureAlgorithm: "JsonWebSignature2020")]

        let response = try await openID4VP.shareVerifiablePresentation(vpTokenSigningResults: vpTokenSigningResults)

        XCTAssertEqual(response, "Success: Request completed successfully.")
    }

    func testSendErrorToVerifier_withoutState() async {
        openID4VP.setResponseUri("https://mock-verifier.com")

        
        let expectedError = InvalidData(message: "Some Error Message",className:  "test")

        await openID4VP.sendErrorToVerifier(error: expectedError)

        guard let recorded = mockNetworkManager.recordedRequests["https://mock-verifier.com"] else {
            return XCTFail("No request recorded")
        }

        let requestBody = recorded.requestBody ?? [:]

        XCTAssertEqual(requestBody["error"], "invalid_request")
        XCTAssertEqual(requestBody["error_description"], "Some Error Message")
        XCTAssertNil(requestBody["state"], "State should not be present in the request body")
    }
    
    
    func testSendErrorToVerifier_withState() async throws {
        openID4VP.setResponseUri("https://mock-verifier.com")
        let authorizationRequest = try await openID4VP.authenticateVerifier(
            urlEncodedAuthorizationRequest: mockUrlEncodedVPRequestWithDirectPostJwt,
            trustedVerifierJSON: preRegisteredVerifiers,
            shouldValidateClient: true
        )
        openID4VP.authorizationRequest = authorizationRequest

        
        let expectedError = InvalidData(message: "Some Error Message",className:  "test")
        
        await openID4VP.sendErrorToVerifier(error: expectedError)
        
        guard let recorded = mockNetworkManager.recordedRequests["https://mock-verifier.com"] else {
            return XCTFail("No request recorded")
        }

        let requestBody = recorded.requestBody ?? [:]

        XCTAssertEqual(requestBody["error"], "invalid_request")
        XCTAssertEqual(requestBody["error_description"], "Some Error Message")
        XCTAssertNotNil(requestBody["state"], "Expected 'state' to be present in the request body")
        XCTAssertEqual(requestBody["state"], "+mRQe1d6pBoJqF6Ab28klg==")
    }
    



    
    

}
