@testable import OpenID4VP
import XCTest

final class AuthorizationResponseHandlerTests: XCTestCase {
    let mockNetworkManager = MockNetworkManager()
    let state = "state"
    let responseUri = "https://mock-verifier.com"
    let holderId = "wallet-holder-id"
    let walletNonce = "mock-nonce"
    let signatureSuite = SignatureSuite.ed25519Signature2020.rawValue
    let walletMetadata = WalletMetadata()
    
    // MARK: - OVP Spec Version Draft 23
    // MARK: Credential format = ldp_vc
    
    override func setUp() {
        JsonLd.setCanonicalizer { _ in "Y2Fub25pY2FsaXplZA" }
    }
    
    func testConstructUnsignedVPTokenThrowsErrorIncaseOfInvalidHoldersIdWithLdpVCAvailable() async throws {
        let invalidHolderIdTestCases = ["", " ", "  ", "null", nil]
        let verifiableCredentials: [String: [FormatType: [AnyCodable]]] = [
            "input_descriptor1": [.ldp_vc: [AnyCodable(ldpVC())]],
        ]
        
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager, walletMetadata: walletMetadata)
        let authorizationRequest = getMockAuthorizationRequest(specVersion: .draft23)
        for holderId in invalidHolderIdTestCases {
            await XCTAssertAsyncThrowsError(try await handler.constructUnsignedVPToken(
                credentialsMap: verifiableCredentials,
                authorizationRequest: authorizationRequest,
                responseUri: responseUri,
                holderId: holderId,
                signatureSuite: "JsonWebSignature2020",
                walletNonce: "mock-nonce"
            )) { error in
                assertOpenID4VPException(error,
                                         expectedMessage: "Holder ID cannot be null or empty for LDP VC format",
                                         expectedCode: OpenID4VPErrorCodes.invalidRequest
                )
            }
        }
    }
    
    func testConstructUnsignedVPTokenThrowsErrorIncaseOfInvalidSignatureSuitesWithLdpVCAvailable() async throws {
        let invalidsignatureSuiteTestCases = ["", " ", "  ", "null", nil]
        let verifiableCredentials: [String: [FormatType: [AnyCodable]]] = [
            "input_descriptor1": [.ldp_vc: [AnyCodable(ldpVC())]],
            "org.iso.18013.5.1.mDL": [.mso_mdoc: [AnyCodable(sampleMdoc)]],
        ]
        
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager, walletMetadata: walletMetadata)
        let authorizationRequest = getMockAuthorizationRequest(specVersion: .draft23)
        for invalidSignatureSuite in invalidsignatureSuiteTestCases {
            await XCTAssertAsyncThrowsError(try await handler.constructUnsignedVPToken(
                credentialsMap: verifiableCredentials,
                authorizationRequest: authorizationRequest,
                responseUri: responseUri,
                holderId: holderId,
                signatureSuite: invalidSignatureSuite,
                walletNonce: walletNonce
            )) { error in
                assertOpenID4VPException(error,
                                         expectedMessage: "Signature Suite cannot be null or empty for LDP VC format",
                                         expectedCode: OpenID4VPErrorCodes.invalidRequest
                )
            }
        }
    }
    
    func testConstructAndSendAuthorizationResponseToVerifierHasTheAuthorizationResponseAsExpected() async throws {
        let verifiableCredentials: [String: [FormatType: [AnyCodable]]] = [
            "input_descriptor1": [.ldp_vc: [AnyCodable(ldpVC()), AnyCodable(ldpVC(credentialType: "UniversityCredential"))]],
            "input_descriptor2": [.ldp_vc: [AnyCodable(ldpVC())]],
        ]
        
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager, walletMetadata: walletMetadata)
        let authorizationRequest = getMockAuthorizationRequest(specVersion: .draft23)
        
        _ = try await handler.constructUnsignedVPToken(
            credentialsMap: verifiableCredentials,
            authorizationRequest: authorizationRequest,
            responseUri: responseUri,
            holderId: holderId,
            signatureSuite: signatureSuite,
            walletNonce: walletNonce
        )
        
        let vpTokenSigningResults: [VPTokenSigningResult] = [
            VPTokenSigningResult(signedData: Data("testJWS".utf8)),
        ]
        
        mockNetworkManager.setMockResponse(for: responseUri, responseBody: "sending is success in AuthorizationResponseTests")
        
        let result = try await handler.constructAndSendAuthorizationResponseToVerifier(
            authorizationRequest: authorizationRequest,
            vpTokenSigningResults: vpTokenSigningResults,
            responseUri: responseUri
        )
        
        XCTAssertEqual(result.body(), "sending is success in AuthorizationResponseTests")
        let recordedRequest = mockNetworkManager.recordedRequests[responseUri]!
        XCTAssertEqual(recordedRequest.requestBody?["state"] as? String, state)
        XCTAssertNotNil(recordedRequest.requestBody?["presentation_submission"])
        XCTAssertEqual(recordedRequest.requestBody?.keys.count, 3)
    }
    
    func testConstructAndSendAuthorizationResponseToVerifierSendingAuthorizationResponseWithMultipleVPFormatsSuccessfully() async throws {
        let verifiableCredentials: [String: [FormatType: [AnyCodable]]] = [
            "input_descriptor1": [.ldp_vc: [AnyCodable(ldpVC())]],
            "org.iso.18013.5.1.mDL": [.mso_mdoc: [AnyCodable(sampleMdoc)]],
        ]
        
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager, walletMetadata: walletMetadata)
        let mockAuthorizationRequest = getMockAuthorizationRequest(responseMode: .directPostJwt, specVersion: .draft23)
        
        mockNetworkManager.setMockResponse(for: responseUri, responseBody: "sending is success in AuthorizationResponseTests")
        
        let vpTokenSigningResults: [VPTokenSigningResult] = [
            VPTokenSigningResult(signedData: Data("testJWS".utf8)),
            VPTokenSigningResult(signedData: Data("aGVsbG8=".utf8)),
        ]
        
        _ = try await handler.constructUnsignedVPToken(
            credentialsMap: verifiableCredentials,
            authorizationRequest: mockAuthorizationRequest,
            responseUri: responseUri,
            holderId: holderId,
            signatureSuite: signatureSuite,
            walletNonce: walletNonce
        )
        
        let result = try await handler.constructAndSendAuthorizationResponseToVerifier(
            authorizationRequest: mockAuthorizationRequest,
            vpTokenSigningResults: vpTokenSigningResults,
            responseUri: responseUri
        )
        
        XCTAssertEqual(result.body(), "sending is success in AuthorizationResponseTests")
        let recordedRequest = mockNetworkManager.recordedRequests[responseUri]!
        XCTAssertEqual(recordedRequest.requestBody?.keys.count, 1)
        XCTAssertNotNil(recordedRequest.requestBody?["response"])
    }
    
    // Common: spec version agnostic
    func testConstructAndSendAuthorizationResponseToVerifierThrowErrorWhenResponseTypeIsNotSupportedByLibrary() async {
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager, walletMetadata: walletMetadata)
        let authorizationRequest = getMockAuthorizationRequest(responseType: "fragment")
        
        do {
            _ = try await handler.constructAndSendAuthorizationResponseToVerifier(
                authorizationRequest: authorizationRequest,
                vpTokenSigningResults: [],
                responseUri: "https://client.example.org/cb"
            )
            XCTFail("Expected error not thrown")
        } catch {
            assertOpenID4VPException(error,
                                     expectedMessage: "Provided response_type - fragment is not supported",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testConstructAndSendAuthorizationResponseToVerifierToSharePresentationSubmissionOfLdpVCInExpectedFormat() async throws {
        // Arrange
        let verifiableCredentials: [String: [FormatType: [AnyCodable]]] = [
            "input_descriptor1": [.ldp_vc: [AnyCodable(ldpVC())]],
            "org.iso.18013.5.1.mDL": [.mso_mdoc: [AnyCodable(sampleMdoc)]],
        ]
        
        let expectedPresentationSubmissionTemplateWithMdocFirst = """
        {
            "definition_id": "vp_presentation_definition",
            "descriptor_map": [
                {
                    "id": "org.iso.18013.5.1.mDL",
                    "format": "mso_mdoc",
                    "path": "$[0]"
                },
                {
                    "format": "ldp_vp",
                    "id": "input_descriptor1",
                    "path": "$[1]",
                    "path_nested": {
                        "id": "input_descriptor1",
                        "path": "$.verifiableCredential[0]",
                        "format": "ldp_vc"
                    }
                }
            ],
            "id": "<DYNAMIC_ID>"
        }
        """
        
        let expectedPresentationSubmissionTemplateWithLdpFirst = """
        {
            "definition_id": "vp_presentation_definition",
            "descriptor_map": [
                {
                    "format": "ldp_vp",
                    "id": "input_descriptor1",
                    "path": "$[0]",
                    "path_nested": {
                        "id": "input_descriptor1",
                        "path": "$.verifiableCredential[0]",
                        "format": "ldp_vc"
                    }
                },        
                {
                    "id": "org.iso.18013.5.1.mDL",
                    "format": "mso_mdoc",
                    "path": "$[1]"
                }
            ],
            "id": "<DYNAMIC_ID>"
        }
        """
        
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager, walletMetadata: walletMetadata)
        
        _ = try await handler.constructUnsignedVPToken(
            credentialsMap: verifiableCredentials,
            authorizationRequest: mockAuthorizationRequestObjectWithDirectPostResponseMode,
            responseUri: responseUri,
            holderId: holderId,
            signatureSuite: signatureSuite,
            walletNonce: walletNonce
        )
        
        mockNetworkManager.setMockResponse(
            for: responseUri,
            responseBody: "sending is success in AuthorizationResponseTests"
        )
        
        let mockVPTokenSigningResults: [VPTokenSigningResult] = [
            VPTokenSigningResult(signedData: Data("testJWS".utf8)),
            VPTokenSigningResult(signedData: Data("sign=".utf8)),
        ]
        
        _ = try await handler.constructAndSendAuthorizationResponseToVerifier(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .draft23),
            vpTokenSigningResults: mockVPTokenSigningResults,
            responseUri: responseUri
        )
        
        // Extract actual response
        guard let recordedRequest = mockNetworkManager.recordedRequests[responseUri],
              let actualBody = recordedRequest.requestBody?["presentation_submission"] else {
            XCTFail("No recorded request found for \(responseUri)")
            return
        }
        
        // Get actual ID
        let actualJson = decodeQueryValue(actualBody)
        guard let actualData = actualJson.data(using: .utf8),
              let actualDict = try JSONSerialization.jsonObject(with: actualData) as? [String: Any],
              let actualId = actualDict["id"] as? String else {
            XCTFail("Could not parse or extract ID from actual body")
            return
        }
        
        let vpToken = recordedRequest.requestBody?["vp_token"] as? String
        // This check is made to avoid flakiness in tests as the order of credentials in vp_token is not guaranteed due to input mtaching credentials being a map
        let expectedPresentationSubmissionTemplate: String = vpToken?.starts(with: "[\"o") ?? false ? expectedPresentationSubmissionTemplateWithMdocFirst : expectedPresentationSubmissionTemplateWithLdpFirst
        
        // Replace the dynamic ID in expected string
        let expectedJsonString = expectedPresentationSubmissionTemplate.replacingOccurrences(of: "<DYNAMIC_ID>", with: actualId)
        
        assertJsonString(
            expected: expectedJsonString,
            actual: actualJson,
            strict: false
        )
    }
    
    // MARK: Credential format = SD-JWT, common spec version agnostic tests
    
    func testCreationOfUnsignedVPTokenWithSdJwtFormatSuccess() async throws {
        let verifiableCredentials: [String: [FormatType: [AnyCodable]]] = [
            "input_descriptor2": [.vc_sd_jwt: [AnyCodable(sampeVcSdJwtWithHolderBinding)]],
        ]
        
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager, walletMetadata: walletMetadata)
        let authorizationRequest = getMockAuthorizationRequest()
        
        await XCTAssertNoThrowAndVerifyAsync(try await handler.constructUnsignedVPToken(
            credentialsMap: verifiableCredentials,
            authorizationRequest: authorizationRequest,
            responseUri: responseUri,
            holderId: holderId,
            signatureSuite: signatureSuite,
            walletNonce: walletNonce
        )) { result in
            XCTAssertTrue(result.count == 1)
        }
    }
    
    func testSharingOfSdJwtWithHolderBindingSuccess() async throws {
        mockNetworkManager.setMockResponse(for: responseUri, responseBody: "sending is success in AuthorizationResponseTests")
        let verifiableCredentials: [String: [FormatType: [AnyCodable]]] = [
            "input_descriptor2": [.vc_sd_jwt: [AnyCodable(sampeVcSdJwtWithHolderBinding)]],
        ]
        
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager, walletMetadata: walletMetadata)
        let authorizationRequest = getMockAuthorizationRequest(specVersion: .draft23)
        _ = try await handler.constructUnsignedVPToken(
            credentialsMap: verifiableCredentials,
            authorizationRequest: authorizationRequest,
            responseUri: responseUri,
            holderId: holderId,
            signatureSuite: signatureSuite,
            walletNonce: walletNonce
        )
        
        let result = try await handler.constructAndSendAuthorizationResponseToVerifier(authorizationRequest: authorizationRequest, vpTokenSigningResults: [VPTokenSigningResult(signedData: Data("ayuht".utf8))], responseUri: responseUri)
        
        XCTAssertEqual(result.body(), "sending is success in AuthorizationResponseTests")
        let recordedRequest = mockNetworkManager.recordedRequests[responseUri]!
        XCTAssertEqual(recordedRequest.requestBody?["state"] as? String, state)
        let presentationSubmission: String? = recordedRequest.requestBody?["presentation_submission"]
        XCTAssertNotNil(presentationSubmission)
        XCTAssertEqual(recordedRequest.requestBody?.keys.count, 3)
    }

    func testSharingOfSdJwtWithoutHolderBindingPreservesCredential() async throws {
        let verifiableCredentials: [String: [FormatType: [AnyCodable]]] = [
            "input_descriptor2": [.vc_sd_jwt: [AnyCodable(sampleVcSdJwtWithNoHolderBinding)]],
        ]

        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager, walletMetadata: walletMetadata)
        let authorizationRequest = getMockAuthorizationRequest(specVersion: .draft23)

        let unsignedVPTokens = try await handler.constructUnsignedVPToken(
            credentialsMap: verifiableCredentials,
            authorizationRequest: authorizationRequest,
            responseUri: responseUri,
            holderId: holderId,
            signatureSuite: signatureSuite,
            walletNonce: walletNonce
        )

        XCTAssertTrue(unsignedVPTokens.isEmpty)

        let authorizationResponse = try handler.constructVPResponse(
            signingResults: [],
            authorizationRequest: authorizationRequest
        )

        let encodedVpToken = try XCTUnwrap(authorizationResponse["vp_token"])
        let vpToken = try JSONDecoder().decode(String.self, from: Data(encodedVpToken.utf8))
        XCTAssertEqual(vpToken, sampleVcSdJwtWithNoHolderBinding)
    }
    
    // MARK: Credential format = All supported credential formats combination
    
    func testConstructUnsignedVPTokenSuccess() async throws {
        let verifiableCredentials: [String: [FormatType: [AnyCodable]]] = [
            "input_descriptor1": [.ldp_vc: [AnyCodable(ldpVC())]],
            "org.iso.18013.5.1.mDL": [.mso_mdoc: [AnyCodable(sampleMdoc)]],
            "input_descriptor2": [.vc_sd_jwt: [AnyCodable(sampeVcSdJwtWithHolderBinding)]],
            "input_descriptor3": [.dc_sd_jwt: [AnyCodable(sampeVcSdJwtWithHolderBinding)]],
        ]
        
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager, walletMetadata: walletMetadata)
        let authorizationRequest = getMockAuthorizationRequest(specVersion: .draft23)
        
        await XCTAssertNoThrowAndVerifyAsync(try await handler.constructUnsignedVPToken(
            credentialsMap: verifiableCredentials,
            authorizationRequest: authorizationRequest,
            responseUri: responseUri,
            holderId: holderId,
            signatureSuite: signatureSuite,
            walletNonce: walletNonce
        )) { result in
            XCTAssertTrue(result.count == 4)
        }
    }
    
    func testShareAuthorizationResponseSuccess() async throws {
        mockNetworkManager.clearResponses()
        mockNetworkManager.setMockResponse(for: responseUri, responseBody: "sending is success in AuthorizationResponseTests")
        let verifiableCredentials: [String: [FormatType: [AnyCodable]]] = [
            "input_descriptor1": [.ldp_vc: [AnyCodable(ldpVC())]],
            "org.iso.18013.5.1.mDL": [.mso_mdoc: [AnyCodable(sampleMdoc)]],
            "input_descriptor2": [.vc_sd_jwt: [AnyCodable(sampeVcSdJwtWithHolderBinding)]],
            "input_descriptor3": [.dc_sd_jwt: [AnyCodable(sampeVcSdJwtWithHolderBinding)]],
        ]
        
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager, walletMetadata: walletMetadata)
        let authorizationRequest = getMockAuthorizationRequest(specVersion: .draft23)
        let unsignedVPTokens = try await handler.constructUnsignedVPToken(
            credentialsMap: verifiableCredentials,
            authorizationRequest: authorizationRequest,
            responseUri: responseUri,
            holderId: holderId,
            signatureSuite: signatureSuite,
            walletNonce: walletNonce
        )
        print("unsignedVPTokens: \(unsignedVPTokens)")
        
        let vpTokenSigningResults: [VPTokenSigningResult] = [
            VPTokenSigningResult(signedData: Data("ayuht".utf8)),
            VPTokenSigningResult(signedData: Data("testJWS".utf8)),
            VPTokenSigningResult(signedData: Data("aGVsbG8=".utf8)),
            VPTokenSigningResult(signedData: Data("ayuht".utf8)),
        ]
        
        _ = try await handler.constructAndSendAuthorizationResponseToVerifier(
            authorizationRequest: authorizationRequest,
            vpTokenSigningResults: vpTokenSigningResults,
            responseUri: responseUri
        )
        
        let recordedRequest = (mockNetworkManager.recordedRequests[responseUri]!).requestBody
        XCTAssertEqual(recordedRequest?["state"] as? String, state)
        XCTAssertNotNil(recordedRequest?["presentation_submission"])
    }
    
    func testThrowExceptionWhenVPTokenSigningResultMissingForAFormat() async throws {
        mockNetworkManager.clearResponses()
        mockNetworkManager.setMockResponse(for: responseUri, responseBody: "sending is success in AuthorizationResponseTests")
        let verifiableCredentials: [String: [FormatType: [AnyCodable]]] = [
            "input_descriptor1": [.ldp_vc: [AnyCodable(ldpVC())]],
            "org.iso.18013.5.1.mDL": [.mso_mdoc: [AnyCodable(sampleMdoc)]],
            "input_descriptor2": [.vc_sd_jwt: [AnyCodable(sampeVcSdJwtWithHolderBinding)]],
            "input_descriptor3": [.dc_sd_jwt: [AnyCodable(sampeVcSdJwtWithHolderBinding)]],
        ]
        
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager, walletMetadata: walletMetadata)
        let authorizationRequest = getMockAuthorizationRequest(specVersion: .draft23)
        _ = try await handler.constructUnsignedVPToken(
            credentialsMap: verifiableCredentials,
            authorizationRequest: authorizationRequest,
            responseUri: responseUri,
            holderId: holderId,
            signatureSuite: signatureSuite,
            walletNonce: walletNonce
        )

        let vpTokenSigningResults: [VPTokenSigningResult] = [ // simulate missing signed data
            VPTokenSigningResult(signedData: Data("testJWS".utf8)),
            VPTokenSigningResult(signedData: Data("aGVsbG8=".utf8)),
            VPTokenSigningResult(signedData: Data("ayuht".utf8)),
        ]
        
        do {
            _ = try await handler.constructAndSendAuthorizationResponseToVerifier(
                authorizationRequest: authorizationRequest,
                vpTokenSigningResults: vpTokenSigningResults,
                responseUri: "https://client.example.org/cb"
            )
            XCTFail("Expected error not thrown")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("Missing signing result"))
            XCTAssertEqual(OpenID4VPErrorCodes.invalidRequest, (error as? OpenID4VPException)?.errorCode)
        }
    }
    
    func testConstructAuthorizationErrorResponseMapsErrorCorrectly() {
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager, walletMetadata: walletMetadata)
        let authorizationRequest = getMockAuthorizationRequest(specVersion: .draft23)
        let error = InvalidData(message: "Invalid input data", className: "Test")
        
        
        let response = handler.constructAuthorizationErrorResponse(
            authorizationRequest: authorizationRequest,
            exception: error,
            walletNonce: "wallet-nonce"
        )
        
        XCTAssertEqual(response["error"] as? String, "invalid_request")
        XCTAssertEqual(response["error_description"] as? String, "Invalid input data")
        XCTAssertEqual(response["state"] as? String, state)
    }
    
    
    func testConstructAuthorizationResponseSuccess() async throws {
        let verifiableCredentials: [String: [FormatType: [AnyCodable]]] = [
            "input_descriptor1": [.ldp_vc: [AnyCodable(ldpVC())]],
        ]
        
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager, walletMetadata: walletMetadata)
        let authorizationRequest = getMockAuthorizationRequest(responseMode: .directPost, specVersion: .draft23)
        
        _ = try await handler.constructUnsignedVPToken(
            credentialsMap: verifiableCredentials,
            authorizationRequest: authorizationRequest,
            responseUri: responseUri,
            holderId: holderId,
            signatureSuite: signatureSuite,
            walletNonce: walletNonce
        )
        
        let vpTokenSigningResults: [VPTokenSigningResult] = [
            VPTokenSigningResult(signedData: Data("testJWS".utf8)),
        ]
        
        let authorizationResponse = try handler.constructVPResponse(
            signingResults: vpTokenSigningResults, authorizationRequest: authorizationRequest
        )
        
        XCTAssertNotNil(authorizationResponse["vp_token"])
        XCTAssertNotNil(authorizationResponse["presentation_submission"])
        XCTAssertEqual(authorizationResponse["state"], state)
    }
    
    func testConstructAuthorizationResponseThrowsErrorForUnsupportedResponseType() {
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager, walletMetadata: walletMetadata)
        let authorizationRequest = getMockAuthorizationRequest(responseType: "fragment", specVersion: .draft23)
        
        XCTAssertThrowsError(
            try handler.constructVPResponse(
                signingResults: [], authorizationRequest: authorizationRequest
            )
        ) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Provided response_type - fragment is not supported",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testConstructAuthorizationErrorResponseWithOpenIDException() {
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager, walletMetadata: walletMetadata)
        let authorizationRequest = getMockAuthorizationRequest(specVersion: .draft23)
        
        let error = InvalidData(
            message: "Invalid input data",
            className: "TestClass"
        )
        
        let response = handler.constructAuthorizationErrorResponse(
            authorizationRequest: authorizationRequest,
            exception: error,
            walletNonce: "wallet-nonce"
        )
        
        XCTAssertEqual(response["error"] as? String, "invalid_request")
        XCTAssertEqual(response["error_description"] as? String, "Invalid input data")
        XCTAssertEqual(response["state"] as? String, state)
    }
    
    func testConstructAuthorizationErrorResponseWithGenericError() {
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager, walletMetadata: walletMetadata)
        let authorizationRequest = getMockAuthorizationRequest(specVersion: .draft23)
        
        let error = NSError(domain: "test", code: 500)
        
        let response = handler.constructAuthorizationErrorResponse(
            authorizationRequest: authorizationRequest,
            exception: error,
            walletNonce: "wallet-nonce"
        )
        
        XCTAssertEqual(response["error"] as? String, "invalid_request")
        XCTAssertNotNil(response["error_description"])
        XCTAssertEqual(response["state"] as? String, state)
    }
    
    // common spec version agnostic tests
    func testConstructAuthorizationErrorResponseReturnMinimalErrorResponseIfConstructionOfErrorFails() {
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager, walletMetadata: walletMetadata)
        let authorizationRequest = getMockAuthorizationRequest(responseModeValue: "fragment" )
        
        let error = NSError(domain: "test", code: 500)
        
        let response = handler.constructAuthorizationErrorResponse(
            authorizationRequest: authorizationRequest,
            exception: error,
            walletNonce: "wallet-nonce"
        )
        
        XCTAssertEqual(response["error"] as? String, "invalid_request")
        XCTAssertNotNil(response["error_description"])
        XCTAssertTrue((response["error_description"] as? String)?.starts(with: "Failed to construct error response:") == true)
    }
    
    // MARK: - OVP Spec Version 1
    // Credential format = ldp_vc

    func testV1ConstructUnsignedVPTokenThrowsErrorForInvalidHolderIdWithLdpVC() async throws {
        let invalidHolderIdTestCases: [String?] = ["", " ", "  ", "null", nil]
        let verifiableCredentials: [String: [FormatType: [AnyCodable]]] = [
            "input_descriptor1": [.ldp_vc: [AnyCodable(ldpVC())]],
        ]

        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager, walletMetadata: walletMetadata)
        let authorizationRequest = getMockAuthorizationRequest(specVersion: .v1)
        for holderId in invalidHolderIdTestCases {
            await XCTAssertAsyncThrowsError(try await handler.constructUnsignedVPToken(
                credentialsMap: verifiableCredentials,
                authorizationRequest: authorizationRequest,
                responseUri: responseUri,
                holderId: holderId,
                signatureSuite: "JsonWebSignature2020",
                walletNonce: walletNonce
            )) { error in
                assertOpenID4VPException(error,
                    expectedMessage: "Holder ID cannot be null or empty for LDP VC format",
                    expectedCode: OpenID4VPErrorCodes.invalidRequest)
            }
        }
    }

    func testV1ConstructUnsignedVPTokenThrowsErrorForInvalidSignatureSuiteWithLdpVC() async throws {
        let invalidSignatureSuites: [String?] = ["", " ", "  ", "null", nil]
        let verifiableCredentials: [String: [FormatType: [AnyCodable]]] = [
            "input_descriptor1": [.ldp_vc: [AnyCodable(ldpVC())]],
            "org.iso.18013.5.1.mDL": [.mso_mdoc: [AnyCodable(sampleMdoc)]],
        ]

        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager, walletMetadata: walletMetadata)
        let authorizationRequest = getMockAuthorizationRequest(specVersion: .v1)
        for invalidSignatureSuite in invalidSignatureSuites {
            await XCTAssertAsyncThrowsError(try await handler.constructUnsignedVPToken(
                credentialsMap: verifiableCredentials,
                authorizationRequest: authorizationRequest,
                responseUri: responseUri,
                holderId: holderId,
                signatureSuite: invalidSignatureSuite,
                walletNonce: walletNonce
            )) { error in
                assertOpenID4VPException(error,
                    expectedMessage: "Signature Suite cannot be null or empty for LDP VC format",
                    expectedCode: OpenID4VPErrorCodes.invalidRequest)
            }
        }
    }

    func testV1ConstructAndSendAuthorizationResponseHasExpectedBody() async throws {
        let verifiableCredentials: [String: [FormatType: [AnyCodable]]] = [
            "input_descriptor1": [.ldp_vc: [AnyCodable(ldpVC()), AnyCodable(ldpVC(credentialType: "UniversityCredential"))]],
            "input_descriptor2": [.ldp_vc: [AnyCodable(ldpVC())]],
        ]

        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager, walletMetadata: walletMetadata)
        let authorizationRequest = getMockAuthorizationRequest(specVersion: .v1)

        _ = try await handler.constructUnsignedVPToken(
            credentialsMap: verifiableCredentials,
            authorizationRequest: authorizationRequest,
            responseUri: responseUri,
            holderId: holderId,
            signatureSuite: signatureSuite,
            walletNonce: walletNonce
        )

        let vpTokenSigningResults: [VPTokenSigningResult] = [
            VPTokenSigningResult(signedData: Data("testJWS".utf8)),
        ]

        mockNetworkManager.setMockResponse(for: responseUri, responseBody: "sending is success in AuthorizationResponseTests")

        let result = try await handler.constructAndSendAuthorizationResponseToVerifier(
            authorizationRequest: authorizationRequest,
            vpTokenSigningResults: vpTokenSigningResults,
            responseUri: responseUri
        )

        XCTAssertEqual(result.body(), "sending is success in AuthorizationResponseTests")
        let recordedRequest = mockNetworkManager.recordedRequests[responseUri]!
        XCTAssertEqual(recordedRequest.requestBody?["state"] as? String, state)
        XCTAssertNotNil(recordedRequest.requestBody?["vp_token"])
        XCTAssertEqual(recordedRequest.requestBody?.keys.count, 2)
    }

    func testV1ConstructAndSendAuthorizationResponseThrowsForUnsupportedResponseType() async {
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager, walletMetadata: walletMetadata)
        // spec version v1, unsupported response type
        let authorizationRequest = getMockAuthorizationRequest(responseType: "fragment", specVersion: .v1)

        await XCTAssertAsyncThrowsError(try await handler.constructAndSendAuthorizationResponseToVerifier(
            authorizationRequest: authorizationRequest,
            vpTokenSigningResults: [],
            responseUri: "https://client.example.org/cb"
        )) { error in
            assertOpenID4VPException(error,
                expectedMessage: "Provided response_type - fragment is not supported",
                expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    // MARK: - Spec Version 1 - Credential format = SD-JWT

    func testV1ConstructUnsignedVPTokenWithSdJwtSuccess() async throws {
        let verifiableCredentials: [String: [FormatType: [AnyCodable]]] = [
            "input_descriptor2": [.vc_sd_jwt: [AnyCodable(sampeVcSdJwtWithHolderBinding)]],
        ]

        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager, walletMetadata: walletMetadata)
        let authorizationRequest = getMockAuthorizationRequest(specVersion: .v1)

        await XCTAssertNoThrowAndVerifyAsync(try await handler.constructUnsignedVPToken(
            credentialsMap: verifiableCredentials,
            authorizationRequest: authorizationRequest,
            responseUri: responseUri,
            holderId: holderId,
            signatureSuite: signatureSuite,
            walletNonce: walletNonce
        )) { result in
            XCTAssertEqual(result.count, 1)
            print("Constructed data: \(result)")
        }
    }

    func testV1SharingOfSdJwtWithHolderBindingSuccess() async throws {
        mockNetworkManager.setMockResponse(for: responseUri, responseBody: "sending is success in AuthorizationResponseTests")
        let verifiableCredentials: [String: [FormatType: [AnyCodable]]] = [
            "input_descriptor2": [.vc_sd_jwt: [AnyCodable(sampeVcSdJwtWithHolderBinding)]],
        ]

        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager, walletMetadata: walletMetadata)
        let authorizationRequest = getMockAuthorizationRequest(specVersion: .v1)
        _ = try await handler.constructUnsignedVPToken(
            credentialsMap: verifiableCredentials,
            authorizationRequest: authorizationRequest,
            responseUri: responseUri,
            holderId: holderId,
            signatureSuite: signatureSuite,
            walletNonce: walletNonce
        )

        let result = try await handler.constructAndSendAuthorizationResponseToVerifier(
            authorizationRequest: authorizationRequest,
            vpTokenSigningResults: [VPTokenSigningResult(signedData: Data("ayuht".utf8))],
            responseUri: responseUri
        )

        XCTAssertEqual(result.body(), "sending is success in AuthorizationResponseTests")
        let recordedRequest = mockNetworkManager.recordedRequests[responseUri]!
        XCTAssertEqual(recordedRequest.requestBody?["state"] as? String, state)
        XCTAssertNotNil(recordedRequest.requestBody?["vp_token"])
        XCTAssertEqual(recordedRequest.requestBody?.keys.count, 2)
    }

    // MARK: - Spec Version 1 - constructUnsignedVPToken

    func testV1ConstructUnsignedVPTokenWithAllFormatsSuccess() async throws {
        let verifiableCredentials: [String: [FormatType: [AnyCodable]]] = [
            "input_descriptor1": [.ldp_vc: [AnyCodable(ldpVC())]],
            "org.iso.18013.5.1.mDL": [.mso_mdoc: [AnyCodable(sampleMdoc)]],
            "input_descriptor2": [.vc_sd_jwt: [AnyCodable(sampeVcSdJwtWithHolderBinding)]],
            "input_descriptor3": [.dc_sd_jwt: [AnyCodable(sampeVcSdJwtWithHolderBinding)]],
        ]

        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager, walletMetadata: walletMetadata)
        let authorizationRequest = getMockAuthorizationRequest(specVersion: .v1)

        await XCTAssertNoThrowAndVerifyAsync(try await handler.constructUnsignedVPToken(
            credentialsMap: verifiableCredentials,
            authorizationRequest: authorizationRequest,
            responseUri: responseUri,
            holderId: holderId,
            signatureSuite: signatureSuite,
            walletNonce: walletNonce
        )) { result in
            XCTAssertEqual(result.count, 4)
//            XCTAssertTrue(result.keys.contains(.ldp_vc))
//            XCTAssertTrue(result.keys.contains(.mso_mdoc))
//            XCTAssertTrue(result.keys.contains(.vc_sd_jwt))
//            XCTAssertTrue(result.keys.contains(.dc_sd_jwt))
        }
    }

    func testV1ShareAuthorizationResponseWithAllFormatsSuccess() async throws {
        mockNetworkManager.clearResponses()
        mockNetworkManager.setMockResponse(for: responseUri, responseBody: "sending is success in AuthorizationResponseTests")
        let verifiableCredentials: [String: [FormatType: [AnyCodable]]] = [
            "input_descriptor1": [.ldp_vc: [AnyCodable(ldpVC())]],
            "org.iso.18013.5.1.mDL": [.mso_mdoc: [AnyCodable(sampleMdoc)]],
            "input_descriptor2": [.vc_sd_jwt: [AnyCodable(sampeVcSdJwtWithHolderBinding)]],
            "input_descriptor3": [.dc_sd_jwt: [AnyCodable(sampeVcSdJwtWithHolderBinding)]],
        ]

        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager, walletMetadata: walletMetadata)
        let authorizationRequest = getMockAuthorizationRequest(specVersion: .v1)
        _ = try await handler.constructUnsignedVPToken(
            credentialsMap: verifiableCredentials,
            authorizationRequest: authorizationRequest,
            responseUri: responseUri,
            holderId: holderId,
            signatureSuite: signatureSuite,
            walletNonce: walletNonce
        )

        let vpTokenSigningResults: [VPTokenSigningResult] = [
            VPTokenSigningResult(signedData: Data("testJWS".utf8)),
            VPTokenSigningResult(signedData: Data("aGVsbG8=".utf8)),
            VPTokenSigningResult(signedData: Data("ayuht".utf8)),
            VPTokenSigningResult(signedData: Data("ayuht".utf8)),
        ]

        _ = try await handler.constructAndSendAuthorizationResponseToVerifier(
            authorizationRequest: authorizationRequest,
            vpTokenSigningResults: vpTokenSigningResults,
            responseUri: responseUri
        )

        let recordedRequest = mockNetworkManager.recordedRequests[responseUri]!.requestBody
        XCTAssertEqual(recordedRequest?["state"] as? String, state)
        XCTAssertNotNil(recordedRequest?["vp_token"])
    }

    // MARK: - Spec Version 1 - constructAuthorizationResponse

    func testV1ConstructAuthorizationResponseSuccess() async throws {
        let verifiableCredentials: [String: [FormatType: [AnyCodable]]] = [
            "input_descriptor1": [.ldp_vc: [AnyCodable(ldpVC())]],
        ]

        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager, walletMetadata: walletMetadata)
        let authorizationRequest = getMockAuthorizationRequest(responseMode: .directPost, specVersion: .v1)

        _ = try await handler.constructUnsignedVPToken(
            credentialsMap: verifiableCredentials,
            authorizationRequest: authorizationRequest,
            responseUri: responseUri,
            holderId: holderId,
            signatureSuite: signatureSuite,
            walletNonce: walletNonce
        )

        let vpTokenSigningResults: [VPTokenSigningResult] = [
            VPTokenSigningResult(signedData: Data("testJWS".utf8)),
        ]

        let authorizationResponse = try handler.constructVPResponse(
            signingResults: vpTokenSigningResults, authorizationRequest: authorizationRequest
        )

        XCTAssertNotNil(authorizationResponse["vp_token"])
        XCTAssertEqual(authorizationResponse["state"], state)
    }

    func testV1ConstructAuthorizationResponseThrowsForUnsupportedResponseType() {
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager, walletMetadata: walletMetadata)
        let authorizationRequest = getMockAuthorizationRequest(responseType: "fragment", specVersion: .v1)

        XCTAssertThrowsError(try handler.constructVPResponse(
            signingResults: [], authorizationRequest: authorizationRequest
        )) { error in
            assertOpenID4VPException(error,
                expectedMessage: "Provided response_type - fragment is not supported",
                expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    // MARK: - Spec Version 1 - constructAuthorizationErrorResponse

    func testV1ConstructAuthorizationErrorResponseMapsErrorCorrectly() {
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager, walletMetadata: walletMetadata)
        let authorizationRequest = getMockAuthorizationRequest(specVersion: .v1)
        let error = InvalidData(message: "Invalid input data", className: "Test")

        let response = handler.constructAuthorizationErrorResponse(
            authorizationRequest: authorizationRequest,
            exception: error,
            walletNonce: "wallet-nonce"
        )

        XCTAssertEqual(response["error"] as? String, "invalid_request")
        XCTAssertEqual(response["error_description"] as? String, "Invalid input data")
        XCTAssertEqual(response["state"] as? String, state)
    }

    func testV1ConstructAuthorizationErrorResponseWithGenericError() {
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager, walletMetadata: walletMetadata)
        let authorizationRequest = getMockAuthorizationRequest(specVersion: .v1)
        let error = NSError(domain: "test", code: 500)

        let response = handler.constructAuthorizationErrorResponse(
            authorizationRequest: authorizationRequest,
            exception: error,
            walletNonce: "wallet-nonce"
        )

        XCTAssertEqual(response["error"] as? String, "invalid_request")
        XCTAssertNotNil(response["error_description"])
        XCTAssertEqual(response["state"] as? String, state)
    }
}
