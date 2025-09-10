@testable import OpenID4VP
import XCTest

final class AuthorizationResponseHandlerTests: XCTestCase {
    let mockNetworkManager = MockNetworkManager()
    let state = "state"
    let responseUri = "https://mock-verifier.com"
    let holderId = "wallet-holder-id"
    let walletNonce = "mock-nonce"
    let signatureSuite = "JsonWebSignature2020"
    
    func testConstructUnsignedVPTokenThrowsErrorIncaseOfInvalidHoldersIdWithLdpVCAvailable() async throws {
        let invalidHolderIdTestCases = ["", " ", "  ", nil]
        let verifiableCredentials: [String: [FormatType: [AnyCodable]]] = [
            "input_descriptor1": [.ldp_vc: [AnyCodable(ldpVC())]],
            "org.iso.18013.5.1.mDL": [.mso_mdoc: [AnyCodable(sampleMdoc)]],
        ]
        
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager)
        let authorizationRequest = getMockAuthorizationRequest()
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
        let invalidsignatureSuiteTestCases = ["", " ", "  ", nil]
        let verifiableCredentials: [String: [FormatType: [AnyCodable]]] = [
            "input_descriptor1": [.ldp_vc: [AnyCodable(ldpVC())]],
            "org.iso.18013.5.1.mDL": [.mso_mdoc: [AnyCodable(sampleMdoc)]],
        ]
        
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager)
        let authorizationRequest = getMockAuthorizationRequest()
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
    
    
    func testConstructUnsignedVPTokenV1Success() async throws {
        let verifiableCredentials: [String: [String]] = [
            "input_descriptor1": ["{\"credentialSubject\"...}"],
        ]
        
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager)
        let authorizationRequest = getMockAuthorizationRequest()
        
        await XCTAssertNoThrowAndVerifyAsync(try await handler.constructUnsignedVPTokenV1(
            verifiableCredentials: verifiableCredentials,
            authorizationRequest: authorizationRequest,
            responseUri: responseUri,
            walletNonce: walletNonce
        )) { result in
            XCTAssertTrue(result.contains("credentialSubject"))
        }
        
    }
    
    func testShareVPHasTheAuthorizationResponseAsExpected() async throws {
        let verifiableCredentials: [String: [FormatType: [AnyCodable]]] = [
            "input_descriptor1": [.ldp_vc: [AnyCodable(ldpVC()), AnyCodable(ldpVC(credentialType: "UniversityCredential"))]],
            "input_descriptor2": [.ldp_vc: [AnyCodable(ldpVC())]],
        ]
        
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager)
        let authorizationRequest = getMockAuthorizationRequest()
        
        _ = try await handler.constructUnsignedVPToken(
            credentialsMap: verifiableCredentials,
            authorizationRequest: authorizationRequest,
            responseUri: responseUri,
            holderId: holderId,
            signatureSuite: signatureSuite,
            walletNonce: walletNonce
        )
        
        let vpTokenSigningResults = [FormatType.ldp_vc: LdpVPTokenSigningResult(
            jws: "testJWS",
            proofValue: "",
            signatureAlgorithm: "JsonWebSignature2020"
        )]
        
        mockNetworkManager.setMockResponse(for: responseUri, responseBody: "sending is success in AuthorizationResponseTests")
        
        let result = try await handler.shareVP(
            authorizationRequest: authorizationRequest,
            vpTokenSigningResults: vpTokenSigningResults,
            responseUri: responseUri
        )
        
        XCTAssertEqual(result, "sending is success in AuthorizationResponseTests")
        let recordedRequest = mockNetworkManager.recordedRequests[responseUri]!
        XCTAssertEqual(recordedRequest.requestBody?["state"] as? String, state)
        XCTAssertNotNil(recordedRequest.requestBody?["presentation_submission"])
        XCTAssertEqual(recordedRequest.requestBody?.keys.count, 3)
    }
    
    func testShareVPSendingAuthorizationResponseWithMultipleVPFormatsSuccessfully() async throws {
        let verifiableCredentials: [String: [FormatType: [AnyCodable]]] = [
            "input_descriptor1": [.ldp_vc: [AnyCodable(ldpVC())]],
            "org.iso.18013.5.1.mDL": [.mso_mdoc: [AnyCodable(sampleMdoc)]],
        ]
        
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager)
        let mockAuthorizationRequest = getMockAuthorizationRequest(responseMode: .directPostJwt)
        
        mockNetworkManager.setMockResponse(for: responseUri, responseBody: "sending is success in AuthorizationResponseTests")
        
        let vpTokenSigningResults: [FormatType: VPTokenSigningResult] = [
            .ldp_vc: LdpVPTokenSigningResult(jws: "testJWS", proofValue: "", signatureAlgorithm: "JsonWebSignature2020"),
            .mso_mdoc: MdocVPTokenSigningResult(docTypeToDeviceAuthentication: ["org.iso.18013.5.1.mDL": DeviceAuthentication(signature: "aGVsbG8=", algorithm: "ES256")]),
        ]
        
        _ = try await handler.constructUnsignedVPToken(
            credentialsMap: verifiableCredentials,
            authorizationRequest: mockAuthorizationRequest,
            responseUri: responseUri,
            holderId: holderId,
            signatureSuite: signatureSuite,
            walletNonce: walletNonce
        )
        
        let result = try await handler.shareVP(
            authorizationRequest: mockAuthorizationRequest,
            vpTokenSigningResults: vpTokenSigningResults,
            responseUri: responseUri
        )
        
        XCTAssertEqual(result, "sending is success in AuthorizationResponseTests")
        let recordedRequest = mockNetworkManager.recordedRequests[responseUri]!
        XCTAssertEqual(recordedRequest.requestBody?.keys.count, 1)
        XCTAssertNotNil(recordedRequest.requestBody?["response"])
    }
    
    func testShareVPThrowErrorWhenResponseTypeIsNotSupportedByLibrary() async {
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager)
        let authorizationRequest = getMockAuthorizationRequest(responseType: "fragment")
        
        do {
            _ = try await handler.shareVP(
                authorizationRequest: authorizationRequest,
                vpTokenSigningResults: [:],
                responseUri: "https://client.example.org/cb"
            )
            XCTFail("Expected error not thrown")
        } catch {
            assertOpenID4VPException(error,
                                     expectedMessage: "response type - fragment is not supported",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testShareVPThrowErrorWhenRespectiveCredentialFormatIsNotAvailableInUnsignedVPTokens() async {
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager)
        let authorizationRequest = getMockAuthorizationRequest()
        _ = try? await handler.constructUnsignedVPToken(
            credentialsMap: [:],
            authorizationRequest: authorizationRequest,
            responseUri: responseUri,
            holderId: holderId,
            signatureSuite: signatureSuite,
            walletNonce: walletNonce
        )
        
        do {
            _ = try await handler.shareVP(
                authorizationRequest: authorizationRequest,
                vpTokenSigningResults: [FormatType.ldp_vc: LdpVPTokenSigningResult(jws: "", proofValue: "", signatureAlgorithm: "")],
                responseUri: "https://client.example.org/cb"
            )
            XCTFail("Expected error not thrown")
        } catch {
            assertOpenID4VPException(error,
                                     expectedMessage: "unable to find the related credential format - ldp_vc in the unsignedVPTokens map",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testShareVPToSharePresentationSubmissionOfLdpVCInExpectedFormat() async throws {
        // Arrange
        let verifiableCredentials: [String: [FormatType: [AnyCodable]]] = [
            "input_descriptor1": [.ldp_vc: [AnyCodable(ldpVC())]],
            "org.iso.18013.5.1.mDL": [.mso_mdoc: [AnyCodable(sampleMdoc)]],
        ]
        
        let expectedPresentationSubmissionTemplate = """
        {
            "definition_id": "vp_presentation_definition",
            "descriptor_map": [
                {
                    "format": "ldp_vp",
                    "id": "input_descriptor1",
                    "path": "$",
                    "path_nested": {
                        "id": "input_descriptor1",
                        "path": "$.verifiableCredential[0]",
                        "format": "ldp_vc"
                    }
                },
                {
                    "id": "org.iso.18013.5.1.mDL",
                    "format": "mso_mdoc",
                    "path": "$"
                }
            ],
            "id": "<DYNAMIC_ID>"
        }
        """
        
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager)
        
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
        
        let mockVPTokenSigningResults: [FormatType: VPTokenSigningResult] = [
            .ldp_vc: LdpVPTokenSigningResult(
                jws: "testJWS",
                proofValue: "test",
                signatureAlgorithm: "JsonWebSignature2020"
            )
        ]
        
        _ = try await handler.shareVP(
            authorizationRequest: mockAuthorizationRequestObjectWithDirectPostResponseMode,
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
        
        // Replace the dynamic ID in expected string
        let expectedJsonString = expectedPresentationSubmissionTemplate.replacingOccurrences(of: "<DYNAMIC_ID>", with: actualId)
        
        assertJsonString(
            expected: expectedJsonString,
            actual: actualJson,
            strict: false
        )
    }
    
    //MARK: Credential format = SD-JWT
    
    func testCreationOfUnsignedVPTokenWithSdJwtFormatSuccess() async throws {
        let verifiableCredentials: [String: [FormatType: [AnyCodable]]] = [
            "input_descriptor2": [.vc_sd_jwt: [AnyCodable(sampeVcSdJwtWithHolderBinding)]],
        ]
        
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager)
        let authorizationRequest = getMockAuthorizationRequest()
        
        await XCTAssertNoThrowAndVerifyAsync(try await handler.constructUnsignedVPToken(
            credentialsMap: verifiableCredentials,
            authorizationRequest: authorizationRequest,
            responseUri: responseUri,
            holderId: holderId,
            signatureSuite: signatureSuite,
            walletNonce: walletNonce
        )) { result in
            XCTAssertTrue(result.keys.count == 1)
            XCTAssertTrue(result.keys.contains(.vc_sd_jwt))
            XCTAssertTrue((result.values.first as? UnsignedSdJWTVPToken)?.uuidToUnsignedKBT.count == 1)
        }
    }
    
    func testSharingOfSdJwtWithHolderBindingSuccess() async throws {
        mockNetworkManager.setMockResponse(for: responseUri, responseBody: "sending is success in AuthorizationResponseTests")
        let verifiableCredentials: [String: [FormatType: [AnyCodable]]] = [
            "input_descriptor2": [.vc_sd_jwt: [AnyCodable(sampeVcSdJwtWithHolderBinding)]],
        ]
        
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager)
        let authorizationRequest = getMockAuthorizationRequest()
        let unsignedVpTokens = try await handler.constructUnsignedVPToken(
            credentialsMap: verifiableCredentials,
            authorizationRequest: authorizationRequest,
            responseUri: responseUri,
            holderId: holderId,
            signatureSuite: signatureSuite,
            walletNonce: walletNonce
        )
        
        let sdJwtUUID = (unsignedVpTokens[.vc_sd_jwt] as! UnsignedSdJWTVPToken).uuidToUnsignedKBT.keys.first!
        let result = try await handler.shareVP(authorizationRequest: authorizationRequest, vpTokenSigningResults: [.vc_sd_jwt: SdJwtVpTokenSigningResult(uuidToKbJWTSignature: [sdJwtUUID: "ayuht"])], responseUri: responseUri)
        
        
        XCTAssertEqual(result, "sending is success in AuthorizationResponseTests")
        let recordedRequest = mockNetworkManager.recordedRequests[responseUri]!
        XCTAssertEqual(recordedRequest.requestBody?["state"] as? String, state)
        let presentationSubmission: String? = recordedRequest.requestBody?["presentation_submission"]
        XCTAssertNotNil(presentationSubmission)
        XCTAssertEqual(recordedRequest.requestBody?.keys.count, 3)
         
    }
            
    
    //MARK: Credential format = All supported credential formats combination
    
    func testConstructUnsignedVPTokenSuccess() async throws {
        let verifiableCredentials: [String: [FormatType: [AnyCodable]]] = [
            "input_descriptor1": [.ldp_vc: [AnyCodable(ldpVC())]],
            "org.iso.18013.5.1.mDL": [.mso_mdoc: [AnyCodable(sampleMdoc)]],
            "input_descriptor2": [.vc_sd_jwt: [AnyCodable(sampeVcSdJwtWithHolderBinding)]],
            "input_descriptor3": [.dc_sd_jwt: [AnyCodable(sampeVcSdJwtWithHolderBinding)]],
        ]
        
        let handler = AuthorizationResponseHandler(networkManager: mockNetworkManager)
        let authorizationRequest = getMockAuthorizationRequest()
        
        await XCTAssertNoThrowAndVerifyAsync(try await handler.constructUnsignedVPToken(
            credentialsMap: verifiableCredentials,
            authorizationRequest: authorizationRequest,
            responseUri: responseUri,
            holderId: holderId,
            signatureSuite: signatureSuite,
            walletNonce: walletNonce
        )) { result in
            XCTAssertTrue(result.keys.contains(.ldp_vc))
            XCTAssertTrue(result.keys.contains(.mso_mdoc))
            XCTAssertTrue(result.keys.contains(.vc_sd_jwt))
            XCTAssertTrue(result.keys.contains(.dc_sd_jwt))
        }
        
    }
}


/**
 sdjwt1 (holder binding), sdjwt2 (no holder binding)
 
unsigned vp token [uuid1: sdjwt1kbjwtUnsigned]
 credentials [uuid1: sdjwt1, uuid2: sdjwt2]
 

 
 consumer send the result
 vpTokenSigningResults [uuid1:  kbJwtSigned]
 vpTokenSigningResults [:]
 
iterate credentials
    for each uuid check if unsigned is available in unsigned vp token
        if available, then add the signed version to vp token
        else dont attach
 
 
 sdjwtx (no holder binding)
 unsigned vp token [:]
  credentials [uuid1: sdjwtx]
 
 result of method -> [sd-jwt : SdJwtUnsignedVpToken(uuidtoUnsignedKBT([:]))] // as long as credentials have sd-jwt there will be     SdJwtUnsignedVpToken   entry in the map (having uuidtoUnsignedKBT depends on holder binding) & consumer should send the sdjwt vptoken signing result back with info (info can be empty map or element based on the unsigned vp token input)
 
    consumer send the result
    vpTokenSigningResults [:]
 
 */

