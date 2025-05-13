import XCTest
@testable import OpenID4VP

final class AuthorizationResponseHandlerTests: XCTestCase {
    let mockNetworkManager = MockNetworkManager()
    let verifiableCredentials: [String: [FormatType: [Any]]] = ["input_descriptor1": [.ldp_vc: [ldpVC(), ldpVC(credentialType: "UniversityCredential")]], "input_descriptor2": [.ldp_vc: [ldpVC()]]]
    let vpTokenSigningResults = [FormatType.ldp_vc:LdpVPTokenSigningResult(jws: "wemcn3234ns", signatureAlgorithm: "RsaSignature2018", publicKey: "-----BEGIN PUBLIC KEY-----\\nMIIBIjANBggvSPv73S\\nG5ToTt07NZPdKDrg9lSjetZup39oj12u0YoyRMlMhY0xYL6c8X1BexM7Wlp+c13o\\n1QIDAQAB\\n-----END PUBLIC KEY-----\\n", domain: "https://example")]
    let unsignedVPTokens = [FormatType.ldp_vc: UnsignedLdpVPToken(context: ["https://www.w3.org/2018/credentials/v1"], type: ["VerifiablePresentation"], verifiableCredential: [ldpVC().mapValues { AnyCodable($0) },ldpVC(credentialType: "UniversityCredential").mapValues { AnyCodable($0) }, ldpVC(credentialType: "DegreeCredential").mapValues { AnyCodable($0) }], id: "uuid", holder: "wallet/app")]
    
    /// construction of vp_token for signing
    
    func testConstructUnsignedVPTokens() throws {
        let authorizationResponseHandler: AuthorizationResponseHandler = AuthorizationResponseHandler(networkManager: mockNetworkManager)
        let vpTokens: [FormatType: UnsignedVPToken] = try authorizationResponseHandler.constructUnsignedVPToken(credentialsMap: verifiableCredentials, authorizationRequest: getMockAuthorizationRequest(), responseUri : "/response-uri")
        
        XCTAssertTrue(vpTokens.keys.count == 1)
        let ldpVPToken = vpTokens[.ldp_vc] as! UnsignedLdpVPToken
        XCTAssertEqual(ldpVPToken.verifiableCredential.count, 3)
        XCTAssertEqual(ldpVPToken.holder, "")
        XCTAssertEqual(ldpVPToken.type, ["VerifiablePresentation"])
        XCTAssertEqual(ldpVPToken.context, ["https://www.w3.org/2018/credentials/v1"])
        XCTAssertNotNil(UUID(uuidString: ldpVPToken.id), "ID should be a valid UUID")
    }
    
    func testConstructUnsignedVPTokensThrowErrorWhenCredentialsListIsEmpty() throws {
        let authorizationResponseHandler: AuthorizationResponseHandler = AuthorizationResponseHandler(networkManager: mockNetworkManager)
        
        XCTAssertThrowsError(try authorizationResponseHandler.constructUnsignedVPToken(credentialsMap: [:], authorizationRequest: getMockAuthorizationRequest(), responseUri : "/response-uri")) { error in
            XCTAssertEqual("Empty credentials list - The Wallet did not have the requested Credentials to satisfy the Authorization Request.", error.localizedDescription)
        }
        
    }
    
    // Sharing of verifiable presentations
    /// one VP format in response_type vp_token
    
    func testShareVPHasTheAuthorizationResponseAsExpected() async throws {
        let expectedVPToken = """
{
  "type": [
    "VerifiablePresentation"
  ],
  "@context": [
    "https://www.w3.org/2018/credentials/v1"
  ],
  "verifiableCredential": [
    {
      "credentialSubject": {
        "family_name": "Mockister",
        "given_name": "MockUser",
        "birthdate": "1949-01-22"
      },
      "type": [
        "VerifiableCredential",
        "IDCardCredential"
      ],
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1"
      ],
      "issuer": {
        "id": "did:example:issuer"
      },
      "proof": {
        "jws": "eyJhb...JQdBw",
        "created": "2021-03-19T15:30:15Z",
        "proofPurpose": "assertionMethod",
        "verificationMethod": "did:example:issuer#keys-1",
        "type": "Ed25519Signature2018"
      },
      "issuanceDate": "2010-01-01T19:23:24Z",
      "id": "https://example.com/credentials/1872"
    },
    {
      "id": "https://example.com/credentials/1872",
      "issuer": {
        "id": "did:example:issuer"
      },
      "proof": {
        "verificationMethod": "did:example:issuer#keys-1",
        "jws": "eyJhb...JQdBw",
        "proofPurpose": "assertionMethod",
        "created": "2021-03-19T15:30:15Z",
        "type": "Ed25519Signature2018"
      },
      "issuanceDate": "2010-01-01T19:23:24Z",
      "credentialSubject": {
        "family_name": "Mockister",
        "birthdate": "1949-01-22",
        "given_name": "MockUser"
      },
      "type": [
        "VerifiableCredential",
        "UniversityCredential"
      ],
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1"
      ]
    },
    {
      "credentialSubject": {
        "given_name": "MockUser",
        "birthdate": "1949-01-22",
        "family_name": "Mockister"
      },
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1"
      ],
      "issuer": {
        "id": "did:example:issuer"
      },
      "type": [
        "VerifiableCredential",
        "IDCardCredential"
      ],
      "id": "https://example.com/credentials/1872",
      "issuanceDate": "2010-01-01T19:23:24Z",
      "proof": {
        "jws": "eyJhb...JQdBw",
        "verificationMethod": "did:example:issuer#keys-1",
        "type": "Ed25519Signature2018",
        "proofPurpose": "assertionMethod",
        "created": "2021-03-19T15:30:15Z"
      }
    }
  ],
  "holder": "",
  "proof": {
    "challenge": "nonce",
    "jws": "testJWS",
    "domain": "testDomain",
    "type": "ES256",
    "verificationMethod": "testPublicKey",
    "proofPurpose": "authentication",
  }
}
"""
        let authorizationResponseHandler: AuthorizationResponseHandler = AuthorizationResponseHandler(networkManager: mockNetworkManager)
        let responseUri = "https://mock-verifier.com/response-uri"
        _ = try authorizationResponseHandler.constructUnsignedVPToken(credentialsMap: verifiableCredentials, authorizationRequest: getMockAuthorizationRequest(),responseUri : responseUri)

        mockNetworkManager.setMockResponse(for: responseUri, responseBody: "sending is success in AuthorizationResponseTests")
        let mockVPTokenSigningResults = [FormatType.ldp_vc : LdpVPTokenSigningResult(
            jws: "testJWS",
            signatureAlgorithm: "ES256",
            publicKey: "testPublicKey",
            domain: "testDomain"
        )]
        _ =  try authorizationResponseHandler.constructUnsignedVPToken(credentialsMap: verifiableCredentials, authorizationRequest: getMockAuthorizationRequest(), responseUri : responseUri)
        
        let result = try await authorizationResponseHandler.shareVP(authorizationRequest: mockAuthorizationRequestObjectWithDirectPostResponseMode, vpTokenSigningResults: mockVPTokenSigningResults, responseUri: responseUri)
        
        XCTAssertEqual("sending is success in AuthorizationResponseTests", result)
        let recordedRequest = mockNetworkManager.recordedRequests[responseUri]!
        let decodedVPToken = decodeQueryValue(jsonString(recordedRequest.requestBody?["vp_token"]! ?? "") ?? "")
        XCTAssertTrue(recordedRequest.requestBody?.keys.count == 3)
        XCTAssertTrue(recordedRequest.requestBody?["presentation_submission"] != nil)
        assertJsonString(expected: expectedVPToken, actual: decodedVPToken, strict: false)
        XCTAssertEqual("state", recordedRequest.requestBody?["state"] as! String)
    }
    
    /// more than one VP format in response_type vp_token -> formats: ldp_vc, mso_mdoc
    func testShareVPSendingAuthorizationResponseWithMultipleVPFormatsSuccessfully() async throws {
        let verifiableCredentials: [String: [FormatType: [Any]]] = [
            "input_descriptor1": [.ldp_vc: [ldpVC()]],
            "org.iso.18013.5.1.mDL": [.mso_mdoc: [sampleMdoc]]
        ]
        let authorizationResponseHandler: AuthorizationResponseHandler = AuthorizationResponseHandler(networkManager: mockNetworkManager)
        let mockAuthorizationRequest = getMockAuthorizationRequest(responseMode: .directPostJwt)
        let responseUri = "https://mock-verifier.com"
        mockNetworkManager.setMockResponse(for: responseUri, responseBody: "sending is success in AuthorizationResponseTests")
        let mockVPTokenSigningResults : [FormatType: VPTokenSigningResult] = [
            .ldp_vc : LdpVPTokenSigningResult(
                jws: "testJWS",
                signatureAlgorithm: "ES256",
                publicKey: "testPublicKey",
                domain: "testDomain"
            ),
            .mso_mdoc: MdocVPTokenSigningResult(
                docTypeToDeviceAuthentication: ["org.iso.18013.5.1.mDL": DeviceAuthentication(signature: "aGVsbG8=", algorithm: "ES256")]
            )
        ]
        _ =  try authorizationResponseHandler.constructUnsignedVPToken(credentialsMap: verifiableCredentials, authorizationRequest: mockAuthorizationRequest, responseUri : "/response-uri")
        
        let result = try await authorizationResponseHandler.shareVP(authorizationRequest: mockAuthorizationRequest, vpTokenSigningResults: mockVPTokenSigningResults, responseUri: responseUri)
        
        XCTAssertEqual("sending is success in AuthorizationResponseTests", result)
        let recordedRequest = mockNetworkManager.recordedRequests[responseUri]!
        XCTAssertTrue(recordedRequest.requestBody?.keys.count == 1)
        XCTAssertTrue(recordedRequest.requestBody?["response"] != nil)
        //TODO: Cross check
        XCTAssertTrue((((recordedRequest.requestBody?["response"] as! String).starts(with: "ey")) != nil))
    }
    
    func testShareVPThrowErrorWhenResponseTypeIsNotSupportedByLibrary() async  {
        let authorizationRequest = getMockAuthorizationRequest(responseType: "fragment")
        let authorizationResponseHandler = AuthorizationResponseHandler(networkManager: mockNetworkManager)
        
        do {
            _ = try await authorizationResponseHandler.shareVP(authorizationRequest: authorizationRequest, vpTokenSigningResults: vpTokenSigningResults, responseUri: "https://client.example.org/cb")
            XCTFail("Response type not supported error should have been thrown but did not get error")
        } catch {
            XCTAssertEqual("response type - fragment is not supported", error.localizedDescription)
        }
    }
    
    func testShareVPThrowErrorWhenRespectiveCredentialFormatIsNotAvailableInUnsignedVPTokens() async  {
        let authorizationRequest = getMockAuthorizationRequest()
        let authorizationResponseHandler = AuthorizationResponseHandler(networkManager: mockNetworkManager)
        //constructUnsignedVPTokens returns error as empty credentialsMap is passed, so unsignedVPTokens field is empty dictionary
        do{_ =  try authorizationResponseHandler.constructUnsignedVPToken(credentialsMap: [:], authorizationRequest: authorizationRequest, responseUri : "/response-uri")}catch {}
        
        do {
            _ = try await authorizationResponseHandler.shareVP(authorizationRequest: authorizationRequest, vpTokenSigningResults: vpTokenSigningResults, responseUri: "https://client.example.org/cb")
            XCTFail("Response type not supported error should have been thrown but did not get error")
        } catch {
            XCTAssertEqual("unable to find the related credential format - ldp_vc in the unsignedVPTokens map", error.localizedDescription)
        }
    }
    
    func testShareVPThrowErrorWhenVerifiableCredentialsAreNotPassedInExpectedFormats() async  {
        let testCases: [TestCase] = [
            TestCase(input: ["input1": [FormatType.ldp_vc : [1,2]]], expectedError: "ldp_vc credentials are not passed in JSON format"),
            TestCase(input: ["input1": [.mso_mdoc : [1,2]]], expectedError: "mso_mdoc credentials are not passed in string format"),
        ]
        let authorizationResponseHandler = AuthorizationResponseHandler(networkManager: mockNetworkManager)
        for testCase in testCases {
            XCTAssertThrowsError(try authorizationResponseHandler.constructUnsignedVPToken(credentialsMap: testCase.input, authorizationRequest: getMockAuthorizationRequest(), responseUri : "/response-uri")) { error in
                XCTAssertEqual(testCase.expectedError, error.localizedDescription)
            }
        }
    }
    
    /// construction of presentation submission for sharing
    
    /// format - ldp_vc
    func testShareVPToSharePresentationSubmissionOfLdpVCInExpectedFormat() async throws {
        let expectedPresentationSubmission = """
{
  "descriptor_map": [
    {
      "path": "$",
      "path_nested": {
        "id": "input_descriptor1",
        "format": "ldp_vc",
        "path": "$.verifiableCredential[0]"
      },
      "id": "input_descriptor1",
      "format": "ldp_vp"
    },
    {
      "path": "$",
      "path_nested": {
        "id": "input_descriptor1",
        "path": "$.verifiableCredential[1]",
        "format": "ldp_vc"
      },
      "id": "input_descriptor1",
      "format": "ldp_vp"
    },
    {
      "path": "$",
      "path_nested": {
        "format": "ldp_vc",
        "path": "$.verifiableCredential[2]",
        "id": "input_descriptor2"
      },
      "id": "input_descriptor2",
      "format": "ldp_vp"
    }
  ],
  "definition_id": "vp_presentation_definition"
}
"""
        let authorizationResponseHandler: AuthorizationResponseHandler = AuthorizationResponseHandler(networkManager: mockNetworkManager)
        _ = try authorizationResponseHandler.constructUnsignedVPToken(credentialsMap: verifiableCredentials, authorizationRequest: getMockAuthorizationRequest(),responseUri : "/response-uri")
        let responseUri = "https://mock-verifier.com"
        mockNetworkManager.setMockResponse(for: responseUri, responseBody: "sending is success in AuthorizationResponseTests")
        let mockVPTokenSigningResults = [FormatType.ldp_vc : LdpVPTokenSigningResult(
            jws: "testJWS",
            signatureAlgorithm: "ES256",
            publicKey: "testPublicKey",
            domain: "testDomain"
        )]
        _ =  try authorizationResponseHandler.constructUnsignedVPToken(credentialsMap: verifiableCredentials, authorizationRequest: getMockAuthorizationRequest(), responseUri : "/response-uri")
        
        _ = try await authorizationResponseHandler.shareVP(authorizationRequest: mockAuthorizationRequestObjectWithDirectPostResponseMode, vpTokenSigningResults: mockVPTokenSigningResults, responseUri: responseUri)
        
        let recordedRequest = mockNetworkManager.recordedRequests[responseUri]!
        let decodedPresentationSubmission = decodeQueryValue(jsonString(recordedRequest.requestBody?["presentation_submission"]! ?? "") ?? "")
        assertJsonString(expected: expectedPresentationSubmission, actual: decodedPresentationSubmission, strict: false)
    }
}
