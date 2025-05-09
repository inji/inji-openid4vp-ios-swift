import XCTest
@testable import OpenID4VP

final class AuthorizationResponseHandlerTests: XCTestCase {
    let mockNetworkManager = MockNetworkManager()
    let verifiableCredentials: [String: [FormatType: [Any]]] = ["input_descriptor1": [.ldp_vc: ["cred1", "cred3"]], "input_descriptor2": [.ldp_vc: ["cred3"]]]
    let vpTokenSigningResults = [FormatType.ldp_vc:LdpVPTokenSigningResult(jws: "wemcn3234ns", signatureAlgorithm: "RsaSignature2018", publicKey: "-----BEGIN PUBLIC KEY-----\\nMIIBIjANBggvSPv73S\\nG5ToTt07NZPdKDrg9lSjetZup39oj12u0YoyRMlMhY0xYL6c8X1BexM7Wlp+c13o\\n1QIDAQAB\\n-----END PUBLIC KEY-----\\n", domain: "https://example")]
    let unsignedVPTokens = [FormatType.ldp_vc: UnsignedLdpVPToken(context: ["https://www.w3.org/2018/credentials/v1"], type: ["VerifiablePresentation"], verifiableCredential: ["cred1","cred2", "cred3"], id: "uuid", holder: "wallet/app")]
    
    /// construction of vp_token for signing
    
    func testConstructUnsignedVPTokens() throws {
        let authorizationResponseHandler: AuthorizationResponseHandler = AuthorizationResponseHandler(networkManager: mockNetworkManager)
        let vpTokens: [FormatType: UnsignedVPToken] = try authorizationResponseHandler.constructUnsignedVPToken(credentialsMap: verifiableCredentials, authorizationRequest: getMockAuthorizationRequest(), responseUri : "/response-uri")
        
        XCTAssertTrue(vpTokens.keys.count == 1)
        let ldpVPToken = vpTokens[.ldp_vc] as! UnsignedLdpVPToken
        XCTAssertEqual(ldpVPToken.verifiableCredential.count, ["cred1", "cred2", "cred3"].count)
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
    
    /// sharing of verifiable presentations
    
    func testShareVPHasThePresentationDefinitionAsExpected() async throws {
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
        
        let result = try await authorizationResponseHandler.shareVP(authorizationRequest: mockAuthorizationRequestObjectWithDirectPostResponseMode, vpTokenSigningResults: mockVPTokenSigningResults, responseUri: responseUri)
        
        XCTAssertEqual("sending is success in AuthorizationResponseTests", result)
        let recordedRequest = mockNetworkManager.recordedRequests[responseUri]!
        let decodedPresentationSubmission = decodeQueryValue((recordedRequest.requestBody?["presentation_submission"])!)
        let decodedVPToken = decodeQueryValue((recordedRequest.requestBody?["vp_token"])!)
        XCTAssertTrue(recordedRequest.requestBody?.keys.count == 3)
        assertJsonString(expected: "{\"definition_id\":\"vp_presentation_definition\",\"descriptor_map\":[{\"path_nested\":{\"path\":\"$.verifiableCredential[0]\",\"id\":\"input_descriptor1\",\"format\":\"ldp_vc\"},\"format\":\"ldp_vp\",\"id\":\"input_descriptor1\",\"path\":\"$\"},{\"format\":\"ldp_vp\",\"id\":\"input_descriptor1\",\"path_nested\":{\"id\":\"input_descriptor1\",\"format\":\"ldp_vc\",\"path\":\"$.verifiableCredential[1]\"},\"path\":\"$\"},{\"format\":\"ldp_vp\",\"id\":\"input_descriptor2\",\"path\":\"$\",\"path_nested\":{\"format\":\"ldp_vc\",\"path\":\"$.verifiableCredential[2]\",\"id\":\"input_descriptor2\"}}]}", actual: decodedPresentationSubmission, strict: false)
        assertJsonString(expected: "{\r\n  \"proof\" : {\r\n    \"challenge\" : \"nonce\",\r\n    \"jws\" : \"testJWS\",\r\n    \"verificationMethod\" : \"testPublicKey\",\r\n    \"domain\" : \"testDomain\",\r\n    \"type\" : \"ES256\",\r\n    \"proofPurpose\" : \"authentication\"\r\n  },\r\n  \"type\" : [\r\n    \"VerifiablePresentation\"\r\n  ],\r\n  \"@context\" : [\r\n    \"https:\\/\\/www.w3.org\\/2018\\/credentials\\/v1\"\r\n  ],\r\n  \"holder\" : \"\",\r\n  \"verifiableCredential\" : [\r\n    \"cred1\",\r\n    \"cred3\",\r\n    \"cred3\"\r\n  ]\r\n}", actual: decodedVPToken, strict: false)
        XCTAssertEqual("state", recordedRequest.requestBody?["state"])
    }
    
    ///// sharing of authorization response with more than one VP format in response_type vp_token
    func testShareVPSendingAuthorizationResponseWithMultipleVPFormatsSuccessfully() async throws {
        //TODO: fix me :)
        let verifiableCredentials: [String: [FormatType: [Any]]] = [
            "input_descriptor1": [.ldp_vc: ["cred3"]],
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
        print("recordedRequest.requestBody: \(recordedRequest.requestBody)")
        XCTAssertTrue(recordedRequest.requestBody?.keys.count == 1)
        XCTAssertTrue(recordedRequest.requestBody?["response"] != nil)
        XCTAssertTrue(((recordedRequest.requestBody?["response"]?.starts(with: "ey")) != nil))
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
    
    func testShareVPThrowErrorWhenVerifiableCredentialsAreNotPassedAsStringInLdpVcsOrMdocs() async  {
        let testCases: [TestCase] = [
            TestCase(input: ["input1": [FormatType.ldp_vc : [1,2]]], expectedError: "ldp_vc credentials are not passed in string format"),
            TestCase(input: ["input1": [.mso_mdoc : [1,2]]], expectedError: "mso_mdoc credentials are not passed in string format"),
        ]
        let authorizationResponseHandler = AuthorizationResponseHandler(networkManager: mockNetworkManager)
        for testCase in testCases {
            XCTAssertThrowsError(try authorizationResponseHandler.constructUnsignedVPToken(credentialsMap: testCase.input, authorizationRequest: getMockAuthorizationRequest(), responseUri : "/response-uri")) { error in
                XCTAssertEqual(testCase.expectedError, error.localizedDescription)
            }
        }
    }
}

func jsonStringToArray(_ jsonString: String) -> [Any]? {
    guard let data = jsonString.data(using: .utf8) else {
        print("Failed to convert string to data")
        return nil
    }
    
    do {
        if let jsonArray = try JSONSerialization.jsonObject(with: data, options: []) as? [Any] {
            return jsonArray
        } else if let jsonObject = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any] {
            // If it's an object rather than an array, wrap it in an array
            return [jsonObject]
        } else {
            print("Failed to parse JSON into array or object")
            return nil
        }
    } catch {
        print("Error parsing JSON: \(error)")
        return nil
    }
}

func stringToVPTokenArray(_ jsonString: String) -> VPTokenType? {
    guard let data = jsonString.data(using: .utf8) else {
        print("Failed to convert string to data")
        return nil
    }

    do {
        if let jsonArray = try JSONSerialization.jsonObject(with: data, options: []) as? [String] {
            // Convert each string in the array to a VPToken
            let vpTokens: [any VPToken] = jsonArray.map { MdocVPToken(value: $0) }
            return .vpTokenArray(vpTokens)
        } else if let jsonArray = try JSONSerialization.jsonObject(with: data, options: []) as? [[String: Any]] {
            // Handle array of objects by converting each to a token string representation
            let vpTokens: [any VPToken] = jsonArray.compactMap { tokenObject in
                if let tokenData = try? JSONSerialization.data(withJSONObject: tokenObject),
                   let tokenString = String(data: tokenData, encoding: .utf8) {
                    return MdocVPToken(value: tokenString)
                }
                return nil
            }
            return .vpTokenArray(vpTokens)
        } else {
            print("JSON string is not an array of strings or objects")
            return nil
        }
    } catch {
        print("Error parsing JSON string to VPTokenArray: \(error)")
        return nil
    }
}
