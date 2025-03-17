import XCTest
@testable import OpenID4VP

final class AuthorizationResponseHandlerTests: XCTestCase {
    let mockNetworkManager = MockNetworkManager()
    let verifiableCredentials: [String: [FormatType: [Any]]] = ["input_descriptor1": [.ldp_vc: ["cred1", "cred3"]], "input_descriptor2": [.ldp_vc: ["cred3"]]]
    let vpResponsesMetaData = [FormatType.ldp_vc:LdpVPResponseMetadata(jws: "wemcn3234ns", signatureAlgorithm: "RsaSignature2018", publicKey: "-----BEGIN PUBLIC KEY-----\\nMIIBIjANBggvSPv73S\\nG5ToTt07NZPdKDrg9lSjetZup39oj12u0YoyRMlMhY0xYL6c8X1BexM7Wlp+c13o\\n1QIDAQAB\\n-----END PUBLIC KEY-----\\n", domain: "https://example")]
    let vpTokensForSigning = [FormatType.ldp_vc: LdpVPTokenForSigning(verifiableCredential: ["cred1","cred2", "cred3"], id: "uuid", holder: "wallet/app")]
    
    /// construction of vp_token for signing
    
    func testConstructVpForSigning() throws {
        let authorizationResponseHandler: AuthorizationResponseHandler = AuthorizationResponseHandler(networkManager: mockNetworkManager)
        let vpTokens: [FormatType: VPTokenForSigning] = try authorizationResponseHandler.constructVPTokenForSigning(credentialsMap: verifiableCredentials, holder: "holder")
        
        XCTAssertTrue(vpTokens.keys.count == 1)
        let ldpVpToken = vpTokens[.ldp_vc] as! LdpVPTokenForSigning
        XCTAssertEqual(ldpVpToken.verifiableCredential.count, ["cred1", "cred2", "cred3"].count)
        XCTAssertEqual(ldpVpToken.holder, "holder")
        XCTAssertEqual(ldpVpToken.type, ["VerifiablePresentation"])
        XCTAssertEqual(ldpVpToken.context, ["https://www.w3.org/2018/credentials/v1"])
        XCTAssertNotNil(UUID(uuidString: ldpVpToken.id), "ID should be a valid UUID")
    }

    func testConstructVpForSigningThrowErrorWhenCredentialsListIsEmpty() throws {
        let authorizationResponseHandler: AuthorizationResponseHandler = AuthorizationResponseHandler(networkManager: mockNetworkManager)
        
        XCTAssertThrowsError(try authorizationResponseHandler.constructVPTokenForSigning(credentialsMap: [:], holder: "holder")) { error in
            XCTAssertEqual("Empty credentials list - The Wallet did not have the requested Credentials to satisfy the Authorization Request.", error.localizedDescription)
        }
       
    }
    
    /// sharing of verifiable presentations

    func testShareVPHasThePresentationDefinitionAsExpected() async throws {
        let authorizationResponseHandler: AuthorizationResponseHandler = AuthorizationResponseHandler(networkManager: mockNetworkManager)
        _ = try authorizationResponseHandler.constructVPTokenForSigning(credentialsMap: verifiableCredentials, holder: "holder")
        let responseUri = "https://mock-verifier.com"
        mockNetworkManager.setMockResponse(for: responseUri, responseBody: "sending is success in AuthorizationResponseTests")
        let mockVPResponsesMetadata = [FormatType.ldp_vc : LdpVPResponseMetadata(
            jws: "testJWS",
            signatureAlgorithm: "ES256",
            publicKey: "testPublicKey",
            domain: "testDomain"
        )]
        _ =  try authorizationResponseHandler.constructVPTokenForSigning(credentialsMap: verifiableCredentials, holder: "holder")
        
        let result = try await authorizationResponseHandler.shareVP(authorizationRequest: mockAuthorizationRequestObjectWithDirectPostResponseMode, vpResponsesMetadata: mockVPResponsesMetadata, responseUri: responseUri)
        
        XCTAssertEqual("sending is success in AuthorizationResponseTests", result)
        let recordedRequest = mockNetworkManager.recordedRequests[responseUri]!
        let decodedPresentationSubmission = decodeQueryValue((recordedRequest.requestBody?["presentation_submission"])!)
        let decodedVpToken = decodeQueryValue((recordedRequest.requestBody?["vp_token"])!)
        XCTAssertTrue(recordedRequest.requestBody?.keys.count == 3)
        compareJsonStrings( "{\"definition_id\":\"vp_presentation_definition\",\"descriptor_map\":[{\"path_nested\":{\"path\":\"$.verifiableCredential[0]\",\"id\":\"input_descriptor1\",\"format\":\"ldp_vp\"},\"format\":\"ldp_vp\",\"id\":\"input_descriptor1\",\"path\":\"$\"},{\"format\":\"ldp_vp\",\"id\":\"input_descriptor1\",\"path_nested\":{\"id\":\"input_descriptor1\",\"format\":\"ldp_vp\",\"path\":\"$.verifiableCredential[1]\"},\"path\":\"$\"},{\"format\":\"ldp_vp\",\"id\":\"input_descriptor2\",\"path\":\"$\",\"path_nested\":{\"format\":\"ldp_vp\",\"path\":\"$.verifiableCredential[2]\",\"id\":\"input_descriptor2\"}}]}", decodedPresentationSubmission, strict: false)
        compareJsonStrings("{\r\n  \"proof\" : {\r\n    \"challenge\" : \"nonce\",\r\n    \"jws\" : \"testJWS\",\r\n    \"verificationMethod\" : \"testPublicKey\",\r\n    \"domain\" : \"testDomain\",\r\n    \"type\" : \"ES256\",\r\n    \"proofPurpose\" : \"authentication\"\r\n  },\r\n  \"type\" : [\r\n    \"VerifiablePresentation\"\r\n  ],\r\n  \"@context\" : [\r\n    \"https:\\/\\/www.w3.org\\/2018\\/credentials\\/v1\"\r\n  ],\r\n  \"holder\" : \"holder\",\r\n  \"verifiableCredential\" : [\r\n    \"cred1\",\r\n    \"cred3\",\r\n    \"cred3\"\r\n  ]\r\n}", decodedVpToken, strict: false)
        XCTAssertEqual("state", recordedRequest.requestBody?["state"])
    }
    
    func testShareVPThrowErrorWhenResponseTypeIsNotSupportedByLibrary() async  {
        let authorizationRequest = getMockAuthorizationRequest(responseType: "fragment")
        let authorizationResponseHandler = AuthorizationResponseHandler(networkManager: mockNetworkManager)

        do {
            _ = try await authorizationResponseHandler.shareVP(authorizationRequest: authorizationRequest, vpResponsesMetadata: vpResponsesMetaData, responseUri: "https://client.example.org/cb")
            XCTFail("Response type not supported error should have been thrown but did not get error")
        } catch {
            XCTAssertEqual("response type - fragment is not supported", error.localizedDescription)
        }
    }
    
    func testShareVPThrowErrorWhenRespectiveCredentialFormatIsNotAvailableInVpTokensForSigning() async  {
        let authorizationRequest = getMockAuthorizationRequest()
        let authorizationResponseHandler = AuthorizationResponseHandler(networkManager: mockNetworkManager)
        //constructVPTokenForSigning returns error as empty credentialsMap is passed, so vpTokensForSigning field is empty dictionary
        do{_ =  try authorizationResponseHandler.constructVPTokenForSigning(credentialsMap: [:], holder: "holder")}catch {}

        do {
            _ = try await authorizationResponseHandler.shareVP(authorizationRequest: authorizationRequest, vpResponsesMetadata: vpResponsesMetaData, responseUri: "https://client.example.org/cb")
            XCTFail("Response type not supported error should have been thrown but did not get error")
        } catch {
            XCTAssertEqual("unable to find the related credential format - ldp_vc in the vpTokensForSigning map", error.localizedDescription)
        }
    }
    
    func testShareVPThrowErrorWhenVerifiableCredentialsAreNotPassedAsStringInLdpVcs() async  {
        let authorizationRequest = getMockAuthorizationRequest()
        let authorizationResponseHandler = AuthorizationResponseHandler(networkManager: mockNetworkManager)
        
        XCTAssertThrowsError(try authorizationResponseHandler.constructVPTokenForSigning(credentialsMap: ["input1": [.ldp_vc : [1,2]]], holder: "holder")) { error in
            XCTAssertEqual("ldp_vc credentials are not passed in string format", error.localizedDescription)
        }
    }
}
