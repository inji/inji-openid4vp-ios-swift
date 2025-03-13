import XCTest
@testable import OpenID4VP

final class AuthorizationResponseTests: XCTestCase {
    let mockNetworkManager = MockNetworkManager()
    let verifiableCredentials: [String: [String]] = ["key1": ["cred1", "cred2"], "key2": ["cred3"]]
    
    func testConstructVpForSigning() throws {
        let vpTokenString = try AuthorizationResponse.constructVpForSigning(verifiableCredentials)
        
        let jsonData = Data(vpTokenString.utf8)
        let decodedVpToken = try JSONDecoder().decode(VpTokenForSigning.self, from: jsonData)
        
        XCTAssertEqual(decodedVpToken.verifiableCredential.count, ["cred1", "cred2", "cred3"].count)
        XCTAssertEqual(decodedVpToken.holder, "")
        XCTAssertEqual(decodedVpToken.type, ["VerifiablePresentation"])
        XCTAssertEqual(decodedVpToken.context, ["https://www.w3.org/2018/credentials/v1"])
        XCTAssertNotNil(UUID(uuidString: decodedVpToken.id), "ID should be a valid UUID")
        XCTAssertEqual(AuthorizationResponse.verifiableCredentials, ["key1": ["cred1", "cred2"], "key2": ["cred3"]])
    }
    
    func testShareVPHasThePresentationDefinitionAsExpected() async throws {
        _ = try AuthorizationResponse.constructVpForSigning(verifiableCredentials)
        let responseUri = "https://mock-verifier.com"
        mockNetworkManager.setMockResponse(for: responseUri, responseBody: "sending is success in AuthorizationResponseTests")
        let mockVPResponseMetadata = VPResponseMetadata(
            jws: "testJWS",
            signatureAlgorithm: "ES256",
            publicKey: "testPublicKey",
            domain: "testDomain"
        )
        
        let result = try await AuthorizationResponse.shareVp(vpResponseMetadata: mockVPResponseMetadata, authorizationRequest: mockAuthorizationRequestObjectWithDirectPostResponseMode, responseUri: mockAuthorizationRequestObjectWithDirectPostResponseMode.responseUri!, networkManager: mockNetworkManager)
        
        XCTAssertEqual("sending is success in AuthorizationResponseTests", result)
        let recordedRequest = mockNetworkManager.recordedRequests[responseUri]!
        let decodedPresentationSubmission = decodeQueryValue((recordedRequest.requestBody?["presentation_submission"])!)
        compareJsonStrings( "{\"definition_id\":\"client_id\",\"descriptor_map\":[{\"format\":\"ldp_vp\",\"id\":\"key1\",\"path\":\"$.verifiableCredential[0]\"},{\"id\":\"key1\",\"path\":\"$.verifiableCredential[1]\",\"format\":\"ldp_vp\"},{\"format\":\"ldp_vp\",\"path\":\"$.verifiableCredential[2]\",\"id\":\"key2\"}]}", decodedPresentationSubmission, strict: false)
    }
}
