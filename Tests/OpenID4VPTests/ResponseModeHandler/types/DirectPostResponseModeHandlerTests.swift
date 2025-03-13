import XCTest
@testable import OpenID4VP

final class DirectPostResponseModeHandlerTests: XCTestCase {
    private let mockVPToken = VPToken(context: ["context"], type: ["typ1"], verifiableCredential: ["VC1"], id: "identifier", holder: "holder", proof: Proof(type: "Ed25519Signature2018", created: "2021-03-19T15:30:15Z", challenge: "n-0S6_WzA2Mj", domain: "https://client.example.org/cb", jws: "eyJhbG...IAoDA", proofPurpose: .vpProofPurpose, verificationMethod: "did:example:holder#key-1"))
    private let mockPresentationSubmission = PresentationSubmission(definition_id: "client-identifier", descriptor_map: [DescriptorMap(id: "input_1", format: .ldp_vp, path: "$.verifiableCredential[0]")])
    private let mockNetworkManager = MockNetworkManager()
    private let responseUri = "https://mock-verifier.com"

    func testValidationClientMetadatadaNotThrowErrorForDirectPost() throws {
        let directPostAuthorizationResponseModeHandler = DirectPostResponseModeHandler()
        
        XCTAssertNoThrow(try directPostAuthorizationResponseModeHandler.validate(clientMetadata: mockClientMetadataObject))
    }
    
    func testSendAuthorizationResponseForDirectPostResponseMode()  async throws {
        let directPostAuthorizationResponseModeHandler = DirectPostResponseModeHandler()
        mockNetworkManager.setMockResponse(for: responseUri, responseBody: "Response has been shared successfully here.")
        
        do {
            let result = try await directPostAuthorizationResponseModeHandler.sendAuthorizationResponse(vpToken: mockVPToken, authorizationRequest: mockAuthorizationRequestObjectWithDirectPostResponseMode, presentationSubmission: mockPresentationSubmission, state: mockAuthorizationRequestObjectWithDirectPostResponseMode.state, url: mockAuthorizationRequestObjectWithDirectPostResponseMode.responseUri!, networkManager: mockNetworkManager)
            
            let recordedRequest = mockNetworkManager.recordedRequests[responseUri]
            XCTAssertEqual(HTTP_METHOD.POST, recordedRequest?.requestMethod)
            XCTAssertTrue(recordedRequest?.requestBody?.keys.count == 3)
            XCTAssertTrue(((recordedRequest?.requestBody?.keys.allSatisfy(["vp_token","presentation_submission","state"].contains(_:))) != nil))
            assertDictionariesEqual(expected: ["Content-Type":ContentTypes.applicationFormUrlEncoded], actual: recordedRequest?.requestHeaders)
            XCTAssertEqual("Response has been shared successfully here.", result)
        }
    }
}
