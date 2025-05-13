import XCTest
@testable import OpenID4VP

final class DirectPostResponseModeHandlerTests: XCTestCase {
    let mockVPTokens = VPTokenType.vpTokenElement(LdpVPToken(context: ["context"], type: ["typ1"], verifiableCredential: [ldpVC().mapValues { AnyCodable($0) }], id: "identifier", holder: "holder", proof: Proof(type: "Ed25519Signature2018", created: "2021-03-19T15:30:15Z", challenge: "n-0S6_WzA2Mj", domain: "https://client.example.org/cb", jws: "eyJhbG...IAoDA", proofPurpose: .vpProofPurpose, verificationMethod: "did:example:holder#key-1")))
    
    let mockPresentationSubmission = PresentationSubmission(definitionId: "client-identifier", descriptorMap: [DescriptorMap(id: "input_1", format: .ldp_vp, path: "$", pathNested: PathNested(id: "input_1", format: .ldp_vc, path: "$.verifiableCredential[0]"))])
    
    private let mockNetworkManager = MockNetworkManager()
    private let responseUri = "https://mock-verifier.com"
    
    private var walletMetadata: WalletMetadata!
    
    override func setUpWithError() throws {
        walletMetadata = try createWalletMetadata()
    }
    
    
    func testValidationClientMetadatadaNotThrowErrorForDirectPost() throws {
        let directPostAuthorizationResponseModeHandler = DirectPostResponseModeHandler()
        
        XCTAssertNoThrow(try directPostAuthorizationResponseModeHandler.validate(clientMetadata: mockClientMetadataObject, walletMetadata: walletMetadata, shouldValidateWithWalletMetadata: true))
    }
    
    func testSendAuthorizationResponseForDirectPostResponseMode()  async throws {
        let directPostAuthorizationResponseModeHandler = DirectPostResponseModeHandler()
        let authorizationResponse: AuthorizationResponse = AuthorizationResponse(vpToken: mockVPTokens, presentationSubmission: mockPresentationSubmission, state: "state")
        mockNetworkManager.clearResponses()
        mockNetworkManager.setMockResponse(for: responseUri, responseBody: "Response has been shared successfully here.")
        
        do {
            let result = try await directPostAuthorizationResponseModeHandler.sendAuthorizationResponse(authorizationRequest: mockAuthorizationRequestObjectWithDirectPostResponseMode, authorizationResponse: authorizationResponse, url: mockAuthorizationRequestObjectWithDirectPostResponseMode.responseUri!, networkManager: mockNetworkManager,
                producerInfo: "wallet-nonce",
                recepientInfo: "verifier-nonce")
            
            let recordedRequest = mockNetworkManager.recordedRequests[responseUri]
            XCTAssertEqual(HttpMethod.post, recordedRequest?.requestMethod)
            XCTAssertTrue(recordedRequest?.requestBody?.keys.count == 3)
            XCTAssertTrue(((recordedRequest?.requestBody?.keys.allSatisfy(["vp_token","presentation_submission","state"].contains(_:))) != nil))
            assertDictionariesEqual(expected: ["Content-Type":ContentTypes.applicationFormUrlEncoded.rawValue], actual: recordedRequest?.requestHeaders)
            XCTAssertEqual("Response has been shared successfully here.", result)
        }
    }
}
