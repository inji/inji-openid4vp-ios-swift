import XCTest
@testable import OpenID4VP

final class AuthorizationResponseHandlerTests: XCTestCase {
    let mockNetworkManager = MockNetworkManager()
    let verifiableCredentials: [String: [FormatType: [Any]]] = ["input_descriptor1": [.ldp_vc: ["cred1", "cred3"]], "input_descriptor2": [.ldp_vc: ["cred3"]]]
    
    func testConstructVpForSigning() throws {
        let authorizationResponseHandler: AuthorizationResponseHandler = AuthorizationResponseHandler(networkManager: mockNetworkManager)
        let vpTokens: [FormatType: VPTokenForSigning] = try authorizationResponseHandler.constructVPTokenForSigning(credentialsMap: verifiableCredentials, holder: "holder")
        
        let ldpVpToken = vpTokens[.ldp_vc] as! LdpVPTokenForSigning
        XCTAssertEqual(ldpVpToken.verifiableCredential.count, ["cred1", "cred2", "cred3"].count)
        XCTAssertEqual(ldpVpToken.holder, "holder")
        XCTAssertEqual(ldpVpToken.type, ["VerifiablePresentation"])
        XCTAssertEqual(ldpVpToken.context, ["https://www.w3.org/2018/credentials/v1"])
        XCTAssertNotNil(UUID(uuidString: ldpVpToken.id), "ID should be a valid UUID")
    }
    
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
        compareJsonStrings( "{\"definition_id\":\"vp_presentation_definition\",\"descriptor_map\":[{\"path_nested\":{\"path\":\"$.verifiableCredential[0]\",\"id\":\"input_descriptor1\",\"format\":\"ldp_vp\"},\"format\":\"ldp_vp\",\"id\":\"input_descriptor1\",\"path\":\"$\"},{\"format\":\"ldp_vp\",\"id\":\"input_descriptor1\",\"path_nested\":{\"id\":\"input_descriptor1\",\"format\":\"ldp_vp\",\"path\":\"$.verifiableCredential[1]\"},\"path\":\"$\"},{\"format\":\"ldp_vp\",\"id\":\"input_descriptor2\",\"path\":\"$\",\"path_nested\":{\"format\":\"ldp_vp\",\"path\":\"$.verifiableCredential[2]\",\"id\":\"input_descriptor2\"}}]}", decodedPresentationSubmission, strict: false)
    }
}
