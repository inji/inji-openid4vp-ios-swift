import Foundation
import XCTest
@testable import OpenID4VP

class DidClientIdSchemeAuthorizationRequestTests : XCTestCase {
    let mockNetworkManager: MockNetworkManager! = MockNetworkManager()
    let mockSetResponseUri: (String) -> Void = { value in
    }
    
    func testShouldThrowErrorWhenRequestUriIsNotAvailableInAuthorizationRequest() async {
        let didSchemeAuthRequestHandler = try! getAuthRequestHandler(trustedVerifiers: [], authRequestParams: createAuthorizationRequest(paramList: authRequestWithDidByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfDid)), shouldValidateClient: false, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
        
        do{
            try await didSchemeAuthRequestHandler.gatherAuthRequest()
            XCTFail("Expected error to be thrown but it did not happen")
        } catch {
            XCTAssertEqual("Missing Input: request_uri param is required", error.localizedDescription)
        }
    }
    
    func testShouldThrowErrorWhenAuthRequestObtainedByReferenceIsNotSigned() async {
        mockNetworkManager.setMockResponse(for: URL(string: "https://mock-verifier.com/verifier/get-auth-request-obj")!,response: "non-jwt")
        let didSchemeAuthRequestHandler = try! getAuthRequestHandler(trustedVerifiers: [], authRequestParams: createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfDid)), shouldValidateClient: false, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
        
        do{
            try await didSchemeAuthRequestHandler.gatherAuthRequest()
            XCTFail("Expected error to be thrown but it did not happen")
        } catch {
            XCTAssertEqual("Authorization Request must be signed and contain JWT for given client_id_scheme", error.localizedDescription)
        }
    }
}
