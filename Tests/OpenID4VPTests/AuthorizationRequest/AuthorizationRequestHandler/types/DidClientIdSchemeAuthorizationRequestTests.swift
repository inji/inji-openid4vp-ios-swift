import Foundation
import XCTest
@testable import OpenID4VP

class DidClientIdSchemeAuthorizationRequestTests : XCTestCase {
    let mockNetworkManager: MockNetworkManager! = MockNetworkManager()
    let mockSetResponseUri: (String) -> Void = { value in
    }
    
    func testShouldThrowErrorWhenRequestUriIsInvalid() async{
        let authorizationRequestParametersByReference = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfPreRegistered,["request_uri": "http://invalid-mock-verifier.com"])) as [String: Any]
        let didSchemeAuthRequestHandler = try! getAuthorizationRequestHandler(trustedVerifiers: [], authorizationRequestParameters: authorizationRequestParametersByReference, shouldValidateClient: false, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
        
        do {
            try await didSchemeAuthRequestHandler.fetchAuthRequest()
            XCTFail("request_uri data is not valid error to be thrown but not thrown")
        } catch{
            XCTAssertEqual("request_uri data is not valid", error.localizedDescription)
        }
    }
    
    func testShouldThrowErrorWhenRequestUriIsNotAvailableInAuthorizationRequest() async {
        let didSchemeAuthRequestHandler = try! getAuthorizationRequestHandler(trustedVerifiers: [], authorizationRequestParameters: createAuthorizationRequest(paramList: authRequestWithDidByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfDid)) as [String : Any], shouldValidateClient: false, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
        
        do{
            try await didSchemeAuthRequestHandler.fetchAuthRequest()
            XCTFail("Expected error to be thrown but it did not happen")
        } catch {
            XCTAssertEqual("Missing Input: request_uri param is required", error.localizedDescription)
        }
    }
    
    func testShouldThrowErrorWhenAuthRequestObtainedByReferenceIsNotSigned() async {
        mockNetworkManager.setMockResponse(for: URL(string: "https://mock-verifier.com/verifier/get-auth-request-obj")!,response: "non-jwt")
        let didSchemeAuthRequestHandler = try! getAuthorizationRequestHandler(trustedVerifiers: [], authorizationRequestParameters: createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfDid)) as [String : Any], shouldValidateClient: false, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
        
        do{
            try await didSchemeAuthRequestHandler.fetchAuthRequest()
            XCTFail("Expected error to be thrown but it did not happen")
        } catch {
            XCTAssertEqual("Authorization Request must be signed and contain JWT for given client_id_scheme", error.localizedDescription)
        }
    }
}
