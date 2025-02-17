import Foundation
import XCTest
@testable import OpenID4VP

class RedirectUriSchemeAuthRequestHandlerTests : XCTestCase {
    let mockNetworkManager: MockNetworkManager! = MockNetworkManager()
    let mockSetResponseUri: (String) -> Void = { value in
    }
    
    func testShouldThrowErrorWhenAuthRequestObtainedByReferenceIsSigned() async {
        mockNetworkManager.setMockResponse(for: URL(string: "https://mock-verifier.com/verifier/get-auth-request-obj")!,response: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
        let redirectUriSchemeAuthRequestHandler = try! getAuthRequestHandler( trustedVerifiers: [], authRequestParams: createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfRedirectUri)), shouldValidateClient: false, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
        
        do{
            try await redirectUriSchemeAuthRequestHandler.gatherAuthRequest()
            XCTFail("Expected error to be thrown but it did not happen")
        } catch {
            XCTAssertEqual("Authorization Request must not be signed for given client_id_scheme", error.localizedDescription)
        }
    }
    
    func testThrowErrorWhenAuthRequestWhenClientIdIsNotEqualToResponseUriWithDirectPostResponseMode() async{
        let redirectUriSchemeAuthRequestHandler = try! getAuthRequestHandler( trustedVerifiers: [], authRequestParams: createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue.map { $0 == AuthorizationRequestFieldConstants.redirectUri.rawValue ? AuthorizationRequestFieldConstants.responseUri.rawValue : $0 } , requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfRedirectUri, ["response_mode":"direct_post", "response_uri": "https://some-other.com"])), shouldValidateClient: false, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
        
        do{
            try await redirectUriSchemeAuthRequestHandler.validateAndParseRequestFields()
            XCTFail("Expected error to be thrown but it did not happen")
        } catch {
            XCTAssertEqual("An unexpected exception occurred: exception type: invalidVerifierRedirectUri", error.localizedDescription)
        }
    }
    
    func testThrowErrorWhenAuthRequestWhenClientIdIsNotEqualToResponseUriWithDirectPostJwtResponseMode() async{
        let redirectUriSchemeAuthRequestHandler = try! getAuthRequestHandler( trustedVerifiers: [], authRequestParams: createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue.map { $0 == AuthorizationRequestFieldConstants.redirectUri.rawValue ? AuthorizationRequestFieldConstants.responseUri.rawValue : $0 } , requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfRedirectUri, ["response_mode":"direct_post.jwt", "response_uri": "https://some-other.com"])), shouldValidateClient: false, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
        
        do{
            try await redirectUriSchemeAuthRequestHandler.validateAndParseRequestFields()
            XCTFail("Expected error to be thrown but it did not happen")
        } catch {
            XCTAssertEqual("An unexpected exception occurred: exception type: invalidVerifierRedirectUri", error.localizedDescription)
        }
    }
    
    func testThrowErrorWhenAuthRequestWhenClientIdIsNotEqualToRedirectUriWithFragmentResponseMode() async{
        let redirectUriSchemeAuthRequestHandler = try! getAuthRequestHandler( trustedVerifiers: [], authRequestParams: createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfRedirectUri, ["response_mode":"fragment", "redirect_uri": "https://some-other.com"])), shouldValidateClient: false, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
        
        do{
            try await redirectUriSchemeAuthRequestHandler.validateAndParseRequestFields()
            XCTFail("Expected error to be thrown but it did not happen")
        } catch {
            XCTAssertEqual("An unexpected exception occurred: exception type: invalidVerifierRedirectUri", error.localizedDescription)
        }
    }
}
