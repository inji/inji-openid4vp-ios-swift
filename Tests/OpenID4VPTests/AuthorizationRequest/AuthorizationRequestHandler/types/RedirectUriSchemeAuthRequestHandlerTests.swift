import Foundation
import XCTest
@testable import OpenID4VP


class RedirectUriSchemeAuthRequestHandlerTests : XCTestCase {
    let mockNetworkManager: MockNetworkManager! = MockNetworkManager()
    let mockSetResponseUri: (String) -> Void = { value in
    }
    let requestUri: URL = URL(string: "https://mock-verifier.com/verifier/get-auth-request-obj")!
    
    func setup(){
        super.setUp()
        mockNetworkManager.clearMockResponses()
    }
    
    //Fetch authorization request
    func testShouldThrowErrorWhenAuthRequestObtainedByReferenceIsJWT() async {
        let requestUriResponse =  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfRedirectUri)) as [String:Any]
        let redirectUriSchemeAuthRequestHandler = RedirectUriSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
        redirectUriSchemeAuthRequestHandler.requestUriResponse = createNetworkResponse(requestUriResponse)
        
        do{
            try await redirectUriSchemeAuthRequestHandler.validateRequestUriResponse()
            XCTFail("Expected error to be thrown but it did not happen")
        } catch {
            XCTAssertEqual("Authorization Request must not be signed for given client_id_scheme", error.localizedDescription)
        }
    }
    
    func testShouldThrowErrorWhenAuthRequestObtainedByReferenceIsNotHavingJsonContentType() async {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfRedirectUri)) as [String:Any]
        let redirectUriSchemeAuthRequestHandler = RedirectUriSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
        redirectUriSchemeAuthRequestHandler.requestUriResponse = createNetworkResponse("string-data", httpUrlResponse: HTTPURLResponse(url: requestUri, statusCode: 200, httpVersion: "", headerFields: ["Content-Type":"application/x-www-form-urlencoded"])!)
        
        do{
            try await redirectUriSchemeAuthRequestHandler.validateRequestUriResponse()
            XCTFail("Expected error to be thrown but it did not happen")
        } catch {
            XCTAssertEqual("Authorization Request must not be signed for given client_id_scheme", error.localizedDescription)
        }
    }
    
    func testShouldThrowErrorWhenAuthRequestObtainedByReferenceIsNotHavingContentTypePropertyInHeaders() async {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfRedirectUri)) as [String:Any]
        let redirectUriSchemeAuthRequestHandler = RedirectUriSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
        redirectUriSchemeAuthRequestHandler.requestUriResponse = createNetworkResponse("string-data", httpUrlResponse: HTTPURLResponse(url: requestUri, statusCode: 200, httpVersion: "", headerFields: [:])!)
        
        do{
            try await redirectUriSchemeAuthRequestHandler.validateRequestUriResponse()
            XCTFail("Expected error to be thrown but it did not happen")
        } catch {
            XCTAssertEqual("Authorization Request must not be signed for given client_id_scheme", error.localizedDescription)
        }
    }
    
    func testThrowErrorWhenClientIdIsNotEqualToResponseUriWithDirectPostResponseMode() async{
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfRedirectUri, ["response_uri": "http://invalid-mock-verifier.com"])) as [String : Any]
        let redirectUriSchemeAuthRequestHandler = RedirectUriSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)

        do{
            try await redirectUriSchemeAuthRequestHandler.validateAndParseRequestFields()
            XCTFail("Expected error to be thrown but it did not happen")
        } catch {
            XCTAssertEqual("Invalid Verifier: VP sharing failed: Verifier authentication was unsuccessful.response_uri should be equal to client_id for given client_id_scheme", error.localizedDescription)
        }
    }
    
    func testThrowErrorWhenAuthorizationRequestObjectClientIdIsNotMatchingWithRequestParameterClientIdInDirectPostResponseMode() async {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfRedirectUri, ["response_mode": "fragment","redirect_uri": "http://invalid-mock-verifier.com"])) as [String : Any]
        let redirectUriSchemeAuthRequestHandler = RedirectUriSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)

        do{
            try await redirectUriSchemeAuthRequestHandler.validateAndParseRequestFields()
            XCTFail("Expected error to be thrown but it did not happen")
        } catch {
            XCTAssertEqual("Given response_mode Optional(\"fragment\") is not supported", error.localizedDescription)
        }
    }
}
