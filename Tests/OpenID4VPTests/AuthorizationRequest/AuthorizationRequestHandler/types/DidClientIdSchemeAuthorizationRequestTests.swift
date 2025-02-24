import Foundation
import XCTest
@testable import OpenID4VP

class DidClientIdSchemeAuthorizationRequestTests : XCTestCase {
    let mockNetworkManager: MockNetworkManager! = MockNetworkManager()
    let mockSetResponseUri: (String) -> Void = { value in
    }
    
    func testShouldThrowErrorWhenClientIdDoesNotStartWithDid() async{
        let authorizationRequestParametersByReference = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, ["client_id": "sample-client", "client_id_scheme" : "did"])) as [String: Any]
        let didSchemeAuthRequestHandler = DidSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParametersByReference, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
        
        XCTAssertThrowsError(try didSchemeAuthRequestHandler.validateClientId()){ error in
            XCTAssertEqual("Invalid Verifier: VP sharing failed: Verifier authentication was unsuccessful.client ID should start with did prefix if client_id_scheme is did", error.localizedDescription)
        }
    }
    
    func testShouldThrowErrorWhenRequestUriIsNotAvailableInAuthorizationRequest() async {
        let authorizationRequestByValue: [String : Any] = createAuthorizationRequest(paramList: authRequestWithDidByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfDid)) as [String : Any]
        let didSchemeAuthRequestHandler = DidSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestByValue, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
        
        do{
            try await didSchemeAuthRequestHandler.validateRequestUriResponse()
            XCTFail("Expected error to be thrown but it did not happen")
        } catch {
            XCTAssertEqual("Missing Input: request_uri param is required", error.localizedDescription)
        }
    }
    
    func testShouldThrowErrorWhenAuthRequestObtainedByReferenceIsNotJWT() async {
        let url: URL = URL(string: "https://mock-verifier.com/verifier/get-auth-request-obj")!
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfDid)) as [String : Any]
        let didSchemeAuthRequestHandler = DidSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParametersByReference, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
        didSchemeAuthRequestHandler.requestUriResponse = createNetworkResponse("non-jwt", httpUrlResponse: HTTPURLResponse(url: url, statusCode: 200, httpVersion: "", headerFields: ["Content-Type": "application/oauth-authz-req+jwt"])!)
        
        do{
            try await didSchemeAuthRequestHandler.validateRequestUriResponse()
            XCTFail("Expected error to be thrown but it did not happen")
        } catch {
            XCTAssertEqual("Authorization Request must be signed and contain JWT for given client_id_scheme - did", error.localizedDescription)
        }
    }
    
    func testShouldThrowErrorWhenAuthRequestObtainedByReferenceDoesNotContainContentTypeFieldItselfInHeader() async {
        let url: URL = URL(string: "https://mock-verifier.com/verifier/get-auth-request-obj")!
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfDid)) as [String : Any]
        let didSchemeAuthRequestHandler = DidSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParametersByReference, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
        didSchemeAuthRequestHandler.requestUriResponse = createNetworkResponse("non-jwt", httpUrlResponse: HTTPURLResponse(url: url, statusCode: 200, httpVersion: "", headerFields: [:])!)
        
        do{
            try await didSchemeAuthRequestHandler.validateRequestUriResponse()
            XCTFail("Expected error to be thrown but it did not happen")
        } catch {
            XCTAssertEqual("Authorization Request must be signed and contain JWT for given client_id_scheme - did", error.localizedDescription)
        }
    }
    
    func testShouldThrowErrorWhenAuthRequestObtainedByReferenceDoesNotContainJWTContentTypeInHeader() async {
        let url: URL = URL(string: "https://mock-verifier.com/verifier/get-auth-request-obj")!
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfDid)) as [String : Any]
        let didSchemeAuthRequestHandler = DidSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParametersByReference, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
        didSchemeAuthRequestHandler.requestUriResponse = createNetworkResponse("non-jwt", httpUrlResponse: HTTPURLResponse(url: url, statusCode: 200, httpVersion: "", headerFields: ["Content-Type": "application/json"])!)
        
        do{
            try await didSchemeAuthRequestHandler.fetchAuthorizationRequest()
            XCTFail("Expected error to be thrown but it did not happen")
        } catch {
            XCTAssertEqual("Authorization Request must be signed and contain JWT for given client_id_scheme - did", error.localizedDescription)
        }
    }
}
