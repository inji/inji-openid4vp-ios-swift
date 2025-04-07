import Foundation
import XCTest
@testable import OpenID4VP

class DidClientIdSchemeAuthorizationRequestTests : XCTestCase {
    let mockNetworkManager: MockNetworkManager! = MockNetworkManager()
    let mockSetResponseUri: (String) -> Void = { value in
    }
    
    func testShouldThrowErrorWhenRequestUriIsNotAvailableInAuthorizationRequest() async {
        let authorizationRequestByValue: [String : Any] = createAuthorizationRequest(paramList: authRequestWithDidByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientId)) as [String : Any]
        let didSchemeAuthRequestHandler = DidSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestByValue, setResponseUri: mockSetResponseUri, networkManager: mockNetworkManager)
    
        do{
            try await didSchemeAuthRequestHandler.validateRequestUriResponse(requestUriResponse: nil)
            XCTFail("Expected error to be thrown but it did not happen")
        } catch {
            XCTAssertEqual("Missing Input: request_uri param is required", error.localizedDescription)
        }
    }
    
    func testShouldThrowErrorWhenAuthRequestObtainedByReferenceIsNotJWT() async {
        let url: URL = URL(string: "https://mock-verifier.com/verifier/get-auth-request-obj")!
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientId)) as [String : Any]
        
        let didSchemeAuthRequestHandler = DidSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParametersByReference, setResponseUri: mockSetResponseUri, networkManager: mockNetworkManager)
        let requestUriResponse = createNetworkResponse("non-jwt", httpUrlResponse: HTTPURLResponse(url: url, statusCode: 200, httpVersion: "", headerFields: ["Content-Type": "application/oauth-authz-req+jwt"])!)
        
        do{
            try await didSchemeAuthRequestHandler.validateRequestUriResponse(requestUriResponse: requestUriResponse)
            XCTFail("Expected error to be thrown but it did not happen")
        } catch {
            XCTAssertEqual("Authorization Request must be signed and contain JWT for given client_id_scheme - did", error.localizedDescription)
        }
    }
    
    func testShouldThrowErrorWhenAuthRequestObtainedByReferenceDoesNotContainContentTypeFieldItselfInHeader() async {
        let url: URL = URL(string: "https://mock-verifier.com/verifier/get-auth-request-obj")!
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientId)) as [String : Any]
        let didSchemeAuthRequestHandler = DidSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParametersByReference, setResponseUri: mockSetResponseUri, networkManager: mockNetworkManager)
        let requestUriResponse = createNetworkResponse("non-jwt", httpUrlResponse: HTTPURLResponse(url: url, statusCode: 200, httpVersion: "", headerFields: [:])!)
        
        do{
            try await didSchemeAuthRequestHandler.validateRequestUriResponse(requestUriResponse: requestUriResponse)
            XCTFail("Expected error to be thrown but it did not happen")
        } catch {
            XCTAssertEqual("Authorization Request must be signed and contain JWT for given client_id_scheme - did", error.localizedDescription)
        }
    }
    
    func testShouldThrowErrorWhenAuthRequestsAlgObtainedByReferenceDoesNotMatchWithWalletMetadata() async {
        let url: URL = URL(string: "https://mock-verifier.com/verifier/get-auth-request-obj")!
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientId)) as [String : Any]
        let didSchemeAuthRequestHandler = DidSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParametersByReference, walletMetadata: walletMetadata, setResponseUri: mockSetResponseUri, networkManager: mockNetworkManager)
        didSchemeAuthRequestHandler.shouldValidateWithWalletMetadata = true
        let requestUriResponse = createNetworkResponse("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ10.SflK5c", httpUrlResponse: HTTPURLResponse(url: url, statusCode: 200, httpVersion: "", headerFields: ["Content-Type": "application/oauth-authz-req+jwt"]))
        
        do{
            try await didSchemeAuthRequestHandler.validateRequestUriResponse(requestUriResponse: requestUriResponse)
            XCTFail("Expected error to be thrown but it did not happen")
        } catch {
            XCTAssertEqual("request_object_signing_alg is not supported by wallet", error.localizedDescription)
        }
    }
    
    func testShouldThrowErrorWhenAuthRequestObtainedByReferenceDoesNotContainJWTContentTypeInHeader() async {
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientId)) as [String : Any]
        let didSchemeAuthRequestHandler = DidSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParametersByReference, setResponseUri: mockSetResponseUri, networkManager: mockNetworkManager)
        
        do{
            try await didSchemeAuthRequestHandler.fetchAuthorizationRequest()
            XCTFail("Expected error to be thrown but it did not happen")
        } catch {
            XCTAssertEqual("Authorization Request must be signed and contain JWT for given client_id_scheme - did", error.localizedDescription)
        }
    }
    
    func testProcessingWalletMetadataSuccessfully() async{
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, [
            "client_id": "mock-client",
        ])) as [String : Any]
        let didScheme = DidSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: walletMetadata, setResponseUri: mockSetResponseUri, networkManager: mockNetworkManager!)
            
        let processedMetadata = didScheme.process(walletMetadata: walletMetadata)
        
        assertDictionariesEqual(expected: convertToDictionary(object: walletMetadata)!, actual: convertToDictionary(object: processedMetadata))
    }
    
    func testFetchingHeadersForDIDClientIdSchemeSuccessfully() async{
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithDidByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, [
            "client_id": "mock-client",
        ])) as [String : Any]
        let preRegistered = DidSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: walletMetadata, setResponseUri: mockSetResponseUri, networkManager: mockNetworkManager!)
        
        let expectedHeader =
        [Header.contentType.rawValue: ContentTypes.applicationFormUrlEncoded.rawValue,
         Header.accept.rawValue: ContentTypes.applicationJwt.rawValue]
            
        let header = preRegistered.getHeadersForAuthorizationRequestUri()
        
        assertDictionariesEqual(expected: expectedHeader, actual: header)
    }
}
