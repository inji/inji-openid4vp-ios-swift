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
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientId)) as [String:Any]
        let redirectUriSchemeAuthRequestHandler = RedirectUriSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil, setResponseUri: mockSetResponseUri, networkManager: mockNetworkManager)
        
        do{
            try await redirectUriSchemeAuthRequestHandler.validateRequestUriResponse(requestUriResponse: createNetworkResponse(requestUriResponse))
            XCTFail("Expected error to be thrown but it did not happen")
        } catch {
            XCTAssertEqual("Authorization Request must not be signed for given client_id_scheme", error.localizedDescription)
        }
    }
    
    func testShouldThrowErrorWhenAuthRequestObtainedByReferenceIsNotHavingJsonContentType() async {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientId)) as [String:Any]
        let redirectUriSchemeAuthRequestHandler = RedirectUriSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil, setResponseUri: mockSetResponseUri, networkManager: mockNetworkManager)
        let requestUriResponse = createNetworkResponse("string-data", httpUrlResponse: HTTPURLResponse(url: requestUri, statusCode: 200, httpVersion: "", headerFields: ["Content-Type":"application/x-www-form-urlencoded"])!)
        
        do{
            try await redirectUriSchemeAuthRequestHandler.validateRequestUriResponse(requestUriResponse: requestUriResponse)
            XCTFail("Expected error to be thrown but it did not happen")
        } catch {
            XCTAssertEqual("Authorization Request must not be signed for given client_id_scheme", error.localizedDescription)
        }
    }
    
    func testShouldThrowErrorWhenAuthRequestObtainedByReferenceIsNotHavingContentTypePropertyInHeaders() async {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientId)) as [String:Any]
        let redirectUriSchemeAuthRequestHandler = RedirectUriSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil, setResponseUri: mockSetResponseUri, networkManager: mockNetworkManager)
        let requestUriResponse = createNetworkResponse("string-data", httpUrlResponse: HTTPURLResponse(url: requestUri, statusCode: 200, httpVersion: "", headerFields: [:])!)
        
        do{
            try await redirectUriSchemeAuthRequestHandler.validateRequestUriResponse(requestUriResponse: requestUriResponse)
            XCTFail("Expected error to be thrown but it did not happen")
        } catch {
            XCTAssertEqual("Authorization Request must not be signed for given client_id_scheme", error.localizedDescription)
        }
    }
    
    /// validate and parse request fields
    
    func testThrowNoErrorForValidAuthorizationRequestWhileValidateAndParseRequestFields() async {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientId)) as [String : Any]
        let redirectUriSchemeAuthRequestHandler = RedirectUriSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil, setResponseUri: mockSetResponseUri, networkManager: mockNetworkManager)
        
        do{
            try await redirectUriSchemeAuthRequestHandler.validateAndParseRequestFields()
        } catch {
            XCTFail("Error should not be thrown but error - \(error) is captured")
        }
    }
    
    func testThrowErrorWhenClientIdIsNotEqualToResponseUriWithDirectPostResponseMode() async{
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientId, ["response_uri": "http://invalid-mock-verifier.com"])) as [String : Any]
        let redirectUriSchemeAuthRequestHandler = RedirectUriSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil, setResponseUri: mockSetResponseUri, networkManager: mockNetworkManager)
        
        do{
            try await redirectUriSchemeAuthRequestHandler.validateAndParseRequestFields()
            XCTFail("Expected error to be thrown but it did not happen")
        } catch {
            XCTAssertEqual("Invalid Verifier: VP sharing failed: Verifier authentication was unsuccessful.response_uri should be equal to client_id for given client_id_scheme", error.localizedDescription)
        }
    }
    
    func testThrowErrorWhenAuthorizationRequestObjectClientIdIsNotMatchingWithRequestParameterClientIdInDirectPostResponseMode() async {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientId, ["response_mode": "fragment","redirect_uri": "http://invalid-mock-verifier.com"])) as [String : Any]
        let redirectUriSchemeAuthRequestHandler = RedirectUriSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil, setResponseUri: mockSetResponseUri, networkManager: mockNetworkManager)
        
        do{
            try await redirectUriSchemeAuthRequestHandler.validateAndParseRequestFields()
            XCTFail("Expected error to be thrown but it did not happen")
        } catch {
            XCTAssertEqual("Given response_mode - fragment is not supported", error.localizedDescription)
        }
    }
    
    func testSuccessfulWhenAuthorizationRequestObjectClientIdIsNotMatchingWithRequestParameterClientIdInDirectPostResponseMode() async {
        let requestUriResponse: String = createAuthorizationRequestObject(clientIdScheme: .redirectUri, authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue,redirectUriSchemeClientId), applicableFields: authRequestWithRedirectUriByValue)
        
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientId)) as [String:Any]
        let redirectUriSchemeAuthRequestHandler = RedirectUriSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil, setResponseUri: mockSetResponseUri, networkManager: mockNetworkManager)
        
        do{
            try await redirectUriSchemeAuthRequestHandler.validateRequestUriResponse(requestUriResponse: createNetworkResponse(requestUriResponse))
        }catch{
            XCTFail("Error should not be thrown but error - \(error) is captured")
        }
    }
    
    func testProcessingWalletMetadataSuccessfully() async{
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, [
            "client_id": "mock-client",
        ])) as [String : Any]
        let redirectScheme = RedirectUriSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: walletMetadata, setResponseUri: mockSetResponseUri, networkManager: mockNetworkManager!)
        
        var expectedWalletMetadata: WalletMetadata = walletMetadata
        expectedWalletMetadata.requestObjectSigningAlgValuesSupported = nil
        
        let processedMetadata = redirectScheme.process(walletMetadata: walletMetadata)
        
        assertDictionariesEqual(expected: convertToDictionary(object: expectedWalletMetadata)!, actual: convertToDictionary(object: processedMetadata))
    }
    
    func testFetchingHeadersForRedirectClientIdSchemeSuccessfully() async{
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, [
            "client_id": "mock-client",
        ])) as [String : Any]
        let preRegistered = RedirectUriSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: walletMetadata, setResponseUri: mockSetResponseUri, networkManager: mockNetworkManager!)
        
        let expectedHeader =
        [Header.contentType.rawValue: ContentTypes.applicationFormUrlEncoded.rawValue,
         Header.accept.rawValue: ContentTypes.applicationJson.rawValue]
            
        let header = preRegistered.getHeadersForAuthorizationRequestUri()
        
        assertDictionariesEqual(expected: expectedHeader, actual: header)
    }
}
