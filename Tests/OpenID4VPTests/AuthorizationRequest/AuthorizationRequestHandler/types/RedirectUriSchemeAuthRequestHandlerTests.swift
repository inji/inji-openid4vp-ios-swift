//import Foundation
//import XCTest
//@testable import OpenID4VP
//
//
//class RedirectUriSchemeAuthRequestHandlerTests : XCTestCase {
//    let mockNetworkManager: MockNetworkManager! = MockNetworkManager()
//    let mockSetResponseUri: (String) -> Void = { value in
//    }
//    let requestUri: URL = URL(string: "https://mock-verifier.com/verifier/get-auth-request-obj")!
//    
//    private var walletMetadata: WalletMetadata!
//    
//    override func setUpWithError() throws {
//        walletMetadata = try createWalletMetadata()
//    }
//    
//    func setup(){
//        super.setUp()
//        mockNetworkManager.clearResponses()
//    }
//    
//    //Fetch authorization request
//    func testShouldThrowErrorWhenAuthRequestObtainedByReferenceIsJWT() async {
//        let requestUriResponse =  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
//        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReferenceDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdDraft23)) as [String:Any]
//        let redirectUriSchemeAuthRequestHandler = RedirectUriSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil, setResponseUri: mockSetResponseUri, networkManager: mockNetworkManager)
//        
//        await assertAsyncThrowsError(try await redirectUriSchemeAuthRequestHandler.validateRequestUriResponse(requestUriResponse: createNetworkResponse(requestUriResponse))) { error in
//            XCTAssertEqual("Authorization Request must not be signed for given client_id_scheme", error.localizedDescription)
//        }
//    }
//    
//    func testShouldThrowErrorWhenAuthRequestObtainedByReferenceIsNotHavingJsonContentType() async {
//        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReferenceDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdDraft23)) as [String:Any]
//        let redirectUriSchemeAuthRequestHandler = RedirectUriSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil, setResponseUri: mockSetResponseUri, networkManager: mockNetworkManager)
//        let requestUriResponse = createNetworkResponse("string-data", httpUrlResponse: HTTPURLResponse(url: requestUri, statusCode: 200, httpVersion: "", headerFields: ["Content-Type":"application/x-www-form-urlencoded"])!)
//        
//        await assertAsyncThrowsError(try await redirectUriSchemeAuthRequestHandler.validateRequestUriResponse(requestUriResponse: requestUriResponse)) { error in
//            XCTAssertEqual("Authorization Request must not be signed for given client_id_scheme", error.localizedDescription)
//        }
//    }
//    
//    func testShouldThrowErrorWhenAuthRequestObtainedByReferenceIsNotHavingContentTypePropertyInHeaders() async {
//        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReferenceDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdDraft23)) as [String:Any]
//        let redirectUriSchemeAuthRequestHandler = RedirectUriSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil, setResponseUri: mockSetResponseUri, networkManager: mockNetworkManager)
//        let requestUriResponse = createNetworkResponse("string-data", httpUrlResponse: HTTPURLResponse(url: requestUri, statusCode: 200, httpVersion: "", headerFields: [:])!)
//
//        await assertAsyncThrowsError(try await redirectUriSchemeAuthRequestHandler.validateRequestUriResponse(requestUriResponse: requestUriResponse)) { error in
//            XCTAssertEqual("Authorization Request must not be signed for given client_id_scheme", error.localizedDescription)
//        }
//    }
//    
//    /// validate and parse request fields
//    
//    func testThrowNoErrorForValidAuthorizationRequestWhileValidateAndParseRequestFields() async {
//        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdDraft23)) as [String : Any]
//        let redirectUriSchemeAuthRequestHandler = RedirectUriSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil, setResponseUri: mockSetResponseUri, networkManager: mockNetworkManager)
//
//        await assertAsyncNoThrowsError(try await redirectUriSchemeAuthRequestHandler.validateAndParseRequestFields())
//    }
//    
//    func testThrowErrorWhenClientIdIsNotEqualToResponseUriWithDirectPostResponseMode() async{
//        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdDraft23, ["response_uri": "http://invalid-mock-verifier.com"])) as [String : Any]
//        let redirectUriSchemeAuthRequestHandler = RedirectUriSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil, setResponseUri: mockSetResponseUri, networkManager: mockNetworkManager)
//
//        await assertAsyncThrowsError(try await redirectUriSchemeAuthRequestHandler.validateAndParseRequestFields()) { error in
//            XCTAssertEqual("Invalid Verifier: VP sharing failed: Verifier authentication was unsuccessful.response_uri should be equal to client_id for given client_id_scheme", error.localizedDescription)
//        }
//    }
//    
//    func testThrowErrorWhenAuthorizationRequestObjectClientIdIsNotMatchingWithRequestParameterClientIdInDirectPostResponseMode() async {
//        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdDraft23, ["response_mode": "fragment","redirect_uri": "http://invalid-mock-verifier.com"])) as [String : Any]
//        let redirectUriSchemeAuthRequestHandler = RedirectUriSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil, setResponseUri: mockSetResponseUri, networkManager: mockNetworkManager)
//
//        await assertAsyncThrowsError(try await redirectUriSchemeAuthRequestHandler.validateAndParseRequestFields()) { error in
//            XCTAssertEqual("Given response_mode - fragment is not supported", error.localizedDescription)
//        }
//    }
//    
//    func testSuccessfulValidationOfRequestUriResponseWhenResponseModeIsDirectPost() async {
//        let requestUriResponse: String = createAuthorizationRequestObject(clientIdScheme: .redirectUri, authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue,redirectUriSchemeClientIdDraft23), applicableFields: authRequestWithRedirectUriByValue)
//
//        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReferenceDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdDraft23)) as [String:Any]
//        let redirectUriSchemeAuthRequestHandler = RedirectUriSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil, setResponseUri: mockSetResponseUri, networkManager: mockNetworkManager)
//
//        await assertAsyncNoThrowsError(try await redirectUriSchemeAuthRequestHandler.validateRequestUriResponse(requestUriResponse: createNetworkResponse(requestUriResponse)))
//    }
//    
//    func testProcessingWalletMetadataSuccessfully() async{
//        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValueDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, [
//            "client_id": "mock-client",
//        ])) as [String : Any]
//        let redirectScheme = RedirectUriSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: walletMetadata, setResponseUri: mockSetResponseUri, networkManager: mockNetworkManager!)
//        
//        var expectedWalletMetadata: WalletMetadata = walletMetadata
//        expectedWalletMetadata.requestObjectSigningAlgValuesSupported = nil
//        
//        let processedMetadata = redirectScheme.process(walletMetadata: walletMetadata)
//        
//        assertDictionariesEqual(expected: convertToDictionary(object: expectedWalletMetadata)!, actual: convertToDictionary(object: processedMetadata))
//    }
//    
//    func testFetchingHeadersForRedirectClientIdSchemeSuccessfully() async{
//        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, [
//            "client_id": "mock-client",
//        ])) as [String : Any]
//        let preRegistered = RedirectUriSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: walletMetadata, setResponseUri: mockSetResponseUri, networkManager: mockNetworkManager!)
//        
//        let expectedHeader =
//        [Header.contentType.rawValue: ContentTypes.applicationFormUrlEncoded.rawValue,
//         Header.accept.rawValue: ContentTypes.applicationJson.rawValue]
//            
//        let header = preRegistered.getHeadersForAuthorizationRequestUri()
//        
//        assertDictionariesEqual(expected: expectedHeader, actual: header)
//    }
//}
