import Foundation
import XCTest
@testable import OpenID4VP


class RedirectUriSchemeAuthRequestHandlerTests : XCTestCase {
    let mockNetworkManager: MockNetworkManager! = MockNetworkManager()
    let mockSetResponseUri: (String) -> Void = { value in
    }
    let requestUri: URL = URL(string: "https://mock-verifier.com/verifier/get-auth-request-obj")!
    
    private var walletMetadata: WalletMetadata!
    
    override func setUpWithError() throws {
        walletMetadata = try createWalletMetadataV2()
    }
    
    func setup(){
        super.setUp()
        mockNetworkManager.clearResponses()
    }
    
    //Fetch authorization request
    func testShouldThrowErrorWhenAuthRequestObtainedByReferenceIsJWT() async {
        let requestUriResponse =  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReferenceDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdDraft23)) as [String:Any]
        let redirectUriSchemeAuthRequestHandler = RedirectUriSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil, setResponseUri: mockSetResponseUri,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        await XCTAssertAsyncThrowsError(try await redirectUriSchemeAuthRequestHandler.validateRequestUriResponse(requestUriResponse: createNetworkResponse(requestUriResponse),walletNonce: "mock-nonce", isMismatchedAcceptableType: true)) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Authorization Request must not be signed for given client_id_scheme",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testShouldThrowErrorWhenAuthRequestObtainedByReferenceIsNotHavingJsonContentType() async {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReferenceDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdDraft23)) as [String:Any]
        let redirectUriSchemeAuthRequestHandler = RedirectUriSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil, setResponseUri: mockSetResponseUri,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        let requestUriResponse = createNetworkResponse("string-data", httpUrlResponse: HTTPURLResponse(url: requestUri, statusCode: 200, httpVersion: "", headerFields: ["Content-Type":"application/x-www-form-urlencoded"])!)
        
        await XCTAssertAsyncThrowsError(try await redirectUriSchemeAuthRequestHandler.validateRequestUriResponse(requestUriResponse: requestUriResponse,walletNonce: "mock-nonce", isMismatchedAcceptableType: true)) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Authorization Request must not be signed for given client_id_scheme",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testShouldThrowErrorWhenAuthRequestObtainedByReferenceIsNotHavingContentTypePropertyInHeaders() async {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReferenceDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdDraft23)) as [String:Any]
        let redirectUriSchemeAuthRequestHandler = RedirectUriSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce",networkManager: mockNetworkManager)
        let requestUriResponse = createNetworkResponse("string-data", httpUrlResponse: HTTPURLResponse(url: requestUri, statusCode: 200, httpVersion: "", headerFields: [:])!)
        
        await XCTAssertAsyncThrowsError(try await redirectUriSchemeAuthRequestHandler.validateRequestUriResponse(requestUriResponse: requestUriResponse,walletNonce: "mock-nonce",isMismatchedAcceptableType: true)) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Authorization Request must not be signed for given client_id_scheme",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    // Support for Authorization request by reference or by value
    
    func testReturnFalseForAuthorizationRequestByReferenceSupport() {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValueDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdDraft23)) as [String : Any]
        let handler = RedirectUriSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil, setResponseUri: mockSetResponseUri,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        XCTAssertFalse(handler.isRequestUriSupported(), "redirect_uri client_id_scheme should not support request by reference")
    }
    
    func testReturnTrueForAuthorizationRequestByValueSupport() {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValueDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdDraft23)) as [String : Any]
        let handler = RedirectUriSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil, setResponseUri: mockSetResponseUri,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        XCTAssertTrue(handler.isRequestObjectSupported(), "redirect_uri client_id_scheme should support request by value")
    }
    
    /// validate and parse request fields
    
    func testThrowNoErrorForValidAuthorizationRequestWhileValidateAndParseRequestFields() async {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdDraft23)) as [String : Any]
        let redirectUriSchemeAuthRequestHandler = RedirectUriSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil, setResponseUri: mockSetResponseUri,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        await XCTAssertAsyncNoThrowsError(try await redirectUriSchemeAuthRequestHandler.validateAndParseRequestFields())
    }
    
    func testThrowErrorWhenClientIdIsNotEqualToResponseUriWithDirectPostResponseMode() async{
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdDraft23, ["response_uri": "http://invalid-mock-verifier.com"])) as [String : Any]
        let redirectUriSchemeAuthRequestHandler = RedirectUriSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce",networkManager: mockNetworkManager)
        
        await XCTAssertAsyncThrowsError(try await redirectUriSchemeAuthRequestHandler.validateAndParseRequestFields()) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "response_uri should be equal to client_id for given client_id_scheme",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testThrowErrorWhenAuthorizationRequestObjectClientIdIsNotMatchingWithRequestParameterClientIdInDirectPostResponseMode() async {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdDraft23, [AuthorizationRequestFieldConstants.responseMode.rawValue: "fragment","redirect_uri": "http://invalid-mock-verifier.com"])) as [String : Any]
        let redirectUriSchemeAuthRequestHandler = RedirectUriSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil, setResponseUri: mockSetResponseUri,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        await XCTAssertAsyncThrowsError(try await redirectUriSchemeAuthRequestHandler.validateAndParseRequestFields()) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Given response_mode - fragment is not supported",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testSuccessfulValidationOfRequestUriResponseWhenResponseModeIsDirectPost() async {
        let requestUriResponse: String = createAuthorizationRequestObject(clientIdScheme: .redirectUri, authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue,redirectUriSchemeClientIdDraft23), applicableFields: authRequestWithRedirectUriByValue)
        
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReferenceDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdDraft23)) as [String:Any]
        let redirectUriSchemeAuthRequestHandler = RedirectUriSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil, setResponseUri: mockSetResponseUri,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        await XCTAssertAsyncNoThrowsError(try await redirectUriSchemeAuthRequestHandler.validateRequestUriResponse(requestUriResponse: createNetworkResponse(requestUriResponse),walletNonce: "mock-nonce", isMismatchedAcceptableType: false))
    }
    
    func testProcessingWalletMetadataSuccessfully() async{
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValueDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, [
            AuthorizationRequestFieldConstants.clientId.rawValue: "mock-client",
        ])) as [String : Any]
        let redirectScheme = RedirectUriSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: walletMetadata, setResponseUri: mockSetResponseUri,walletNonce: "mock-nonce", networkManager: mockNetworkManager!)
        
        var expectedWalletMetadata: WalletMetadata = walletMetadata
        expectedWalletMetadata.requestObjectSigningAlgValuesSupported = nil
        
        let processedMetadata = redirectScheme.process(walletMetadata: walletMetadata)
        
        assertDictionariesEqual(expected: convertToDictionary(object: expectedWalletMetadata)!, actual: convertToDictionary(object: processedMetadata))
    }
    
    func testFetchingHeadersForRedirectClientIdSchemeSuccessfully() async{
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, [
            AuthorizationRequestFieldConstants.clientId.rawValue: "mock-client",
        ])) as [String : Any]
        let preRegistered = RedirectUriSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: walletMetadata, setResponseUri: mockSetResponseUri,walletNonce: "mock-nonce", networkManager: mockNetworkManager!)
        
        let expectedHeader =
        [Header.contentType.rawValue: ContentTypes.applicationFormUrlEncoded.rawValue,
         Header.accept.rawValue: ContentTypes.applicationJson.rawValue]
        
        let header = preRegistered.getHeadersForAuthorizationRequestUri()
        
        assertDictionariesEqual(expected: expectedHeader, actual: header)
    }
    
    func testShouldThrowErrorWhenResponseUriNotEqualToClientId() async {
        let mockClientId = "http://mock-client.com"
        let invalidResponseUri = "http://invalid-mock-client.com"
        
        let authParams: [String: Any] = createAuthorizationRequest(
            paramList: authRequestWithRedirectUriByValue,
            requestParams: mergeMaps(
                authorizationRequestParamsWithValue,
                redirectUriSchemeClientIdDraft23,
                [
                    "client_id": mockClientId,
                    "client_id_scheme": "redirect_uri",
                    "response_mode": "direct_post",
                    "response_uri": invalidResponseUri,
                    "scope": "openid",
                    "response_type": "vp_token",
                    "nonce": "123456"
                ]
            )
        ) as [String : Any]
        
        let redirectUriSchemeHandler = RedirectUriSchemeAuthorizationRequestHandler(
            authorizationRequestParameters: authParams,
            walletMetadata: walletMetadata,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager
        )
        
        await XCTAssertAsyncThrowsError(
            try await redirectUriSchemeHandler.validateAndParseRequestFields()
        ) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "response_uri should be equal to client_id for given client_id_scheme",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testShouldThrowErrorWhenRequestUriResponseWalletNonceDoesNotMatchWithTheWalletNonceSentDuringRequest() async {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReferenceDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdDraft23, [AuthorizationRequestFieldConstants.requestUriMethod.rawValue: "post"])) as [String:Any]
        let redirectUriSchemeAuthRequestHandler = RedirectUriSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil, setResponseUri: mockSetResponseUri,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        let requestUriResponse = createNetworkResponse(createAuthorizationRequestObject(clientIdScheme: .redirectUri, authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdDraft23, [AuthorizationRequestFieldConstants.walletNonce.rawValue: "hacker-nonce"])), httpUrlResponse: HTTPURLResponse(url: requestUri, statusCode: 200, httpVersion: "", headerFields: ["Content-Type": "application/json"])!)
        await XCTAssertAsyncThrowsError(try await redirectUriSchemeAuthRequestHandler.validateRequestUriResponse(requestUriResponse: requestUriResponse,walletNonce: "mock-nonce", isMismatchedAcceptableType: false)) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "wallet_nonce provided in the authorization request is not the same as shared by wallet",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    
}
