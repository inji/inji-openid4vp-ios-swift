import Foundation
import XCTest
@testable import OpenID4VP

class DidClientIdSchemeAuthorizationRequestTests : XCTestCase {
    let mockNetworkManager: MockNetworkManager! = MockNetworkManager()
    let mockSetResponseUri: (String) -> Void = { value in
    }
    
    private var walletMetadata: WalletMetadata!
    
    override func setUpWithError() throws {
        walletMetadata = try createWalletMetadata()
    }
    
    func testShouldThrowErrorWhenRequestUriIsNotAvailableInAuthorizationRequest() async {
        let authorizationRequestByValue: [String : Any] = createAuthorizationRequest(paramList: authRequestWithDidByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdDraft23)) as [String : Any]
        let didSchemeAuthRequestHandler = DidSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestByValue, setResponseUri: mockSetResponseUri, networkManager: mockNetworkManager)

        await XCTAssertAsyncThrowsError(try await didSchemeAuthRequestHandler.validateRequestUriResponse(requestUriResponse: nil)) { error in
            XCTAssertEqual("Missing Input: request_uri param is required", error.localizedDescription)
        }
    }

    func testShouldThrowErrorWhenAuthRequestObtainedByReferenceIsNotJWT() async {
        let url: URL = URL(string: "https://mock-verifier.com/verifier/get-auth-request-obj")!
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReferenceDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdDraft23)) as [String : Any]

        let didSchemeAuthRequestHandler = DidSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParametersByReference, setResponseUri: mockSetResponseUri, networkManager: mockNetworkManager)
        let requestUriResponse = createNetworkResponse("non-jwt", httpUrlResponse: HTTPURLResponse(url: url, statusCode: 200, httpVersion: "", headerFields: ["Content-Type": "application/oauth-authz-req+jwt"])!)

        await XCTAssertAsyncThrowsError(try await didSchemeAuthRequestHandler.validateRequestUriResponse(requestUriResponse: requestUriResponse)) { error in
            XCTAssertEqual("Authorization Request must be signed and contain JWT for given client_id_scheme - did", error.localizedDescription)
        }
    }
    
    func testShouldThrowErrorWhenAuthRequestObtainedByReferenceDoesNotContainContentTypeFieldItselfInHeader() async {
        let url: URL = URL(string: "https://mock-verifier.com/verifier/get-auth-request-obj")!
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReferenceDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdDraft23)) as [String : Any]
        let didSchemeAuthRequestHandler = DidSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParametersByReference, setResponseUri: mockSetResponseUri, networkManager: mockNetworkManager)
        let requestUriResponse = createNetworkResponse("non-jwt", httpUrlResponse: HTTPURLResponse(url: url, statusCode: 200, httpVersion: "", headerFields: [:])!)

        await XCTAssertAsyncThrowsError(try await didSchemeAuthRequestHandler.validateRequestUriResponse(requestUriResponse: requestUriResponse)) { error in
            XCTAssertEqual("Authorization Request must be signed and contain JWT for given client_id_scheme - did", error.localizedDescription)
        }
    }

    func testShouldThrowErrorWhenAuthRequestsAlgObtainedByReferenceDoesNotMatchWithWalletMetadata() async {
        let url: URL = URL(string: "https://mock-verifier.com/verifier/get-auth-request-obj")!
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReferenceDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdDraft23)) as [String : Any]
        let didSchemeAuthRequestHandler = DidSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParametersByReference, walletMetadata: walletMetadata, setResponseUri: mockSetResponseUri, networkManager: mockNetworkManager)
        didSchemeAuthRequestHandler.shouldValidateWithWalletMetadata = true
        let requestUriResponse = createNetworkResponse("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ10.SflK5c", httpUrlResponse: HTTPURLResponse(url: url, statusCode: 200, httpVersion: "", headerFields: ["Content-Type": "application/oauth-authz-req+jwt"]))

        await XCTAssertAsyncThrowsError(try await didSchemeAuthRequestHandler.validateRequestUriResponse(requestUriResponse: requestUriResponse)) { error in
            XCTAssertEqual("request_object_signing_alg is not supported by wallet", error.localizedDescription)
        }
    }

    func testShouldThrowErrorWhenAuthRequestObtainedByReferenceDoesNotContainJWTContentTypeInHeader() async {
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReferenceDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdDraft23)) as [String : Any]
        let didSchemeAuthRequestHandler = DidSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParametersByReference, setResponseUri: mockSetResponseUri, networkManager: mockNetworkManager)

        await XCTAssertAsyncThrowsError(try await didSchemeAuthRequestHandler.fetchAuthorizationRequest()) { error in
            XCTAssertEqual("Authorization Request must be signed and contain JWT for given client_id_scheme - did", error.localizedDescription)
        }
    }
    
    func testProcessingWalletMetadataSuccessfully() async throws {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValueDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, [
            "client_id": "mock-client",
        ])) as [String : Any]
        let didScheme = DidSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: walletMetadata, setResponseUri: mockSetResponseUri, networkManager: mockNetworkManager!)
            
        let processedMetadata = try didScheme.process(walletMetadata: walletMetadata)
        
        assertDictionariesEqual(expected: convertToDictionary(object: walletMetadata)!, actual: convertToDictionary(object: processedMetadata))
    }
    
    func testShouldThrowErrorForWalletMetadataProcessingWhenRequestObjectSigningAlgValuesSupportedisNil() async throws {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValueDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, [
            "client_id": "mock-client",
        ])) as [String : Any]
        
        let walletMetadata = try createWalletMetadata(requestObjectSigningAlgValuesSupported: nil)
        
        let didScheme = DidSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: walletMetadata, setResponseUri: mockSetResponseUri, networkManager: mockNetworkManager!)
        
        await XCTAssertAsyncThrowsError(try didScheme.process(walletMetadata: walletMetadata)) { error in
            XCTAssertEqual("request_object_signing_alg_values_supported is not present in wallet metadata.", error.localizedDescription)
        }
    }
    
    func testFetchingHeadersForDIDClientIdSchemeSuccessfully() async {
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
