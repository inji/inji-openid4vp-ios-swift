import Foundation
import XCTest
@testable import OpenID4VP

class DidClientIdSchemeAuthorizationRequestTests : XCTestCase {
    let mockNetworkManager: MockNetworkManager! = MockNetworkManager()
    let mockSetResponseUri: (String) -> Void = { value in
    }
    
    let requestUri: URL = URL(string: "https://mock-verifier.com/verifier/get-auth-request-obj")!

    private var walletMetadata: WalletMetadata!

    override func setUpWithError() throws {
        walletMetadata = try createWalletMetadataV2()
    }
    
    // Support for Authorization request by reference or by value
    
    func testReturnFalseForAuthorizationRequestByReferenceSupport() {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValueDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdDraft23)) as [String : Any]
        let handler = DidSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil, setResponseUri: mockSetResponseUri,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        XCTAssertTrue(handler.isRequestUriSupported(), "did client_id_scheme should support request by reference")
    }
    
    func testReturnFalseForAuthorizationRequestByValueSupport() {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValueDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdDraft23)) as [String : Any]
        let handler = DidSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil, setResponseUri: mockSetResponseUri,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        XCTAssertFalse(handler.isRequestObjectSupported(), "did client_id_scheme should not support request by value")
    }

    func testShouldThrowErrorWhenRequestUriIsNotAvailableInAuthorizationRequest() async {
        let authorizationRequestByValue: [String : Any] = createAuthorizationRequest(paramList: authRequestWithDidByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdDraft23)) as [String : Any]
        let didSchemeAuthRequestHandler = DidSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestByValue, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager)

        await XCTAssertAsyncThrowsError(try await didSchemeAuthRequestHandler.validateRequestUriResponse(requestUriResponse: nil, walletNonce: "mock-nonce",isMismatchedAcceptableType: false)) { error in
            assertOpenID4VPException(error,
                expectedMessage: "Missing Input: request_uri param is required",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testShouldThrowErrorWhenAuthRequestObtainedByReferenceIsNotJWT() async {
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReferenceDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdDraft23)) as [String : Any]

        let didSchemeAuthRequestHandler = DidSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParametersByReference, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        let requestUriResponse = createNetworkResponse("non-jwt", httpUrlResponse: HTTPURLResponse(url: requestUri, statusCode: 200, httpVersion: "", headerFields: ["Content-Type": "application/oauth-authz-req+jwt"])!)

        await XCTAssertAsyncThrowsError(try await didSchemeAuthRequestHandler.validateRequestUriResponse(requestUriResponse: requestUriResponse,walletNonce: "mock-nonce", isMismatchedAcceptableType: false)) { error in
            assertOpenID4VPException(error,
                expectedMessage: "Authorization Request must be signed and contain JWT for given client_id_scheme - did",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testShouldThrowErrorWhenRequestUriResponseWalletNonceDoesNotMatchWithTheWalletNonceSentDuringRequest() async {
        mockNetworkManager.setMockResponse(for: didDocumentUrl,responseBody: didResponse)
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReferenceDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue,[AuthorizationRequestFieldConstants.requestUriMethod.rawValue : "post"], DidSchemeClientIdDraft23)) as [String : Any]
        let didSchemeAuthRequestHandler = DidSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParametersByReference, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        let authorizationRequestObject = createAuthorizationRequestObject(clientIdScheme: .did, authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdDraft23, [AuthorizationRequestFieldConstants.walletNonce.rawValue: "hacker-nonce"]))
        let requestUriResponse = createNetworkResponse(authorizationRequestObject, httpUrlResponse: HTTPURLResponse(url: requestUri, statusCode: 200, httpVersion: "", headerFields: ["Content-Type": "application/oauth-authz-req+jwt"])!)

        await XCTAssertAsyncThrowsError(try await didSchemeAuthRequestHandler.validateRequestUriResponse(requestUriResponse: requestUriResponse,walletNonce: "mock-nonce", isMismatchedAcceptableType: false)) { error in
            assertOpenID4VPException(error,
                expectedMessage: "wallet_nonce provided in the authorization request is not the same as shared by wallet",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }


    func testShouldThrowErrorWhenAuthRequestObtainedByReferenceDoesNotContainContentTypeFieldItselfInHeader() async {
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReferenceDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdDraft23)) as [String : Any]
        let didSchemeAuthRequestHandler = DidSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParametersByReference, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        let requestUriResponse = createNetworkResponse("non-jwt", httpUrlResponse: HTTPURLResponse(url: requestUri, statusCode: 200, httpVersion: "", headerFields: [:])!)


        await XCTAssertAsyncThrowsError(try await didSchemeAuthRequestHandler.validateRequestUriResponse(requestUriResponse: requestUriResponse,walletNonce: "mock-nonce", isMismatchedAcceptableType: false)) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Authorization Request must be signed and contain JWT for given client_id_scheme - did",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }

    }

    func testShouldThrowErrorWhenAuthRequestsAlgObtainedByReferenceDoesNotMatchWithWalletMetadata() async {
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReferenceDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdDraft23)) as [String : Any]
        let didSchemeAuthRequestHandler = DidSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParametersByReference, walletMetadata: walletMetadata, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        didSchemeAuthRequestHandler.shouldValidateWithWalletMetadata = true
        let requestUriResponse = createNetworkResponse("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ10.SflK5c", httpUrlResponse: HTTPURLResponse(url: requestUri, statusCode: 200, httpVersion: "", headerFields: ["Content-Type": "application/oauth-authz-req+jwt"]))

        await XCTAssertAsyncThrowsError(try await didSchemeAuthRequestHandler.validateRequestUriResponse(requestUriResponse: requestUriResponse,walletNonce: "mock-nonce", isMismatchedAcceptableType: false)) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "request_object_signing_alg is not supported by wallet",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }

    }

    func testShouldThrowErrorWhenAuthRequestObtainedByReferenceDoesNotContainJWTContentTypeInHeader() async {
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReferenceDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdDraft23)) as [String : Any]
        let didSchemeAuthRequestHandler = DidSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParametersByReference, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager)

        await XCTAssertAsyncThrowsError(try await didSchemeAuthRequestHandler.fetchAuthorizationRequest()) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Authorization Request must be signed and contain JWT for given client_id_scheme - did",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testProcessingWalletMetadataSuccessfully() async throws {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValueDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, [
            AuthorizationRequestFieldConstants.clientId.rawValue: "mock-client",
        ])) as [String : Any]
        let didScheme = DidSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: walletMetadata, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager!)

        let processedMetadata = try didScheme.process(walletMetadata: walletMetadata)

        assertDictionariesEqual(expected: convertToDictionary(object: walletMetadata)!, actual: convertToDictionary(object: processedMetadata))
    }

    func testShouldThrowErrorForWalletMetadataProcessingWhenRequestObjectSigningAlgValuesSupportedisNil() async throws {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValueDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, [
            AuthorizationRequestFieldConstants.clientId.rawValue: "mock-client",
        ])) as [String : Any]

        let walletMetadata = try createWalletMetadataV2(requestObjectSigningAlgValuesSupported: nil)

        let didScheme = DidSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: walletMetadata, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager!)

        await XCTAssertAsyncThrowsError(try didScheme.process(walletMetadata: walletMetadata)) { error in
            assertOpenID4VPException(error,
                expectedMessage: "request_object_signing_alg_values_supported is not present in wallet metadata.",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testFetchingHeadersForDIDClientIdSchemeSuccessfully() async {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithDidByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, [
            AuthorizationRequestFieldConstants.clientId.rawValue: "mock-client",
        ])) as [String : Any]
        let preRegistered = DidSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: walletMetadata, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager!)

        let expectedHeader =
        [Header.contentType.rawValue: ContentTypes.applicationFormUrlEncoded.rawValue,
         Header.accept.rawValue: ContentTypes.applicationJwt.rawValue]

        let header = preRegistered.getHeadersForAuthorizationRequestUri()

        assertDictionariesEqual(expected: expectedHeader, actual: header)
    }
    
}
