
import Foundation
import XCTest
@testable import OpenID4VP




class ClientIdSchemeBasedAuthorizationRequestTests : XCTestCase {
    let mockNetworkManager: MockNetworkManager! = MockNetworkManager()
    let mockSetResponseUri: (String) -> Void = { value in
    }
    var decodedClientMetadata: ClientMetadata?
    var decodedPresentationDefinition: PresentationDefinition?
    
    private var walletMetadata: WalletMetadata!
    let requestUri: URL = URL(string: "https://mock-verifier.com/verifier/get-auth-request-obj")!
    
    override func setUpWithError() throws {
        walletMetadata = try createWalletMetadataV2()
    }
    
    ///    Fetch authorization request tests
    
    
    func testShouldThrowErrorWhenAuthorizationRequestByValueIsNotSupported() async {
        let authorizationRequestParametersByValue: [String : Any] = createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdDraft23)) as [String : Any]
        let mockAuthHandler = MockClientIdSchemeAuthRequestHandler(authorizationRequestParameters: authorizationRequestParametersByValue, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager, isRequestObjectSupported: false)
        
        await XCTAssertAsyncThrowsError(try await mockAuthHandler.fetchAuthorizationRequest()) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "request object is not supported for given client_id_scheme",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testShouldThrowErrorWhenAuthorizationRequestByReferenceIsNotSupported() async {
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReferenceDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdDraft23)) as [String : Any]
        let mockAuthHandler = MockClientIdSchemeAuthRequestHandler(authorizationRequestParameters: authorizationRequestParametersByReference, walletMetadata: walletMetadata, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager, isRequestUriSupported: false)
        
        await XCTAssertAsyncThrowsError(try await mockAuthHandler.fetchAuthorizationRequest()) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "request_uri is not supported for given client_id_scheme",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testShouldmakeApiCallToRequestUriPostWithCorrectAcceptTypeAndContentType() async {
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReferenceDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdDraft23, ["request_uri_method": "post"])) as [String : Any]

        let authorizationRequestObject = createAuthorizationRequestObject(
            clientIdScheme: .did,
            authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdDraft23),
            applicableFields: authRequestWithDidByValue
        )
        let requestUriResponse = createNetworkResponse("non-jwt", httpUrlResponse: HTTPURLResponse(url: requestUri, statusCode: 200, httpVersion: "", headerFields: ["Content-Type": ContentTypes.applicationJwt.rawValue])!)
        mockNetworkManager.setMockResponse(for: "https://mock-verifier.com/verifier/get-auth-request-obj",response: (responseBody: requestUriResponse.body, httpUrlResponse: requestUriResponse.httpUrlResponse))
        let mockAuthHandler = MockClientIdSchemeAuthRequestHandler(authorizationRequestParameters: authorizationRequestParametersByReference, walletMetadata: walletMetadata, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager)


        await XCTAssertAsyncNoThrowsError(try await mockAuthHandler.fetchAuthorizationRequest())
        
        mockNetworkManager.recordedRequests.forEach { (url, recordedRequest) in
            if (url == requestUri.absoluteString) {
                XCTAssertEqual(recordedRequest.requestMethod, HttpMethod.post, "Expected HTTP method to be POST")
                XCTAssertEqual(recordedRequest.requestHeaders?["Accept"], ContentTypes.applicationJwt.rawValue, "Expected Accept header to be \(ContentTypes.applicationJwt.rawValue)")
                XCTAssertEqual(recordedRequest.requestHeaders?["Content-Type"], ContentTypes.applicationFormUrlEncoded.rawValue, "Expected Content-Type header to be \(ContentTypes.applicationFormUrlEncoded.rawValue)")
            }
        }
    }

    func testThrowExceptionWhenRequestUriResponseContentTypeIsNotJWT() async {
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReferenceDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdDraft23)) as [String : Any]

        let authorizationRequestObject = createAuthorizationRequestObject(
            clientIdScheme: .redirectUri,
            authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdDraft23),
            applicableFields: authRequestWithRedirectUriByValue
        )
        let requestUriResponse = createNetworkResponse("non-jwt", httpUrlResponse: HTTPURLResponse(url: requestUri, statusCode: 200, httpVersion: "", headerFields: ["Content-Type": ContentTypes.applicationJson.rawValue])!)
        mockNetworkManager.setMockResponse(for: "https://mock-verifier.com/verifier/get-auth-request-obj",response: (responseBody: requestUriResponse.body, httpUrlResponse: requestUriResponse.httpUrlResponse))
        
        let mockAuthHandler = MockClientIdSchemeAuthRequestHandler(authorizationRequestParameters: authorizationRequestParametersByReference, walletMetadata: walletMetadata, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager)


        await XCTAssertAsyncThrowsError(try await mockAuthHandler.fetchAuthorizationRequest()){ error in
            assertOpenID4VPException(error,
                expectedMessage: "Authorization Request Object must have content type 'application/oauth-authz-req+jwt'",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testFetchAuthorizationRequestByReferenceWhenRespectiveClientIdSchemeSupportsIt() async{
        let authorizationRequestObject = createAuthorizationRequestObject(
            clientIdScheme: .redirectUri,
            authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdDraft23),
            applicableFields: authRequestWithRedirectUriByValue
        )
        let authorizationRequestParameters = createAuthorizationRequest(paramList: authRequestParamsByReferenceDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdDraft23)) as [String : Any]
        mockNetworkManager.setMockResponse(for: "https://mock-verifier.com/verifier/get-auth-request-obj",responseBody: authorizationRequestObject)
        let mockAuthHandler = MockClientIdSchemeAuthRequestHandler(authorizationRequestParameters: authorizationRequestParameters, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        do{
            try await mockAuthHandler.fetchAuthorizationRequest()
            
            assertJSONStringEqual(expected: "{\"response_type\":\"vp_token\",\"client_metadata\":{\"logo_uri\":\"https:\\/\\/mock-verifier.com\\/logo\",\"vp_formats\":{\"ldp_vp\":{\"proof_type\":[\"Ed25519Signature2018\",\"Ed25519Signature2020\"]}},\"client_name\":\"Requester name\",\"authorization_encrypted_response_alg\":\"ECDH-ES\",\"authorization_encrypted_response_enc\":\"A256GCM\",\"jwks\":{\"keys\":[{\"kid\":\"ed-key1\",\"crv\":\"X25519\",\"use\":\"enc\",\"kty\":\"OKP\",\"x\":\"BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4\",\"alg\":\"ECDH-ES\"}]}},\"client_id\":\"redirect_uri:https:\\/\\/mock-verifier.com\",\"response_mode\":\"direct_post\",\"nonce\":\"VbRRB\\/LTxLiXmVNZuyMO8A==\",\"presentation_definition\":{\"id\":\"vp_presentation_definition\",\"input_descriptors\":[{\"constraints\":{\"fields\":[{\"path\":[\"$.credentialSubject.email\"],\"filter\":{\"pattern\":\"@gmail.com\",\"type\":\"string\"}}]},\"format\":{\"ldp_vc\":{\"proof_type\":[\"Ed25519Signature2018\",\"RsaSignature2018\"]}},\"id\":\"input_1\",\"name\":\"Verifiable Credential\",\"purpose\":\"To verify identity using Linked Data Proofs\"}]},\"state\":\"+mRQe1d6pBoJqF6Ab28klg==\",\"response_uri\":\"https:\\/\\/mock-verifier.com\"}", actual: mockAuthHandler.capturedRequestUriResponse!.body)
            XCTAssertTrue(mockAuthHandler.wasMethodCalled)
        } catch {
            XCTFail("Error should not occur but got error \(error) - \(error.localizedDescription)")
        }
    }
    
    func testFetchAuthorizationRequestByReferenceAndRequestUriMethodIsPostPassWalletMetadata() async{
        
        var authorizationRequestWithPostRequestUriMethod = authorizationRequestParamsWithValue
        authorizationRequestWithPostRequestUriMethod[AuthorizationRequestFieldConstants.requestUriMethod.rawValue] = "post"
        
        let authorizationRequestObject = createAuthorizationRequestObject(
            clientIdScheme: .preRegistered,
            authorizationRequestParams: mergeMaps(authorizationRequestWithPostRequestUriMethod, redirectUriSchemeClientIdDraft23),
            applicableFields: authRequestWithRedirectUriByValue
        )
        let authorizationRequestParameters = createAuthorizationRequest(paramList: authRequestParamsByReferenceDraft23 , requestParams: mergeMaps(authorizationRequestWithPostRequestUriMethod, redirectUriSchemeClientIdDraft23)) as [String : Any]
        mockNetworkManager.setMockResponse(for: "https://mock-verifier.com/verifier/get-auth-request-obj",responseBody: authorizationRequestObject)
        let mockAuthHandler = MockClientIdSchemeAuthRequestHandler(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: walletMetadata, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        do{
            try await mockAuthHandler.fetchAuthorizationRequest()
            
            assertJSONStringEqual(expected: "{\"response_type\":\"vp_token\",\"client_metadata\":{\"logo_uri\":\"https:\\/\\/mock-verifier.com\\/logo\",\"vp_formats\":{\"ldp_vp\":{\"proof_type\":[\"Ed25519Signature2018\",\"Ed25519Signature2020\"]}},\"client_name\":\"Requester name\",\"authorization_encrypted_response_alg\":\"ECDH-ES\",\"authorization_encrypted_response_enc\":\"A256GCM\",\"jwks\":{\"keys\":[{\"kid\":\"ed-key1\",\"crv\":\"X25519\",\"use\":\"enc\",\"kty\":\"OKP\",\"x\":\"BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4\",\"alg\":\"ECDH-ES\"}]}},\"client_id\":\"redirect_uri:https:\\/\\/mock-verifier.com\",\"response_mode\":\"direct_post\",\"nonce\":\"VbRRB\\/LTxLiXmVNZuyMO8A==\",\"presentation_definition\":{\"id\":\"vp_presentation_definition\",\"input_descriptors\":[{\"constraints\":{\"fields\":[{\"path\":[\"$.credentialSubject.email\"],\"filter\":{\"pattern\":\"@gmail.com\",\"type\":\"string\"}}]},\"format\":{\"ldp_vc\":{\"proof_type\":[\"Ed25519Signature2018\",\"RsaSignature2018\"]}},\"id\":\"input_1\",\"name\":\"Verifiable Credential\",\"purpose\":\"To verify identity using Linked Data Proofs\"}]},\"state\":\"+mRQe1d6pBoJqF6Ab28klg==\",\"response_uri\":\"https:\\/\\/mock-verifier.com\"}", actual: mockAuthHandler.capturedRequestUriResponse!.body)
            XCTAssertTrue(mockAuthHandler.wasMethodCalled)
            
            let recordedBody = mockNetworkManager.recordedRequests["https://mock-verifier.com/verifier/get-auth-request-obj"]?.requestBody
            XCTAssertNotNil(recordedBody?["wallet_metadata"], "Expected wallet_metadata to be present in the request body")
        } catch {
            XCTFail("Error should not occur but got error \(error) - \(error.localizedDescription)")
        }
    }
    
    func testFetchAuthorizationRequestByValueWithRequestUriMethodNotAvailableInAuthorizationRequestProvided() async{
        let authorizationRequestObject = createAuthorizationRequestObject(
            clientIdScheme: .redirectUri,
            authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdDraft23),
            applicableFields: authRequestWithRedirectUriByValue
        )
        let authorizationRequestParameters = createAuthorizationRequest(paramList: [AuthorizationRequestFieldConstants.clientId.rawValue, "request_uri"] , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdDraft23)) as [String : Any]
        mockNetworkManager.setMockResponse(for: "https://mock-verifier.com/verifier/get-auth-request-obj",responseBody: authorizationRequestObject)
        let mockAuthHandler = MockClientIdSchemeAuthRequestHandler(authorizationRequestParameters: authorizationRequestParameters, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        do{
            try await mockAuthHandler.fetchAuthorizationRequest()
            
            assertJSONStringEqual(expected: "{\"response_type\":\"vp_token\",\"client_metadata\":{\"logo_uri\":\"https:\\/\\/mock-verifier.com\\/logo\",\"vp_formats\":{\"ldp_vp\":{\"proof_type\":[\"Ed25519Signature2018\",\"Ed25519Signature2020\"]}},\"client_name\":\"Requester name\",\"authorization_encrypted_response_alg\":\"ECDH-ES\",\"authorization_encrypted_response_enc\":\"A256GCM\",\"jwks\":{\"keys\":[{\"kid\":\"ed-key1\",\"crv\":\"X25519\",\"use\":\"enc\",\"kty\":\"OKP\",\"x\":\"BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4\",\"alg\":\"ECDH-ES\"}]}},\"client_id\":\"redirect_uri:https:\\/\\/mock-verifier.com\",\"response_mode\":\"direct_post\",\"nonce\":\"VbRRB\\/LTxLiXmVNZuyMO8A==\",\"presentation_definition\":{\"id\":\"vp_presentation_definition\",\"input_descriptors\":[{\"constraints\":{\"fields\":[{\"path\":[\"$.credentialSubject.email\"],\"filter\":{\"pattern\":\"@gmail.com\",\"type\":\"string\"}}]},\"format\":{\"ldp_vc\":{\"proof_type\":[\"Ed25519Signature2018\",\"RsaSignature2018\"]}},\"id\":\"input_1\",\"name\":\"Verifiable Credential\",\"purpose\":\"To verify identity using Linked Data Proofs\"}]},\"state\":\"+mRQe1d6pBoJqF6Ab28klg==\",\"response_uri\":\"https:\\/\\/mock-verifier.com\"}", actual: mockAuthHandler.capturedRequestUriResponse!.body)
            XCTAssertTrue(mockAuthHandler.wasMethodCalled)
        } catch {
            XCTFail("Error should not occur but got error \(error) - \(error.localizedDescription)")
        }
    }
    
    ///   Authorization request obtained by value: gives all data as url encoded (presentation_definition is also obtained by value)
    
    func testFetchAuthorizationRequestByValue() async{
        let authorizationRequestParameters: [String: Any] = createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue.map { $0 == "presentation_definition" ? "presentation_definition_uri" : $0 } , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdDraft23)) as [String : Any]
        let mockAuthHandler = MockClientIdSchemeAuthRequestHandler(authorizationRequestParameters: authorizationRequestParameters, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        do{
            try await mockAuthHandler.fetchAuthorizationRequest()
            
            assertDictionariesEqual(expected: [
                "state": "+mRQe1d6pBoJqF6Ab28klg==",
                "response_type": "vp_token",
                "response_uri": "https://mock-verifier.com",
                "response_mode": "direct_post",
                "nonce": "VbRRB/LTxLiXmVNZuyMO8A==",
                "client_id": "redirect_uri:https://mock-verifier.com",
                "presentation_definition_uri": "https://mock-verifier.com/presentation-definition",
                "client_metadata": [
                    "client_name": "Requester name",
                    "authorization_encrypted_response_enc": "A256GCM",
                    "authorization_encrypted_response_alg": "ECDH-ES",
                    "jwks": [
                        "keys": [[
                            "kty": "OKP",
                            "crv": "X25519",
                            "use": "enc",
                            "x": "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
                            "alg": "ECDH-ES",
                            "kid": "ed-key1"
                        ]]
                    ],
                    "vp_formats": [
                        "ldp_vp": [
                            "proof_type": ["Ed25519Signature2018", "Ed25519Signature2020"]
                        ]
                    ],
                    "logo_uri": "https://mock-verifier.com/logo"
                ],
            ], actual: mockAuthHandler.authorizationRequestParameters)
            XCTAssertTrue(mockAuthHandler.wasMethodCalled)
        } catch {
            XCTFail("Error should not occur but got error \(error) - \(error.localizedDescription)")
        }
    }
    
    func testFetchAuthRequestShouldThrowErrorWhenRequestUriIsNotHttpsScheme() async{
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReferenceDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdDraft23,["request_uri": "http://invalid-mock-verifier.com"])) as [String : Any]
        let mockAuthHandler = MockClientIdSchemeAuthRequestHandler(authorizationRequestParameters: authorizationRequestParametersByReference, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        await XCTAssertAsyncThrowsError(try await mockAuthHandler.fetchAuthorizationRequest()) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "request_uri http://invalid-mock-verifier.com data is not valid",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
            
        }
    }
    
    func testFetchAuthRequestWithInvalidRequestUriValuesThrowError() async {
        let testCases: [TestCase<[String: Any], Void>] = [
            TestCase(
                input: ["request_uri": ""],
                expectedError: "Invalid Input: requestUri value cannot be empty or null",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            ),
            TestCase(
                input: ["request_uri": "nil"],
                expectedError: "Invalid Input: requestUri value cannot be empty or null",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            ),
            TestCase(
                input: ["request_uri": "null"],
                expectedError: "Invalid Input: requestUri value cannot be empty or null",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        ]
        
        for testCase in testCases {
            let authorizationRequestParameters: [String: Any] = createAuthorizationRequest(
                paramList: authRequestParamsByReferenceDraft23,
                requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdDraft23, testCase.input)
            ) as [String: Any]
            
            let mockAuthHandler = MockClientIdSchemeAuthRequestHandler(
                authorizationRequestParameters: authorizationRequestParameters,
                setResponseUri: mockSetResponseUri,
                walletNonce: "mock-nonce",
                networkManager: mockNetworkManager
            )
            
            await XCTAssertAsyncThrowsError(try await mockAuthHandler.fetchAuthorizationRequest()) { error in
                assertOpenID4VPException(
                    error,
                    expectedMessage: testCase.expectedError!,
                    expectedCode: testCase.expectedCode!
                )
            }
        }
    }
    
    
    //Fetch info for sending response (error or authorization response) to verifier
    func testResponseUrlSetSuccessfullyForResponseModeDirectPost(){
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValueDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdDraft23))  as [String : Any]
        let expectation = expectation(description: "Handler should be called with expected parameter")
        var responseUri: String?
        let mockSetResponseUri: (String) -> Void = { value in
            responseUri = value
            expectation.fulfill()
        }
        
        let clientIdSchemeBasedAuthorizationRequestHandler = ClientIdSchemeBasedAuthorizationRequestHandlerBaseClass(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        try? clientIdSchemeBasedAuthorizationRequestHandler.setResponseUrl()
        
        wait(for: [expectation], timeout: 2.0)
        XCTAssertEqual(responseUri, "https://mock-verifier.com", "Handler was called with unexpected parameter")
    }
    
    func testFetchInfoForSendingResponseToVerifierForInvalidResponseModeThrowInvalidResponseModeError() {
        let testCases: [TestCase<[String: String?], Void>] = [
            TestCase(input: [AuthorizationRequestFieldConstants.responseMode.rawValue: "fragment"], expectedError: "Given response_mode - fragment is not supported", expectedCode: OpenID4VPErrorCodes.invalidRequest),
            TestCase(input: [AuthorizationRequestFieldConstants.responseMode.rawValue: ""], expectedError: "Given response_mode -  is not supported", expectedCode: OpenID4VPErrorCodes.invalidRequest),
            TestCase(input: [AuthorizationRequestFieldConstants.responseMode.rawValue: "nil"], expectedError: "Given response_mode - nil is not supported", expectedCode: OpenID4VPErrorCodes.invalidRequest),
            TestCase(input: [AuthorizationRequestFieldConstants.responseMode.rawValue: "null"], expectedError: "Given response_mode - null is not supported", expectedCode: OpenID4VPErrorCodes.invalidRequest),
            TestCase(input: [AuthorizationRequestFieldConstants.responseMode.rawValue: nil], expectedError: "Given response_mode -  is not supported", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        ]
        
        for testCase in testCases {
            let authorizationRequestParameters = createAuthorizationRequest(
                paramList: authRequestWithPreRegisteredByValueDraft23,
                requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdDraft23, testCase.input)
            ) as [String: Any]
            
            let handler = ClientIdSchemeBasedAuthorizationRequestHandlerBaseClass(
                authorizationRequestParameters: authorizationRequestParameters,
                walletMetadata: nil,
                setResponseUri: mockSetResponseUri,
                walletNonce: "mock-nonce",
                networkManager: mockNetworkManager
            )
            
            XCTAssertThrowsError(try handler.setResponseUrl()) { error in
                assertOpenID4VPException(error, expectedMessage: testCase.expectedError!, expectedCode: testCase.expectedCode!)
            }
        }
    }
    
    
    //Validate fields in authorization request which are mandatory
    
    func testParseAndValidateAuthorizationRequestWithPresentationDefinitionByReferenceSupport() async{
        decodedClientMetadata = createInstance(clientMetadata, as: ClientMetadata.self)
        decodedPresentationDefinition = createInstance(presentationDefinition, as: PresentationDefinition.self)
        let presentationDefinition = convertToJsonString(presentationDefinition)
        let authorizationRequestParameters: [String: Any] = createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue.map { $0 == "presentation_definition" ? "presentation_definition_uri" : $0 } , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdDraft23)) as [String : Any]
        mockNetworkManager.setMockResponse(for: "https://mock-verifier.com/presentation-definition",responseBody: presentationDefinition)
        
        let mockAuthHandler = MockClientIdSchemeAuthRequestHandler(authorizationRequestParameters: authorizationRequestParameters, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        do{
            try await mockAuthHandler.validateAndParseRequestFields()
            
            assertDictionariesEqual(expected: [
                "nonce": "VbRRB/LTxLiXmVNZuyMO8A==",
                "presentation_definition": decodedPresentationDefinition!,
                "response_uri": "https://mock-verifier.com",
                "state": "+mRQe1d6pBoJqF6Ab28klg==",
                "response_type": "vp_token",
                "presentation_definition_uri": "https://mock-verifier.com/presentation-definition",
                "client_metadata": decodedClientMetadata!,
                "client_id": "redirect_uri:https://mock-verifier.com",
                "response_mode": "direct_post",
            ], actual: mockAuthHandler.authorizationRequestParameters)
        } catch {
            XCTFail("Error should not occur but got error \(error) - \(error.localizedDescription)")
        }
    }
    
    func testParseAndValidateAuthorizationRequestWithPresentationDefinitionByValueSupport() async{
        decodedClientMetadata = createInstance(clientMetadata, as: ClientMetadata.self)
        decodedPresentationDefinition = createInstance(presentationDefinition, as: PresentationDefinition.self)
        let authorizationRequestObject = createAuthorizationRequestObject(
            clientIdScheme: .redirectUri,
            authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdDraft23),
            applicableFields: authRequestWithRedirectUriByValue
        )
        let authorizationRequestParameters = createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdDraft23)) as [String : Any]
        mockNetworkManager.setMockResponse(for: "https://mock-verifier.com/verifier/get-auth-request-obj",responseBody: authorizationRequestObject)
        
        let mockAuthHandler = MockClientIdSchemeAuthRequestHandler(authorizationRequestParameters: authorizationRequestParameters, setResponseUri: mockSetResponseUri,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        do{
            try await mockAuthHandler.validateAndParseRequestFields()
            
            assertDictionariesEqual(expected: [
                "client_metadata": decodedClientMetadata!,
                "response_mode": "direct_post",
                "client_id": "redirect_uri:https://mock-verifier.com",
                "response_uri": "https://mock-verifier.com",
                "presentation_definition": decodedPresentationDefinition!,
                "nonce": "VbRRB/LTxLiXmVNZuyMO8A==",
                "state": "+mRQe1d6pBoJqF6Ab28klg==",
                "response_type": "vp_token"
            ], actual: mockAuthHandler.authorizationRequestParameters)
        } catch {
            XCTFail("Error should not occur but got error \(error) - \(error.localizedDescription)")
        }
    }
    
    func testInvalidRequestFieldThrowErrorForResponseTypeField() async {
        let testCases: [TestCase<[String: Any?], Void>] = [
            TestCase(input: [AuthorizationRequestFieldConstants.responseType.rawValue: "null"], expectedError: "Invalid Input: response_type value cannot be empty or null", expectedCode: OpenID4VPErrorCodes.invalidRequest),
            TestCase(input: [AuthorizationRequestFieldConstants.responseType.rawValue: ""], expectedError: "Invalid Input: response_type value cannot be empty or null", expectedCode: OpenID4VPErrorCodes.invalidRequest),
            TestCase(input: [AuthorizationRequestFieldConstants.responseType.rawValue: "nil"], expectedError: "Invalid Input: response_type value cannot be empty or null", expectedCode: OpenID4VPErrorCodes.invalidRequest),
            TestCase(input: [AuthorizationRequestFieldConstants.responseType.rawValue: nil], expectedError: "Missing Input: response_type param is required", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        ]
        
        for testCase in testCases {
            let authorizationRequestParameters = createAuthorizationRequest(
                paramList: authRequestWithPreRegisteredByValueDraft23,
                requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdDraft23, testCase.input)
            ) as [String: Any]
            
            let handler = ClientIdSchemeBasedAuthorizationRequestHandlerBaseClass(
                authorizationRequestParameters: authorizationRequestParameters,
                walletMetadata: nil,
                setResponseUri: mockSetResponseUri,
                walletNonce: "mock-nonce",
                networkManager: mockNetworkManager
            )
            
            await XCTAssertAsyncThrowsError(try await handler.validateAndParseRequestFields()) { error in
                assertOpenID4VPException(error, expectedMessage: testCase.expectedError!, expectedCode: testCase.expectedCode!)
            }
        }
    }
    
    
    func testInvalidRequestFieldErrorForStateField() async {
        let testCases: [TestCase<[String: Any], Void>] = [
            TestCase(input: ["state": "null"], expectedError: "Invalid Input: state value cannot be empty or null", expectedCode: OpenID4VPErrorCodes.invalidRequest),
            TestCase(input: ["state": ""], expectedError: "Invalid Input: state value cannot be empty or null", expectedCode: OpenID4VPErrorCodes.invalidRequest),
            TestCase(input: ["state": "nil"], expectedError: "Invalid Input: state value cannot be empty or null", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        ]
        
        for testCase in testCases {
            let authorizationRequestParameters = createAuthorizationRequest(
                paramList: authRequestWithPreRegisteredByValueDraft23,
                requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdDraft23, testCase.input)
            ) as [String: Any]
            
            let handler = ClientIdSchemeBasedAuthorizationRequestHandlerBaseClass(
                authorizationRequestParameters: authorizationRequestParameters,
                walletMetadata: nil,
                setResponseUri: mockSetResponseUri,
                walletNonce: "mock-nonce",
                networkManager: mockNetworkManager
            )
            
            await XCTAssertAsyncThrowsError(try await handler.validateAndParseRequestFields()) { error in
                assertOpenID4VPException(error, expectedMessage: testCase.expectedError!, expectedCode: testCase.expectedCode!)
            }
        }
    }
    
    
    func testInvalidRequestFieldErrorForResponseModeField() async {
        let testCases: [TestCase<[String: Any], Void>] = [
            TestCase(input: [AuthorizationRequestFieldConstants.responseMode.rawValue: "null"], expectedError: "Invalid Input: response_mode value cannot be empty or null", expectedCode: OpenID4VPErrorCodes.invalidRequest),
            TestCase(input: [AuthorizationRequestFieldConstants.responseMode.rawValue: ""], expectedError: "Invalid Input: response_mode value cannot be empty or null", expectedCode: OpenID4VPErrorCodes.invalidRequest),
            TestCase(input: [AuthorizationRequestFieldConstants.responseMode.rawValue: "nil"], expectedError: "Invalid Input: response_mode value cannot be empty or null", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        ]
        
        for testCase in testCases {
            let authorizationRequestParameters = createAuthorizationRequest(
                paramList: authRequestWithPreRegisteredByValueDraft23,
                requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdDraft23, testCase.input)
            ) as [String: Any]
            
            let handler = ClientIdSchemeBasedAuthorizationRequestHandlerBaseClass(
                authorizationRequestParameters: authorizationRequestParameters,
                walletMetadata: nil,
                setResponseUri: mockSetResponseUri,
                walletNonce: "mock-nonce",
                networkManager: mockNetworkManager
            )
            
            await XCTAssertAsyncThrowsError(try await handler.validateAndParseRequestFields()) { error in
                assertOpenID4VPException(error, expectedMessage: testCase.expectedError!, expectedCode: testCase.expectedCode!)
            }
        }
    }
    
    
    func testInvalidRequestFieldErrorForNonceField() async {
        let testCases: [TestCase<[String: Any?], Void>] = [
            TestCase(input: ["nonce": "null"], expectedError: "Invalid Input: nonce value cannot be empty or null", expectedCode: OpenID4VPErrorCodes.invalidRequest),
            TestCase(input: ["nonce": ""], expectedError: "Invalid Input: nonce value cannot be empty or null", expectedCode: OpenID4VPErrorCodes.invalidRequest),
            TestCase(input: ["nonce": "nil"], expectedError: "Invalid Input: nonce value cannot be empty or null", expectedCode: OpenID4VPErrorCodes.invalidRequest),
            TestCase(input: ["nonce": nil], expectedError: "Missing Input: nonce param is required", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        ]
        
        for testCase in testCases {
            let authorizationRequestParameters = createAuthorizationRequest(
                paramList: authRequestWithPreRegisteredByValueDraft23,
                requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdDraft23, testCase.input)
            ) as [String: Any]
            
            let handler = ClientIdSchemeBasedAuthorizationRequestHandlerBaseClass(
                authorizationRequestParameters: authorizationRequestParameters,
                walletMetadata: nil,
                setResponseUri: mockSetResponseUri,
                walletNonce: "mock-nonce",
                networkManager: mockNetworkManager
            )
            
            await XCTAssertAsyncThrowsError(try await handler.validateAndParseRequestFields()) { error in
                assertOpenID4VPException(error, expectedMessage: testCase.expectedError!, expectedCode: testCase.expectedCode!)
            }
        }
    }
    
    func testShouldThrowInvalidDataErrorWhenResponseTypeInAuthorizationRequestIsNotSupported() async {
        decodedClientMetadata = createInstance(clientMetadata, as: ClientMetadata.self)
        decodedPresentationDefinition = createInstance(presentationDefinition, as: PresentationDefinition.self)
        let presentationDefinition = convertToJsonString(presentationDefinition)
        let authorizationRequestParameters: [String: Any] = createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue.map { $0 == "presentation_definition" ? "presentation_definition_uri" : $0 } , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdDraft23, ["response_type": "vp_token id_token"])) as [String : Any]
        mockNetworkManager.setMockResponse(for: "https://mock-verifier.com/presentation-definition",responseBody: presentationDefinition)
        
        let mockAuthHandler = MockClientIdSchemeAuthRequestHandler(authorizationRequestParameters: authorizationRequestParameters, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        await XCTAssertAsyncThrowsError(try await mockAuthHandler.validateAndParseRequestFields()) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "response type - vp_token id_token is not supported",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testShouldThrowErrorWhenInvalidClientMetadataIsProvided() async{
        let authorizationRequestParameters: [String : Any] = mergeMaps(resquestUriResponseData,["client_metadata": "{}"])
        let clientIdSchemeBasedAuthorizationRequestHandler = ClientIdSchemeBasedAuthorizationRequestHandlerBaseClass(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: walletMetadata, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce",networkManager: mockNetworkManager)
        
        await XCTAssertAsyncThrowsError(try await clientIdSchemeBasedAuthorizationRequestHandler.validateAndParseRequestFields()) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Error during client metadata decoding - Missing Input: client_metadata->vp_formats param is required",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testShouldThrowErrorWhenBothPresenentationDefinitionAndPresenentationDefinitionUriArePresent() async{
        let authorizationRequestParameters: [String : Any] = mergeMaps(resquestUriResponseData,["presentation_definition_uri": "https://mock-verifier.com/presentation-definition", "presentation_definition": presentationDefinition])
        let clientIdSchemeBasedAuthorizationRequestHandler = ClientIdSchemeBasedAuthorizationRequestHandlerBaseClass(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce",networkManager: mockNetworkManager)
        
        await XCTAssertAsyncThrowsError(try await clientIdSchemeBasedAuthorizationRequestHandler.validateAndParseRequestFields()) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Either presentation_definition or presentation_definition_uri request param can be provided but not both",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func assertJSONStringEqual(expected: String, actual: String) {
        guard let expectedData = expected.data(using: .utf8),
              let actualData = actual.data(using: .utf8) else {
            XCTFail("Failed to convert JSON strings to Data")
            return
        }
        
        guard let expectedDict = try? JSONSerialization.jsonObject(with: expectedData, options: []) as? [String: Any],
              let actualDict = try? JSONSerialization.jsonObject(with: actualData, options: []) as? [String: Any] else {
            XCTFail("Failed to convert JSON Data to Dictionary")
            return
        }
        
        XCTAssertTrue(NSDictionary(dictionary: expectedDict).isEqual(to: actualDict), "JSONs do not match")
    }
    
    func testShouldThrowErrorWhenPresenentationDefinitionUriIsPresentButNotSupportedByWallet() async throws {
        let requestUriResponse: [String: Any] = createAuthorizationRequest(paramList: authRequestWithRedirectUriWithPresentationDefinitionUri , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdDraft23)) as [String : Any]
        let authorizationRequestParameters: [String : Any] = mergeMaps(requestUriResponse,["presentation_definition_uri": "https://mock-verifier.com/presentation-definition"])
        
        let walletMetadata = try createWalletMetadataV2(presentationDefinitionURISupported: false)
        
        let clientIdSchemeBasedAuthorizationRequestHandler = ClientIdSchemeBasedAuthorizationRequestHandlerBaseClass(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: walletMetadata, setResponseUri: mockSetResponseUri,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        clientIdSchemeBasedAuthorizationRequestHandler.shouldValidateWithWalletMetadata = true
        
        await XCTAssertAsyncThrowsError(try await clientIdSchemeBasedAuthorizationRequestHandler.validateAndParseRequestFields()) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "presentation_definition_uri is not supported",
                                     expectedCode: OpenID4VPErrorCodes.invalidPresentationDefinitionReference
            )
        }
    }
    
    func testShouldThrowErrorForFetchAuthorizationRequestByReferenceForInvalidClientIdAndResponseUriMethodIsPost() async {
        var authorizationRequestParamsWithValueUpdated = authorizationRequestParamsWithValue
        authorizationRequestParamsWithValueUpdated[AuthorizationRequestFieldConstants.requestUriMethod.rawValue] = "post"
        authorizationRequestParamsWithValueUpdated[AuthorizationRequestFieldConstants.clientId.rawValue] = ""
        
        let authorizationRequestObject = createAuthorizationRequestObject(
            clientIdScheme: .preRegistered,
            authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValueUpdated, redirectUriSchemeClientIdDraft23),
            applicableFields: authRequestWithRedirectUriByValue
        )
        let authorizationRequestParameters = createAuthorizationRequest(paramList: authRequestParamsByReferenceDraft23 , requestParams: authorizationRequestParamsWithValueUpdated) as [String : Any]
        mockNetworkManager.setMockResponse(for: "https://mock-verifier.com/verifier/get-auth-request-obj",responseBody: authorizationRequestObject)
        let mockAuthHandler = MockClientIdSchemeAuthRequestHandler(authorizationRequestParameters: authorizationRequestParameters, walletMetadata: walletMetadata, setResponseUri: mockSetResponseUri,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        await XCTAssertAsyncThrowsError(try await mockAuthHandler.fetchAuthorizationRequest()) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Invalid Input: client_id value cannot be empty or null",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
}
