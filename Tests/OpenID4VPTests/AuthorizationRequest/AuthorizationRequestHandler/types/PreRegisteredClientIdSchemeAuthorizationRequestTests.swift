import Foundation
import XCTest
@testable import OpenID4VP

class PreRegisteredClientIdSchemeTests : XCTestCase {
    let mockNetworkManager: MockNetworkManager! = MockNetworkManager()
    let mockSetResponseUri: (String) -> Void = { value in
    }
    
    let requestUriResponse: String = createAuthorizationRequestObject(clientIdScheme: .preRegistered, authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue,[
        "client_id": "mock-client",
    ]), applicableFields: authRequestWithPreRegisteredByValue)
    let requestUri: URL = URL(string: "https://mock-verifier.com/verifier/get-auth-request-obj")!
    
    private var walletMetadata: WalletMetadata!

        override func setUpWithError() throws {
            walletMetadata = try createWalletMetadata()
        }
    
    // Validate client tests
    
    func testThrowExceptionWhenClientIdIsNotAvailableAsTrustedVerifier(){
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, [
            "client_id": "untrusted-mock-client",
        ])) as [String : Any]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(trustedVerifiers: preRegisteredVerifiers, authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil, shouldValidateClient: true, setResponseUri: mockSetResponseUri, networkManager: mockNetworkManager)
        
        XCTAssertThrowsError(try preRegistered.validateClientId()){ error in
            XCTAssertTrue(error == AuthorizationRequestException.invalidVerifier(message: "Verifier not available in trusted list"))
            XCTAssertEqual("Invalid Verifier: VP sharing failed: Verifier authentication was unsuccessful.Verifier not available in trusted list", error.localizedDescription)
            XCTAssertEqual("Invalid Verifier: VP sharing failed: Verifier authentication was unsuccessful.Verifier not available in trusted list", (error as! AuthorizationRequestException).errorDescription)
        }
    }
    
    
    func testThrowExceptionWhenTrustedVerifiersListIsEmpty(){
        let authorizationRequestParameters: [String : Any] = ["client_id": "other-mock-client","response_uri": "https://mock-verifier.com"]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(trustedVerifiers: preRegisteredVerifiers, authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil, shouldValidateClient: true, setResponseUri: mockSetResponseUri, networkManager: mockNetworkManager)
        
        XCTAssertThrowsError(try preRegistered.validateClientId()){ error in
            XCTAssertEqual("Invalid Verifier: VP sharing failed: Verifier authentication was unsuccessful.Verifier not available in trusted list", (error as! AuthorizationRequestException).errorDescription)
        }
    }
    
    // Validate and parse authorization request - check if verifier is trusted
    func testThrowExceptionWhenClientIdIsAvailableInTrustedVerifiersButResponseUriIsNotMatching() async{
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, [
            "client_id": "mock-client",
            "response_uri": "https://some-other-url.com"
        ])) as [String : Any]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(trustedVerifiers: preRegisteredVerifiers, authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil,shouldValidateClient: true, setResponseUri: mockSetResponseUri, networkManager: mockNetworkManager)

        await assertAsyncThrowsError(try await preRegistered.validateAndParseRequestFields()){ error in
            XCTAssertTrue(error == AuthorizationRequestException.invalidVerifier(message: "response_uri trust cannot be established"))
            XCTAssertEqual("Invalid Verifier: VP sharing failed: Verifier authentication was unsuccessful.response_uri trust cannot be established", error.localizedDescription)
        }
    }
    
    /// Fetch authorization request by value - validate authorization request object and authorization request query paramaters
    
    func testFetchAuthorizationRequestOnValidPreRegisteredSchemeAuthRequestSentByValue() async{
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, [
            "client_id": "mock-client",
        ])) as [String : Any]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(trustedVerifiers: preRegisteredVerifiers, authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil, shouldValidateClient: true, setResponseUri: mockSetResponseUri, networkManager: mockNetworkManager)
        
        try? await preRegistered.fetchAuthorizationRequest()
        
        assertDictionariesEqual(expected: preRegistered.authorizationRequestParameters, actual: [
            "response_mode": "direct_post",
            "response_type": "vp_token",
            "client_id": "mock-client",
            "nonce": "VbRRB/LTxLiXmVNZuyMO8A==",
            "state": "+mRQe1d6pBoJqF6Ab28klg==",
            "response_uri": "https://mock-verifier.com",
            "presentation_definition": [
                "input_descriptors": [[
                    "format": [
                        "ldp_vc": [
                            "proof_type": ["Ed25519Signature2018", "RsaSignature2018"]
                        ]
                    ],
                    "constraints": [
                        "fields": [[
                            "path": ["$.credentialSubject.email"],
                            "filter": [
                                "pattern": "@gmail.com",
                                "type": "string"
                            ]
                        ]]
                    ],
                    "name": "Verifiable Credential",
                    "id": "input_1",
                    "purpose": "To verify identity using Linked Data Proofs"
                ]],
                "id": "vp_presentation_definition"
            ],
            "client_metadata": [
                "authorization_encrypted_response_enc": "A256GCM",
                "authorization_encrypted_response_alg": "ECDH-ES",
                "logo_uri": "https://mock-verifier.com/logo",
                "client_name": "Requester name",
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
                ]
            ]
        ]
        )
    }
    
    func testFetchAuthorizationRequestOnValidPreRegisteredSchemeAuthRequestSentByReference() async{
        let requestUriResponse: String = createAuthorizationRequestObject(clientIdScheme: .preRegistered, authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue,preRegisteredSchemeClientId), applicableFields: authRequestWithPreRegisteredByValue)
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientId)) as [String : Any]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(trustedVerifiers: preRegisteredVerifiers, authorizationRequestParameters: authorizationRequestParametersByReference, walletMetadata: nil,shouldValidateClient: true, setResponseUri: mockSetResponseUri, networkManager: mockNetworkManager)
        
        try? await preRegistered.validateRequestUriResponse(requestUriResponse: createNetworkResponse(requestUriResponse))
        
        assertDictionariesEqual(expected: preRegistered.authorizationRequestParameters, actual: [
            "client_id": "mock-client",
            "state": "+mRQe1d6pBoJqF6Ab28klg==",
            "client_metadata": [
                "vp_formats": [
                    "ldp_vp": [
                        "proof_type": ["Ed25519Signature2018", "Ed25519Signature2020"]
                    ]
                ],
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
                "logo_uri": "https://mock-verifier.com/logo",
                "authorization_encrypted_response_enc": "A256GCM",
                "authorization_encrypted_response_alg": "ECDH-ES",
                "client_name": "Requester name"
            ],
            "response_type": "vp_token",
            "response_mode": "direct_post",
            "response_uri": "https://mock-verifier.com",
            "presentation_definition": [
                "input_descriptors": [[
                    "id": "input_1",
                    "format": [
                        "ldp_vc": [
                            "proof_type": ["Ed25519Signature2018", "RsaSignature2018"]
                        ]
                    ],
                    "name": "Verifiable Credential",
                    "constraints": [
                        "fields": [[
                            "filter": [
                                "type": "string",
                                "pattern": "@gmail.com"
                            ],
                            "path": ["$.credentialSubject.email"]
                        ]]
                    ],
                    "purpose": "To verify identity using Linked Data Proofs"
                ]],
                "id": "vp_presentation_definition"
            ],
            "nonce": "VbRRB/LTxLiXmVNZuyMO8A=="
        ])
    }
    
    func testFetchAuthorizationRequestThrowExceptionForValidationOfMatchingClientIdOnAuthRequestSentByReference() async{
        let requestUriResponse: String = createAuthorizationRequestObject(clientIdScheme: .preRegistered, authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue,[
            "client_id": "some-mock-client",
        ]), applicableFields: authRequestWithPreRegisteredByValue)
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientId)) as [String : Any]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(trustedVerifiers: preRegisteredVerifiers, authorizationRequestParameters: authorizationRequestParametersByReference, walletMetadata: nil, shouldValidateClient: true, setResponseUri: mockSetResponseUri, networkManager: mockNetworkManager)

        await assertAsyncThrowsError(try await preRegistered.validateRequestUriResponse(requestUriResponse: createNetworkResponse(requestUriResponse))) { error in
            XCTAssertTrue(error == AuthorizationRequestException.mismatchingClientIDInRequest)
            XCTAssertEqual("Client Id is mismatching in QR data and Request Uri response", error.localizedDescription)
        }
    }
    
    /// Validation of authRequest params obtained via request_uri by matching with url encoded query param data
    
    func testFetchAuthorizationRequestThrowExceptionWhenAuthRequestObjectObtainedIsJWT() async{
        let requestUriResponse: String = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientId)) as [String : Any]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(trustedVerifiers: preRegisteredVerifiers, authorizationRequestParameters: authorizationRequestParametersByReference, walletMetadata: nil, shouldValidateClient: true, setResponseUri: mockSetResponseUri, networkManager: mockNetworkManager)

        await assertAsyncThrowsError(try await preRegistered.validateRequestUriResponse(requestUriResponse: createNetworkResponse(requestUriResponse))) { error in
            XCTAssertEqual("Authorization Request must not be signed for given client_id_scheme", error.localizedDescription)
        }
    }
    
    func testFetchAuthorizationRequestThrowExceptionWhenAuthRequestObjectObtainedIsNotJsonContentType() async {
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientId)) as [String : Any]

        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(trustedVerifiers: preRegisteredVerifiers, authorizationRequestParameters: authorizationRequestParametersByReference, walletMetadata: nil, shouldValidateClient: true, setResponseUri: mockSetResponseUri, networkManager: mockNetworkManager)
        let requestUriResponse = createNetworkResponse(requestUriResponse, httpUrlResponse: HTTPURLResponse(url: requestUri, statusCode: 200, httpVersion: "", headerFields: ["Content-Type":"application/x-www-form-urlencoded"])!)

        await assertAsyncThrowsError(try await preRegistered.validateRequestUriResponse(requestUriResponse: requestUriResponse)) { error in
            XCTAssertEqual("Authorization Request must not be signed for given client_id_scheme", error.localizedDescription)
        }
    }
    
    func testFetchAuthorizationRequestThrowExceptionWhenAuthRequestObjectObtainedDoesNotContainContentTypeFieldInHeader() async {
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientId)) as [String : Any]
        
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(trustedVerifiers: preRegisteredVerifiers, authorizationRequestParameters: authorizationRequestParametersByReference, walletMetadata: walletMetadata, shouldValidateClient: true, setResponseUri: mockSetResponseUri, networkManager: mockNetworkManager)
        
        let requestUriResponse = createNetworkResponse(requestUriResponse, httpUrlResponse: HTTPURLResponse(url: requestUri, statusCode: 200, httpVersion: "", headerFields: [:])!)
        
        await assertAsyncThrowsError(try await preRegistered.validateRequestUriResponse(requestUriResponse: requestUriResponse)) { error in
            XCTAssertEqual("Authorization Request must not be signed for given client_id_scheme", error.localizedDescription)
        }
    }
    
    func testProcessingWalletMetadataSuccessfully() async{
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, [
            "client_id": "mock-client",
        ])) as [String : Any]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(trustedVerifiers: preRegisteredVerifiers, authorizationRequestParameters: authorizationRequestParameters, walletMetadata: walletMetadata, shouldValidateClient: true, setResponseUri: mockSetResponseUri, networkManager: mockNetworkManager!)
        
        var expectedWalletMetadata: WalletMetadata = walletMetadata
        expectedWalletMetadata.requestObjectSigningAlgValuesSupported = nil
            
        let processedMetadata = preRegistered.process(walletMetadata: walletMetadata)
        
        assertDictionariesEqual(expected: convertToDictionary(object: expectedWalletMetadata)!, actual: convertToDictionary(object: processedMetadata))
    }
    
    func testFetchingHeadersForPreRegisteredClientIdSchemeSuccessfully() async{
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, [
            "client_id": "mock-client",
        ])) as [String : Any]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(trustedVerifiers: preRegisteredVerifiers, authorizationRequestParameters: authorizationRequestParameters, walletMetadata: walletMetadata, shouldValidateClient: true, setResponseUri: mockSetResponseUri, networkManager: mockNetworkManager!)
        
        let expectedHeader =
        [Header.contentType.rawValue: ContentTypes.applicationFormUrlEncoded.rawValue,
         Header.accept.rawValue: ContentTypes.applicationJson.rawValue]
            
        let header = preRegistered.getHeadersForAuthorizationRequestUri()
        
        assertDictionariesEqual(expected: expectedHeader, actual: header)
    }
}
