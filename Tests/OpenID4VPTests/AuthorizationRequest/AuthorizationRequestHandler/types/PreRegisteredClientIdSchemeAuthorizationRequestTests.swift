import Foundation
import XCTest
@testable import OpenID4VP

class PreRegisteredClientIdSchemeTests : XCTestCase {
    let mockNetworkManager: MockNetworkManager! = MockNetworkManager()
    let mockSetResponseUri: (String) -> Void = { value in
    }
    
    let requestUriResponse: String = createAuthorizationRequestObject(clientIdScheme: .preRegistered, authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue,[
        "client_id": "mock-client",
        "client_id_scheme": ClientIdScheme.did.rawValue,
    ]), applicableFields: authRequestWithPreRegisteredByValue)
    let requestUri: URL = URL(string: "https://mock-verifier.com/verifier/get-auth-request-obj")!
    
    // Validate client tests
    
    func testThrowExceptionWhenClientIdIsNotAvailableAsTrustedVerifier(){
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, [
            "client_id": "untrusted-mock-client",
        ])) as [String : Any]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(trustedVerifiers: preRegisteredVerifiers, authorizationRequestParameters: authorizationRequestParameters, networkManager: mockNetworkManager, shouldValidateClient: true, setResponseUri: mockSetResponseUri)
        
        XCTAssertThrowsError(try preRegistered.validateClientId()){ error in
            XCTAssertTrue(error == AuthorizationRequestException.invalidVerifier(message: "Verifier not available in trusted list"))
            XCTAssertEqual("Invalid Verifier: VP sharing failed: Verifier authentication was unsuccessful.Verifier not available in trusted list", error.localizedDescription)
            XCTAssertEqual("Invalid Verifier: VP sharing failed: Verifier authentication was unsuccessful.Verifier not available in trusted list", (error as! AuthorizationRequestException).errorDescription)
        }
    }
    
    
    func testThrowExceptionWhenTrustedVerifiersListIsEmpty(){
        let authorizationRequestParameters: [String : Any] = ["client_id": "other-mock-client","response_uri": "https://mock-verifier.com"]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(trustedVerifiers: preRegisteredVerifiers, authorizationRequestParameters: authorizationRequestParameters, networkManager: mockNetworkManager, shouldValidateClient: true, setResponseUri: mockSetResponseUri)
        
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
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(trustedVerifiers: preRegisteredVerifiers, authorizationRequestParameters: authorizationRequestParameters, networkManager: mockNetworkManager, shouldValidateClient: true, setResponseUri: mockSetResponseUri)
        
        do {
            try await preRegistered.validateAndParseRequestFields()
        }
        catch{
            XCTAssertTrue(error == AuthorizationRequestException.invalidVerifier(message: "response_uri trust cannot be established"))
            XCTAssertEqual("Invalid Verifier: VP sharing failed: Verifier authentication was unsuccessful.response_uri trust cannot be established", error.localizedDescription)
        }
    }
    
    //Fetch authorization request by value - validate authorization request object and authorization request query paramaters
    
    func testFetchAuthorizationRequestOnValidPreRegisteredSchemeAuthRequestSentByValue() async{
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, [
            "client_id": "mock-client",
        ])) as [String : Any]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(trustedVerifiers: preRegisteredVerifiers, authorizationRequestParameters: authorizationRequestParameters, networkManager: mockNetworkManager, shouldValidateClient: true, setResponseUri: mockSetResponseUri)
        
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
                "vp_formats": [
                    "mso_mdoc": [
                        "alg": ["ES256", "EdDSA"]
                    ],
                    "ldp_vp": [
                        "proof_type": ["Ed25519Signature2018", "Ed25519Signature2020", "RsaSignature2018"]
                    ]
                ]
            ]
        ]
        )
    }
    
    func testFetchAuthorizationRequestOnValidPreRegisteredSchemeAuthRequestSentByReference() async{
        let requestUriResponse: String = createAuthorizationRequestObject(clientIdScheme: .preRegistered, authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue,clientIdAndSchemeOfPreRegistered), applicableFields: authRequestWithPreRegisteredByValue)
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfPreRegistered)) as [String : Any]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(trustedVerifiers: preRegisteredVerifiers, authorizationRequestParameters: authorizationRequestParametersByReference, networkManager: mockNetworkManager, shouldValidateClient: true, setResponseUri: mockSetResponseUri)
        preRegistered.requestUriResponse = createNetworkResponse(requestUriResponse)
        
        try? await preRegistered.validateRequestUriResponse()
        
        assertDictionariesEqual(expected: preRegistered.authorizationRequestParameters, actual: [
            "client_id": "mock-client",
            "state": "+mRQe1d6pBoJqF6Ab28klg==",
            "client_metadata": [
                "vp_formats": [
                    "mso_mdoc": [
                        "alg": ["ES256", "EdDSA"]
                    ],
                    "ldp_vp": [
                        "proof_type": ["Ed25519Signature2018", "Ed25519Signature2020", "RsaSignature2018"]
                    ]
                ],
                "logo_uri": "https://mock-verifier.com/logo",
                "authorization_encrypted_response_enc": "A256GCM",
                "authorization_encrypted_response_alg": "ECDH-ES",
                "client_name": "Requester name"
            ],
            "response_type": "vp_token",
            "response_mode": "direct_post",
            "response_uri": "https://mock-verifier.com",
            "client_id_scheme": "pre-registered",
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
            "client_id_scheme": ClientIdScheme.preRegistered.rawValue,
        ]), applicableFields: authRequestWithPreRegisteredByValue)
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfPreRegistered)) as [String : Any]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(trustedVerifiers: preRegisteredVerifiers, authorizationRequestParameters: authorizationRequestParametersByReference, networkManager: mockNetworkManager, shouldValidateClient: true, setResponseUri: mockSetResponseUri)
        preRegistered.requestUriResponse = createNetworkResponse(requestUriResponse)
        
        do{
            _ = try await preRegistered.validateRequestUriResponse()
            XCTFail("Error needs to be thrown")
        } catch {
            XCTAssertTrue(error == AuthorizationRequestException.mismatchingClientIDInRequest)
            XCTAssertEqual("Client Id is mismatching in QR data and Request Uri response", error.localizedDescription)
        }
    }
    
    func testFetchAuthorizationRequestThrowExceptionForValidationOfMatchingClientIdSchemeOnAuthRequestSentByReference() async{
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfPreRegistered)) as [String : Any]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(trustedVerifiers: preRegisteredVerifiers, authorizationRequestParameters: authorizationRequestParametersByReference, networkManager: mockNetworkManager, shouldValidateClient: true, setResponseUri: mockSetResponseUri)
        preRegistered.requestUriResponse = createNetworkResponse(requestUriResponse)
        
        do{
            _ = try await preRegistered.validateRequestUriResponse()
            XCTFail("Error needs to be thrown")
        } catch {
            XCTAssertTrue(error == AuthorizationRequestException.mismatchingClientIdSchemeInRequest)
            XCTAssertEqual("Client Id Scheme is mismatching in QR data and Request Uri response", error.localizedDescription)
        }
    }
    
    //Validation of authRequest params obtained via request_uri by matching with url encoded query param data
    func testShouldThrowErrorWhenClientIdSchemeIsAvailableInOnlyAuthorizationRequestObject() async{
        let requestUriResponse: String = createAuthorizationRequestObject(clientIdScheme: .preRegistered, authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue,["client_id":"mock-client"]), applicableFields: authRequestWithPreRegisteredByValue)
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfPreRegistered)) as [String : Any]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(trustedVerifiers: preRegisteredVerifiers, authorizationRequestParameters: authorizationRequestParametersByReference, networkManager: mockNetworkManager, shouldValidateClient: true, setResponseUri: mockSetResponseUri)
        preRegistered.requestUriResponse = createNetworkResponse(requestUriResponse)
        
        do {
            try await preRegistered.validateRequestUriResponse()
            XCTFail("error should have been thrown but it failed")
        } catch {
            XCTAssertEqual("Client Id Scheme is mismatching in QR data and Request Uri response",error.localizedDescription)
        }
    }
    
    func testShouldThrowErrorWhenClientIdSchemeIsAvailableInOnlyUrlEncodedAuthorizationRequestObject() async{
        let requestUriResponse: String = createAuthorizationRequestObject(clientIdScheme: .preRegistered, authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfPreRegistered), applicableFields: authRequestWithPreRegisteredByValue)
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, ["client_id":"mock-client"])) as [String : Any]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(trustedVerifiers: preRegisteredVerifiers, authorizationRequestParameters: authorizationRequestParametersByReference, networkManager: mockNetworkManager, shouldValidateClient: true, setResponseUri: mockSetResponseUri)
        preRegistered.requestUriResponse = createNetworkResponse(requestUriResponse)
        
        do {
            try await preRegistered.validateRequestUriResponse()
            XCTFail("error should have been thrown but it failed")
        } catch {
            XCTAssertEqual("Client Id Scheme is mismatching in QR data and Request Uri response",error.localizedDescription)
        }
    }
    
    
    func testFetchAuthorizationRequestThrowExceptionWhenAuthRequestObjectObtainedIsJWT() async{
        let requestUriResponse: String = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfPreRegistered)) as [String : Any]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(trustedVerifiers: preRegisteredVerifiers, authorizationRequestParameters: authorizationRequestParametersByReference, networkManager: mockNetworkManager, shouldValidateClient: true, setResponseUri: mockSetResponseUri)
        preRegistered.requestUriResponse = createNetworkResponse(requestUriResponse)
        
        do{
            _ = try await preRegistered.validateRequestUriResponse()
            XCTFail("Error needs to be thrown")
        } catch {
            XCTAssertEqual("Authorization Request must not be signed for given client_id_scheme", error.localizedDescription)
        }
    }
    
    func testFetchAuthorizationRequestThrowExceptionWhenAuthRequestObjectObtainedIsNotJsonContentType() async {
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfPreRegistered)) as [String : Any]
        
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(trustedVerifiers: preRegisteredVerifiers, authorizationRequestParameters: authorizationRequestParametersByReference, networkManager: mockNetworkManager, shouldValidateClient: true, setResponseUri: mockSetResponseUri)
        preRegistered.requestUriResponse = createNetworkResponse(requestUriResponse, httpUrlResponse: HTTPURLResponse(url: requestUri, statusCode: 200, httpVersion: "", headerFields: ["Content-Type":"application/x-www-form-urlencoded"])!)
        
        do{
            _ = try await preRegistered.validateRequestUriResponse()
            XCTFail("Error needs to be thrown")
        } catch {
            XCTAssertEqual("Authorization Request must not be signed for given client_id_scheme", error.localizedDescription)
        }
    }
    
    func testFetchAuthorizationRequestThrowExceptionWhenAuthRequestObjectObtainedDoesNotContainContentTypeFieldInHeader() async {
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfPreRegistered)) as [String : Any]
        
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(trustedVerifiers: preRegisteredVerifiers, authorizationRequestParameters: authorizationRequestParametersByReference, networkManager: mockNetworkManager, shouldValidateClient: true, setResponseUri: mockSetResponseUri)
        preRegistered.requestUriResponse = createNetworkResponse(requestUriResponse, httpUrlResponse: HTTPURLResponse(url: requestUri, statusCode: 200, httpVersion: "", headerFields: [:])!)
        
        do{
            _ = try await preRegistered.validateRequestUriResponse()
            XCTFail("Error needs to be thrown")
        } catch {
            XCTAssertEqual("Authorization Request must not be signed for given client_id_scheme", error.localizedDescription)
        }
    }
}
