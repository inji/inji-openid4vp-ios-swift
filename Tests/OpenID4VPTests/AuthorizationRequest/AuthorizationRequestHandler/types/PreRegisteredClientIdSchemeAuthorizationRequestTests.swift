import Foundation
import XCTest
@testable import OpenID4VP

class PreRegisteredClientIdSchemeTests : XCTestCase {
    let mockNetworkManager: MockNetworkManager! = MockNetworkManager()
    let mockSetResponseUri: (String) -> Void = { value in
    }
    
    // Validate client tests
    
    func testThrowExceptionWhenClientIdIsNotAvailableAsTrustedVerifier(){
        let preRegistered = try! getAuthRequestHandler( trustedVerifiers: preRegisteredVerifiers, authRequestParams: createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, [
            "client_id": "untrusted-mock-client",
        ])), shouldValidateClient: true, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
        
        XCTAssertThrowsError(try preRegistered.validateClientId()){ error in
            XCTAssertTrue(error == AuthorizationRequestException.invalidVerifierClientID)
            XCTAssertEqual("VP sharing failed: Verifier authentication was unsuccessful", error.localizedDescription)
        }
    }
    
    func testThrowExceptionWhenClientIdIsAvailableInTrustedVerifiersButResponseUriIsNotMatching() async{
        let preRegistered = try! getAuthRequestHandler( trustedVerifiers: preRegisteredVerifiers, authRequestParams: createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, [
            "client_id": "mock-client",
            "response_uri": "https://some-other-url.com"
        ])), shouldValidateClient: true, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
        
        do {
            try await preRegistered.validateAndParseRequestFields()
        }
        catch{
            XCTAssertTrue(error == AuthorizationRequestException.invalidVerifierClientID)
            XCTAssertEqual("VP sharing failed: Verifier authentication was unsuccessful", error.localizedDescription)
        }
    }
    
    // TODO: Should we have this test case, instead shouldn't it be same case as client ID is not in trusted verifiers list?
    func testThrowExceptionWhenTrustedVerifiersListIsEmpty(){
        let preRegistered = try! getAuthRequestHandler( trustedVerifiers: [], authRequestParams: ["client_id": "other-mock-client","response_uri": "https://mock-verifier.com"], shouldValidateClient: true, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
        
        XCTAssertThrowsError(try preRegistered.validateClientId()){ error in
            XCTAssertTrue(error == AuthorizationRequestException.emptyVerifierList)
            XCTAssertEqual("Verifiers Validation failed: Trusted Verifiers list is empty", error.localizedDescription)
        }
    }
    
    //Gather authorization request test - by value
    
    func testGatherAuthorizationRequestOnValidPreRegisteredSchemeAuthRequestSentByValue() async{
        let authorizationRequestParameters: [String : String?] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, [
            "client_id": "mock-client",
        ]))
        let preRegistered = try! getAuthRequestHandler( trustedVerifiers: preRegisteredVerifiers, authRequestParams: authorizationRequestParameters as [String : Any], shouldValidateClient: true, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
        
        _ = try? await preRegistered.gatherAuthRequest()
        
        assertDictionaryValues(actual: preRegistered.authRequestParam, expected: [
            "response_type": "vp_token",
            "client_metadata": "{\"authorization_encrypted_response_enc\":\"A256GCM\",\"client_name\":\"Requester name\",\"authorization_encrypted_response_alg\":\"ECDH-ES\",\"logo_uri\":\"https:\\/\\/mock-verifier.com\\/logo\",\"vp_formats\":{\"mso_mdoc\":{\"alg\":[\"ES256\",\"EdDSA\"]},\"ldp_vp\":{\"proof_type\":[\"Ed25519Signature2018\",\"Ed25519Signature2020\",\"RsaSignature2018\"]}}}",
            "response_mode": "direct_post",
            "nonce": "VbRRB/LTxLiXmVNZuyMO8A==",
            "response_uri": "https://mock-verifier.com",
            "presentation_definition": "{\"id\":\"vp_presentation_definition\",\"input_descriptors\":[{\"format\":{\"ldp_vc\":{\"proof_type\":[\"Ed25519Signature2018\",\"RsaSignature2018\"]}},\"purpose\":\"To verify identity using Linked Data Proofs\",\"id\":\"input_1\",\"constraints\":{\"fields\":[{\"path\":[\"$.credentialSubject.email\"],\"filter\":{\"type\":\"string\",\"pattern\":\"@gmail.com\"}}]},\"name\":\"Verifiable Credential\"}]}",
            "state": "+mRQe1d6pBoJqF6Ab28klg==",
            "client_id": "mock-client",
            "client_id_scheme": "pre-registered"
        ]
        )
    }
    
    //Gather authorization request test - by reference
    
    func testGatherAuthorizationRequestOnValidPreRegisteredSchemeAuthRequestSentByReference() async{
        let requestUriResponse: String = createAuthorizationRequestObject(clientIdScheme: .preRegistered, authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue,clientIdAndSchemeOfPreRegistered), applicableFields: authRequestWithPreRegisteredByValue)
        mockNetworkManager.setMockResponse(for: URL(string: "https://mock-verifier.com/verifier/get-auth-request-obj")!,response: requestUriResponse)
        let authorizationRequestParametersByReference: [String : String?] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfPreRegistered))
        let preRegistered = try! getAuthRequestHandler( trustedVerifiers: preRegisteredVerifiers, authRequestParams: authorizationRequestParametersByReference as [String : Any], shouldValidateClient: true, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
        
        let parsedAuthorizationRequest = try? await preRegistered.gatherAuthRequest()
        
        assertDictionaryValues(actual: preRegistered.authRequestParam, expected: [
            "response_mode": "direct_post",
            "response_type": "vp_token",
            "presentation_definition": "{\"id\":\"vp_presentation_definition\",\"input_descriptors\":[{\"format\":{\"ldp_vc\":{\"proof_type\":[\"Ed25519Signature2018\",\"RsaSignature2018\"]}},\"constraints\":{\"fields\":[{\"filter\":{\"pattern\":\"@gmail.com\",\"type\":\"string\"},\"path\":[\"$.credentialSubject.email\"]}]},\"name\":\"Verifiable Credential\",\"id\":\"input_1\",\"purpose\":\"To verify identity using Linked Data Proofs\"}]}",
            "client_metadata": "{\"vp_formats\":{\"ldp_vp\":{\"proof_type\":[\"Ed25519Signature2018\",\"Ed25519Signature2020\",\"RsaSignature2018\"]},\"mso_mdoc\":{\"alg\":[\"ES256\",\"EdDSA\"]}},\"authorization_encrypted_response_enc\":\"A256GCM\",\"client_name\":\"Requester name\",\"authorization_encrypted_response_alg\":\"ECDH-ES\",\"logo_uri\":\"https:\\/\\/mock-verifier.com\\/logo\"}",
            "nonce": "VbRRB/LTxLiXmVNZuyMO8A==",
            "response_uri": "https://mock-verifier.com",
            "state": "+mRQe1d6pBoJqF6Ab28klg==",
            "client_id": "mock-client",
            "client_id_scheme": "pre-registered",
        ])
    }
    
    
    func testGatherAuthorizationRequestThrowExceptionForValidationOfMatchingClientIdOnAuthRequestSentByReference() async{
        let requestUriResponse: String = createAuthorizationRequestObject(clientIdScheme: .preRegistered, authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue,[
            "client_id": "some-mock-client",
            "client_id_scheme": ClientIdScheme.preRegistered.rawValue,
        ]), applicableFields: authRequestWithPreRegisteredByValue)
        mockNetworkManager.setMockResponse(for: URL(string: "https://mock-verifier.com/verifier/get-auth-request-obj")!,response: requestUriResponse)
        let authorizationRequestParametersByReference: [String : String?] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfPreRegistered))
        let preRegistered = try! getAuthRequestHandler( trustedVerifiers: preRegisteredVerifiers, authRequestParams: authorizationRequestParametersByReference as [String : Any], shouldValidateClient: true, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
        
        do{
            _ = try await preRegistered.gatherAuthRequest()
            XCTFail("Error needs to be thrown")
        } catch {
            XCTAssertTrue(error == AuthorizationRequestException.mismatchingClientIDInRequest)
            XCTAssertEqual("Client Id is mismatching in QR data and Request Uri response", error.localizedDescription)
        }
    }
    
    func testGatherAuthorizationRequestThrowExceptionForValidationOfMatchingClientIdSchemeOnAuthRequestSentByReference() async{
        let requestUriResponse: String = createAuthorizationRequestObject(clientIdScheme: .preRegistered, authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue,[
            "client_id": "mock-client",
            "client_id_scheme": ClientIdScheme.did.rawValue,
        ]), applicableFields: authRequestWithPreRegisteredByValue)
        mockNetworkManager.setMockResponse(for: URL(string: "https://mock-verifier.com/verifier/get-auth-request-obj")!,response: requestUriResponse)
        let authorizationRequestParametersByReference: [String : String?] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfPreRegistered))
        let preRegistered = try! getAuthRequestHandler( trustedVerifiers: preRegisteredVerifiers, authRequestParams: authorizationRequestParametersByReference as [String : Any], shouldValidateClient: true, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
        
        do{
            _ = try await preRegistered.gatherAuthRequest()
            XCTFail("Error needs to be thrown")
        } catch {
            XCTAssertTrue(error == AuthorizationRequestException.mismatchingClientIdSchemeInRequest)
            XCTAssertEqual("Client Id Scheme is mismatching in QR data and Request Uri response", error.localizedDescription)
        }
    }
    
    
    func testGatherAuthorizationRequestThrowExceptionWhenAuthRequestObjectIsSigned() async{
        let requestUriResponse: String = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        mockNetworkManager.setMockResponse(for: URL(string: "https://mock-verifier.com/verifier/get-auth-request-obj")!,response: requestUriResponse)
        let authorizationRequestParametersByReference: [String : String?] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfPreRegistered))
        let preRegistered = try! getAuthRequestHandler( trustedVerifiers: preRegisteredVerifiers, authRequestParams: authorizationRequestParametersByReference as [String : Any], shouldValidateClient: false, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
        
        do{
            _ = try await preRegistered.gatherAuthRequest()
            XCTFail("Error needs to be thrown")
        } catch {
            XCTAssertEqual("Authorization Request must not be signed for given client_id_scheme", error.localizedDescription)
        }
    }
    
    
    //Gather info for sending response (error or authorization response) to verifier
    func testGatherInfoForSendingResponseToVerifierForDirectPostResponseMode()throws{
        let expectation = expectation(description: "Handler should be called with expected parameter")
        var responseUri: String?
        let mockSetResponseUri: (String) -> Void = { value in
            responseUri = value
            expectation.fulfill()
        }
        let authorizationRequestParameters: [String : String?] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfPreRegistered))
        let preRegistered = try! getAuthRequestHandler( trustedVerifiers: preRegisteredVerifiers, authRequestParams: authorizationRequestParameters as [String : Any], shouldValidateClient: true, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
        
        try preRegistered.gatherInfoForSendingResponseToVerifier()
        
        wait(for: [expectation], timeout: 2.0)
        XCTAssertEqual(responseUri, "https://mock-verifier.com", "Handler was called with unexpected parameter")
        
    }
    
    func testGatherInfoForSendingResponseToVerifierForFragmentResponseMode()throws{
        let authorizationRequestParameters: [String : String?] = createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue.map { $0 == AuthorizationRequestFieldConstants.responseMode.rawValue ? AuthorizationRequestFieldConstants.redirectUri.rawValue : $0 } , requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfPreRegistered, ["redirect_uri":"mock-client"]))
        let preRegistered = try! getAuthRequestHandler( trustedVerifiers: preRegisteredVerifiers, authRequestParams: authorizationRequestParameters as [String : Any], shouldValidateClient: true, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
        
        XCTAssertThrowsError(try preRegistered.gatherInfoForSendingResponseToVerifier()){ error in
            XCTAssertEqual("An unexpected exception occurred: exception type: invalidResponseMode", error.localizedDescription)
        }
    }
}
