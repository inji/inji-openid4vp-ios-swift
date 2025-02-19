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
        let preRegistered = try! getAuthorizationRequestHandler( trustedVerifiers: preRegisteredVerifiers, authorizationRequestParameters: createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, [
            "client_id": "untrusted-mock-client",
        ])), shouldValidateClient: true, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
        
        XCTAssertThrowsError(try preRegistered.validateClientId()){ error in
            XCTAssertTrue(error == AuthorizationRequestException.invalidVerifier)
            XCTAssertEqual("VP sharing failed: Verifier authentication was unsuccessful", error.localizedDescription)
        }
    }
    
    func testThrowExceptionWhenClientIdIsAvailableInTrustedVerifiersButResponseUriIsNotMatching() async{
        let preRegistered = try! getAuthorizationRequestHandler( trustedVerifiers: preRegisteredVerifiers, authorizationRequestParameters: createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, [
            "client_id": "mock-client",
            "response_uri": "https://some-other-url.com"
        ])), shouldValidateClient: true, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
        
        do {
            try await preRegistered.validateAndParseRequestFields()
        }
        catch{
            XCTAssertTrue(error == AuthorizationRequestException.invalidVerifier)
            XCTAssertEqual("VP sharing failed: Verifier authentication was unsuccessful", error.localizedDescription)
        }
    }
    
    func testThrowExceptionWhenTrustedVerifiersListIsEmpty(){
        let preRegistered = try! getAuthorizationRequestHandler( trustedVerifiers: [], authorizationRequestParameters: ["client_id": "other-mock-client","response_uri": "https://mock-verifier.com"], shouldValidateClient: true, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
        
        XCTAssertThrowsError(try preRegistered.validateClientId()){ error in
            XCTAssertTrue(error == AuthorizationRequestException.emptyVerifierList)
            XCTAssertEqual("Verifiers Validation failed: Trusted Verifiers list is empty", error.localizedDescription)
        }
    }
    
    //Fetch authorization request test - by value
    
    func testFetchAuthorizationRequestOnValidPreRegisteredSchemeAuthRequestSentByValue() async{
        let authorizationRequestParameters: [String : String?] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, [
            "client_id": "mock-client",
        ]))
        let preRegistered = try! getAuthorizationRequestHandler( trustedVerifiers: preRegisteredVerifiers, authorizationRequestParameters: authorizationRequestParameters as [String : Any], shouldValidateClient: true, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
        
        _ = try? await preRegistered.fetchAuthRequest()
        
        assertDictionaryValues(actual: preRegistered.authorizationRequestParameters, expected: [
            "response_type": "vp_token",
            "client_metadata": "{\"authorization_encrypted_response_enc\":\"A256GCM\",\"client_name\":\"Requester name\",\"authorization_encrypted_response_alg\":\"ECDH-ES\",\"logo_uri\":\"https:\\/\\/mock-verifier.com\\/logo\",\"vp_formats\":{\"mso_mdoc\":{\"alg\":[\"ES256\",\"EdDSA\"]},\"ldp_vp\":{\"proof_type\":[\"Ed25519Signature2018\",\"Ed25519Signature2020\",\"RsaSignature2018\"]}}}",
            "response_mode": "direct_post",
            "nonce": "VbRRB/LTxLiXmVNZuyMO8A==",
            "response_uri": "https://mock-verifier.com",
            "presentation_definition": "{\"id\":\"vp_presentation_definition\",\"input_descriptors\":[{\"format\":{\"ldp_vc\":{\"proof_type\":[\"Ed25519Signature2018\",\"RsaSignature2018\"]}},\"purpose\":\"To verify identity using Linked Data Proofs\",\"id\":\"input_1\",\"constraints\":{\"fields\":[{\"path\":[\"$.credentialSubject.email\"],\"filter\":{\"type\":\"string\",\"pattern\":\"@gmail.com\"}}]},\"name\":\"Verifiable Credential\"}]}",
            "state": "+mRQe1d6pBoJqF6Ab28klg==",
            "client_id": "mock-client"
        ]
        )
    }
    
    //Fetch authorization request test - by reference
    
    func testFetchAuthorizationRequestOnValidPreRegisteredSchemeAuthRequestSentByReference() async{
        let requestUriResponse: String = createAuthorizationRequestObject(clientIdScheme: .preRegistered, authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue,clientIdAndSchemeOfPreRegistered), applicableFields: authRequestWithPreRegisteredByValue)
        mockNetworkManager.setMockResponse(for: URL(string: "https://mock-verifier.com/verifier/get-auth-request-obj")!,responseBody: requestUriResponse)
        let authorizationRequestParametersByReference: [String : String?] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfPreRegistered))
        let preRegistered = try! getAuthorizationRequestHandler( trustedVerifiers: preRegisteredVerifiers, authorizationRequestParameters: authorizationRequestParametersByReference as [String : Any], shouldValidateClient: true, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
        
        let parsedAuthorizationRequest = try? await preRegistered.fetchAuthRequest()
        
        assertDictionaryValues(actual: preRegistered.authorizationRequestParameters, expected: [
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
    
    func testShouldThrowErrorWhenRequestUriIsInvalid() async{
        let authorizationRequestParametersByReference: [String : String?] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfPreRegistered,["request_uri": "http://invalid-mock-verifier.com"]))
        let preRegistered = try! getAuthorizationRequestHandler( trustedVerifiers: preRegisteredVerifiers, authorizationRequestParameters: authorizationRequestParametersByReference as [String : Any], shouldValidateClient: true, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
        
        do {
            try await preRegistered.fetchAuthRequest()
            XCTFail("request_uri data is not valid error to be thrown but not thrown")
        } catch{
            XCTAssertEqual("request_uri data is not valid", error.localizedDescription)
        }
    }
    
    
    func testFetchAuthorizationRequestThrowExceptionForValidationOfMatchingClientIdOnAuthRequestSentByReference() async{
        let requestUriResponse: String = createAuthorizationRequestObject(clientIdScheme: .preRegistered, authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue,[
            "client_id": "some-mock-client",
            "client_id_scheme": ClientIdScheme.preRegistered.rawValue,
        ]), applicableFields: authRequestWithPreRegisteredByValue)
        mockNetworkManager.setMockResponse(for: URL(string: "https://mock-verifier.com/verifier/get-auth-request-obj")!,responseBody: requestUriResponse)
        let authorizationRequestParametersByReference: [String : String?] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfPreRegistered))
        let preRegistered = try! getAuthorizationRequestHandler( trustedVerifiers: preRegisteredVerifiers, authorizationRequestParameters: authorizationRequestParametersByReference as [String : Any], shouldValidateClient: true, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
        
        do{
            _ = try await preRegistered.fetchAuthRequest()
            XCTFail("Error needs to be thrown")
        } catch {
            XCTAssertTrue(error == AuthorizationRequestException.mismatchingClientIDInRequest)
            XCTAssertEqual("Client Id is mismatching in QR data and Request Uri response", error.localizedDescription)
        }
    }
    
    func testFetchAuthorizationRequestThrowExceptionForValidationOfMatchingClientIdSchemeOnAuthRequestSentByReference() async{
        mockNetworkManager.setMockResponse(for: URL(string: "https://mock-verifier.com/verifier/get-auth-request-obj")!,responseBody: requestUriResponse)
        let authorizationRequestParametersByReference: [String : String?] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfPreRegistered))
        let preRegistered = try! getAuthorizationRequestHandler( trustedVerifiers: preRegisteredVerifiers, authorizationRequestParameters: authorizationRequestParametersByReference as [String : Any], shouldValidateClient: true, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
        
        do{
            _ = try await preRegistered.fetchAuthRequest()
            XCTFail("Error needs to be thrown")
        } catch {
            XCTAssertTrue(error == AuthorizationRequestException.mismatchingClientIdSchemeInRequest)
            XCTAssertEqual("Client Id Scheme is mismatching in QR data and Request Uri response", error.localizedDescription)
        }
    }
    
    
    func testFetchAuthorizationRequestThrowExceptionWhenAuthRequestObjectObtainedIsJWT() async{
        let requestUriResponse: String = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        mockNetworkManager.setMockResponse(for: URL(string: "https://mock-verifier.com/verifier/get-auth-request-obj")!,responseBody: requestUriResponse)
        let authorizationRequestParametersByReference: [String : String?] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfPreRegistered))
        let preRegistered = try! getAuthorizationRequestHandler( trustedVerifiers: preRegisteredVerifiers, authorizationRequestParameters: authorizationRequestParametersByReference as [String : Any], shouldValidateClient: false, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
        
        do{
            _ = try await preRegistered.fetchAuthRequest()
            XCTFail("Error needs to be thrown")
        } catch {
            XCTAssertEqual("Authorization Request must not be signed for given client_id_scheme", error.localizedDescription)
        }
    }
    
    func testFetchAuthorizationRequestThrowExceptionWhenAuthRequestObjectObtainedIsNotJsonContentType() async {
        mockNetworkManager.setMockResponse(for: requestUri,response: (responseBody: requestUriResponse, HTTPURLResponse(url: requestUri, statusCode: 200, httpVersion: "", headerFields: ["Content-Type":"application/x-www-form-urlencoded"])!))
        let authorizationRequestParametersByReference: [String : String?] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfPreRegistered))
        
        let preRegistered = try! getAuthorizationRequestHandler( trustedVerifiers: preRegisteredVerifiers, authorizationRequestParameters: authorizationRequestParametersByReference as [String : Any], shouldValidateClient: false, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
        do{
            _ = try await preRegistered.fetchAuthRequest()
            XCTFail("Error needs to be thrown")
        } catch {
            XCTAssertEqual("Authorization Request must not be signed for given client_id_scheme", error.localizedDescription)
        }
    }

    func testFetchAuthorizationRequestThrowExceptionWhenAuthRequestObjectObtainedDoesNotContainContentTypeFieldInHeader() async {
        mockNetworkManager.setMockResponse(for: requestUri,response: (responseBody: requestUriResponse, HTTPURLResponse(url: requestUri, statusCode: 200, httpVersion: "", headerFields: [:])!))
        let authorizationRequestParametersByReference: [String : String?] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfPreRegistered))
        
        let preRegistered = try! getAuthorizationRequestHandler( trustedVerifiers: preRegisteredVerifiers, authorizationRequestParameters: authorizationRequestParametersByReference as [String : Any], shouldValidateClient: false, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
        do{
            _ = try await preRegistered.fetchAuthRequest()
            XCTFail("Error needs to be thrown")
        } catch {
            XCTAssertEqual("Authorization Request must not be signed for given client_id_scheme", error.localizedDescription)
        }
    }
    
    
    //Fetch info for sending response (error or authorization response) to verifier
    func testFetchInfoForSendingResponseToVerifierForDirectPostResponseMode()throws{
        let expectation = expectation(description: "Handler should be called with expected parameter")
        var responseUri: String?
        let mockSetResponseUri: (String) -> Void = { value in
            responseUri = value
            expectation.fulfill()
        }
        let authorizationRequestParameters: [String : String?] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfPreRegistered))
        let preRegistered = try! getAuthorizationRequestHandler( trustedVerifiers: preRegisteredVerifiers, authorizationRequestParameters: authorizationRequestParameters as [String : Any], shouldValidateClient: true, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
        
        try preRegistered.setResponseUrlForSendingResponseToVerifier()
        
        wait(for: [expectation], timeout: 2.0)
        XCTAssertEqual(responseUri, "https://mock-verifier.com", "Handler was called with unexpected parameter")
        
    }
    
    func testFetchInfoForSendingResponseToVerifierForFragmentResponseMode()throws{
        let authorizationRequestParameters: [String : String?] = createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue.map { $0 == AuthorizationRequestFieldConstants.responseMode.rawValue ? AuthorizationRequestFieldConstants.redirectUri.rawValue : $0 } , requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfPreRegistered, ["redirect_uri":"mock-client"]))
        let preRegistered = try! getAuthorizationRequestHandler( trustedVerifiers: preRegisteredVerifiers, authorizationRequestParameters: authorizationRequestParameters as [String : Any], shouldValidateClient: true, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
        
        XCTAssertThrowsError(try preRegistered.setResponseUrlForSendingResponseToVerifier()){ error in
            XCTAssertEqual("An unexpected exception occurred: exception type: invalidResponseMode", error.localizedDescription)
        }
    }
}
