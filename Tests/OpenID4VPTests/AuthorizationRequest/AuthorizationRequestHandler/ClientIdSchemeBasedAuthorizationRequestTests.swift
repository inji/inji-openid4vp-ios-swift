
import Foundation
import XCTest
@testable import OpenID4VP

class ClientIdSchemeBasedAuthorizationRequestTests : XCTestCase {
    let mockNetworkManager: MockNetworkManager! = MockNetworkManager()
    let mockSetResponseUri: (String) -> Void = { value in
    }
    var decodedClientMetadata: ClientMetadata?
    var decodedPresentationDefinition: PresentationDefinition?
    
    struct TestCase {
        let input: [String:String?]
        let expectedError: String
    }
    
    // Validate client tests
    func testInvalidRequestFieldErrorForClientIdField() {
        let testCases: [TestCase] = [
            TestCase(input: ["client_id": "null"], expectedError: "Invalid Input: client_id value cannot be empty or null"),
            TestCase(input: ["client_id": ""], expectedError: "Invalid Input: client_id value cannot be empty or null"),
            TestCase(input: ["client_id": "nil"], expectedError: "Invalid Input: client_id value cannot be empty or null"),
            TestCase(input: ["client_id": nil], expectedError: "Missing Input: client_id param is required")
        ]
        
        for testCase in testCases {
            let authorizationRequestParametersWithInvalidClientId: [String : Any?] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValue, requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfPreRegistered, testCase.input))
            let clientIdSchemeBasedAuthorizationRequestHandler = ClientIdSchemeBasedAuthorizationRequestHandlerBaseClass(authorizationRequestParameters: authorizationRequestParametersWithInvalidClientId as [String : Any], networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
            
            XCTAssertThrowsError(try clientIdSchemeBasedAuthorizationRequestHandler.validateClientId()){ error in
                XCTAssertEqual(testCase.expectedError, error.localizedDescription)
            }
        }
    }
    
    //    Fetch authorization request
    class MockClientIdSchemeAuthRequestHandler: ClientIdSchemeBasedAuthorizationRequestHandler {
        var wasMethodCalled = false
        
        override init(authorizationRequestParameters: [String: Any], networkManager: NetworkManaging, setResponseUri: @escaping (String) -> Void) {
            super.init(authorizationRequestParameters: authorizationRequestParameters, networkManager: networkManager, setResponseUri: setResponseUri)
            delegate = self
        }
        func validateRequestUriResponse() async throws {
            wasMethodCalled = true
        }
    }
    
    ///    Authorization request obtained by reference:  request_uri response - gives all data as JSON (presentation_definition is also obtained by reference)
    func testFetchAuthorizationRequestByReference() async{
        let authorizationRequestObject = createAuthorizationRequestObject(
            clientIdScheme: .redirectUri,
            authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfRedirectUri),
            applicableFields: authRequestWithRedirectUriByValue
        )
        let authorizationRequestParameters = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfRedirectUri)) as [String : Any]
        mockNetworkManager.setMockResponse(for: URL(string: "https://mock-verifier.com/verifier/get-auth-request-obj")!,responseBody: authorizationRequestObject)
        let mockAuthHandler = MockClientIdSchemeAuthRequestHandler(authorizationRequestParameters: authorizationRequestParameters, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
        do{
            try await mockAuthHandler.fetchAuthorizationRequest()
            
            assertJSONStringEqual(expected: "{\"client_id\":\"https:\\/\\/mock-verifier.com\",\"response_type\":\"vp_token\",\"presentation_definition\":{\"input_descriptors\":[{\"id\":\"input_1\",\"name\":\"Verifiable Credential\",\"purpose\":\"To verify identity using Linked Data Proofs\",\"constraints\":{\"fields\":[{\"filter\":{\"type\":\"string\",\"pattern\":\"@gmail.com\"},\"path\":[\"$.credentialSubject.email\"]}]},\"format\":{\"ldp_vc\":{\"proof_type\":[\"Ed25519Signature2018\",\"RsaSignature2018\"]}}}],\"id\":\"vp_presentation_definition\"},\"response_mode\":\"direct_post\",\"client_metadata\":{\"client_name\":\"Requester name\",\"vp_formats\":{\"mso_mdoc\":{\"alg\":[\"ES256\",\"EdDSA\"]},\"ldp_vp\":{\"proof_type\":[\"Ed25519Signature2018\",\"Ed25519Signature2020\",\"RsaSignature2018\"]}},\"authorization_encrypted_response_alg\":\"ECDH-ES\",\"authorization_encrypted_response_enc\":\"A256GCM\",\"logo_uri\":\"https:\\/\\/mock-verifier.com\\/logo\"},\"nonce\":\"VbRRB\\/LTxLiXmVNZuyMO8A==\",\"state\":\"+mRQe1d6pBoJqF6Ab28klg==\",\"response_uri\":\"https:\\/\\/mock-verifier.com\",\"client_id_scheme\":\"redirect_uri\"}", actual: mockAuthHandler.requestUriResponse!.body)
            XCTAssertTrue(mockAuthHandler.wasMethodCalled)
        } catch {
            XCTFail("Error should not occur but got error \(error) - \(error.localizedDescription)")
        }
    }
    
    ///   Authorization request obtained by value: gives all data as url encoded (presentation_definition is also obtained by value)
    func testFetchAuthorizationRequestByValue() async{
        let authorizationRequestParameters: [String: Any] = createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue.map { $0 == "presentation_definition" ? "presentation_definition_uri" : $0 } , requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfRedirectUri)) as [String : Any]
        let mockAuthHandler = MockClientIdSchemeAuthRequestHandler(authorizationRequestParameters: authorizationRequestParameters, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
        
        do{
            try await mockAuthHandler.fetchAuthorizationRequest()
            
            XCTAssertNil(mockAuthHandler.requestUriResponse)
            assertDictionariesEqual(expected: [
                "state": "+mRQe1d6pBoJqF6Ab28klg==",
                "response_type": "vp_token",
                "response_uri": "https://mock-verifier.com",
                "response_mode": "direct_post",
                "nonce": "VbRRB/LTxLiXmVNZuyMO8A==",
                "client_id": "https://mock-verifier.com",
                "presentation_definition_uri": "https://mock-verifier.com/presentation-definition",
                "client_metadata": [
                    "client_name": "Requester name",
                    "authorization_encrypted_response_enc": "A256GCM",
                    "authorization_encrypted_response_alg": "ECDH-ES",
                    "vp_formats": [
                        "mso_mdoc": [
                            "alg": ["ES256", "EdDSA"]
                        ],
                        "ldp_vp": [
                            "proof_type": ["Ed25519Signature2018", "Ed25519Signature2020", "RsaSignature2018"]
                        ]
                    ],
                    "logo_uri": "https://mock-verifier.com/logo"
                ],
                "client_id_scheme": "redirect_uri"
            ], actual: mockAuthHandler.authorizationRequestParameters)
            XCTAssertTrue(mockAuthHandler.wasMethodCalled)
        } catch {
            XCTFail("Error should not occur but got error \(error)")
        }
    }
    
    func testFetchAuthRequestShouldThrowErrorWhenRequestUriIsNotHttpsScheme() async{
        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfPreRegistered,["request_uri": "http://invalid-mock-verifier.com"])) as [String : Any]
        let mockAuthHandler = MockClientIdSchemeAuthRequestHandler(authorizationRequestParameters: authorizationRequestParametersByReference, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
        
        do {
            try await mockAuthHandler.fetchAuthorizationRequest()
            XCTFail("request_uri data is not valid error to be thrown but not thrown")
        } catch{
            XCTAssertEqual("request_uri http://invalid-mock-verifier.com data is not valid", error.localizedDescription)
        }
    }
    
    func testFetchAuthRequestWithInvalidRequestUriValuesThrowError() async {
        let testCases: [TestCase] = [
            TestCase(input: ["request_uri": ""], expectedError: "Invalid Input: requestUri value cannot be empty or null"),
            TestCase(input: ["request_uri": "nil"], expectedError: "Invalid Input: requestUri value cannot be empty or null"),
            TestCase(input: ["request_uri": "null"], expectedError: "Invalid Input: requestUri value cannot be empty or null"),
        ]
        
        for testCase in testCases {
            let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReference , requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfPreRegistered, testCase.input))  as [String : Any]
            let mockAuthHandler = MockClientIdSchemeAuthRequestHandler(authorizationRequestParameters: authorizationRequestParameters, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
            
            do {
                try await mockAuthHandler.fetchAuthorizationRequest()
                XCTFail("request_uri data is not valid error to be thrown but not thrown")
            } catch{
                XCTAssertEqual(testCase.expectedError, error.localizedDescription)
            }
        }
    }
    
    //Fetch info for sending response (error or authorization response) to verifier
    func testResponseUrlSetSuccessfullyForResponseModeDirectPost(){
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfPreRegistered))  as [String : Any]
        let expectation = expectation(description: "Handler should be called with expected parameter")
        var responseUri: String?
        let mockSetResponseUri: (String) -> Void = { value in
            responseUri = value
            expectation.fulfill()
        }
        
        let clientIdSchemeBasedAuthorizationRequestHandler = ClientIdSchemeBasedAuthorizationRequestHandlerBaseClass(authorizationRequestParameters: authorizationRequestParameters, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
        try? clientIdSchemeBasedAuthorizationRequestHandler.setResponseUrl()
        
        wait(for: [expectation], timeout: 2.0)
        XCTAssertEqual(responseUri, "https://mock-verifier.com", "Handler was called with unexpected parameter")
    }
    
    func testFetchInfoForSendingResponseToVerifierForInvalidResponseModeThrowInvalidResponseModeError() {
        let testCases: [TestCase] = [
            TestCase(input: ["response_mode": "fragment"], expectedError: "response mode is unsupported"),
            TestCase(input: ["response_mode": ""], expectedError: "response mode is empty"),
            TestCase(input: ["response_mode": "nil"], expectedError: "response mode value cannot be empty or null"),
            TestCase(input: ["response_mode": "null"], expectedError: "response mode value cannot be empty or null"),
            TestCase(input: ["response_mode": nil], expectedError: "response mode property is missing in authorization request")
        ]
        
        for testCase in testCases {
            let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfPreRegistered, testCase.input))  as [String : Any]
            let clientIdSchemeBasedAuthorizationRequestHandler = ClientIdSchemeBasedAuthorizationRequestHandlerBaseClass(authorizationRequestParameters: authorizationRequestParameters, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
            
            XCTAssertThrowsError(try clientIdSchemeBasedAuthorizationRequestHandler.setResponseUrl()){ error in
                XCTAssertEqual("An unexpected exception occurred: exception type: invalidResponseMode", error.localizedDescription, testCase.expectedError)
            }
        }
    }
    
    //Validate fields in authorization request which are mandatory
    
    func testParseAndValidateAuthorizationRequestWithPresentationDefinitionByReferenceSupport() async{
        decodedClientMetadata = createInstance(clientMetadata, as: ClientMetadata.self)
        decodedPresentationDefinition = createInstance(presentationDefinition, as: PresentationDefinition.self)
        let presentationDefinition = convertToJsonString(presentationDefinition)
        let authorizationRequestParameters: [String: Any] = createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue.map { $0 == "presentation_definition" ? "presentation_definition_uri" : $0 } , requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfRedirectUri)) as [String : Any]
        mockNetworkManager.setMockResponse(for: URL(string: "https://mock-verifier.com/presentation-definition")!,responseBody: presentationDefinition)
        
        let mockAuthHandler = MockClientIdSchemeAuthRequestHandler(authorizationRequestParameters: authorizationRequestParameters, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
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
                "client_id": "https://mock-verifier.com",
                "response_mode": "direct_post",
                "client_id_scheme": "redirect_uri"
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
            authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfRedirectUri),
            applicableFields: authRequestWithRedirectUriByValue
        )
        let authorizationRequestParameters = createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfRedirectUri)) as [String : Any]
        mockNetworkManager.setMockResponse(for: URL(string: "https://mock-verifier.com/verifier/get-auth-request-obj")!,responseBody: authorizationRequestObject)
        
        let mockAuthHandler = MockClientIdSchemeAuthRequestHandler(authorizationRequestParameters: authorizationRequestParameters, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
        do{
            try await mockAuthHandler.validateAndParseRequestFields()
            
            assertDictionariesEqual(expected: [
                "client_metadata": decodedClientMetadata!,
                "response_mode": "direct_post",
                "client_id": "https://mock-verifier.com",
                "response_uri": "https://mock-verifier.com",
                "presentation_definition": decodedPresentationDefinition!,
                "nonce": "VbRRB/LTxLiXmVNZuyMO8A==",
                "state": "+mRQe1d6pBoJqF6Ab28klg==",
                "client_id_scheme": "redirect_uri",
                "response_type": "vp_token"
            ], actual: mockAuthHandler.authorizationRequestParameters)
        } catch {
            XCTFail("Error should not occur but got error \(error) - \(error.localizedDescription)")
        }
    }
    
    func testInvalidRequestFieldThrowErrorForResponseTypeField() async {
        let testCases: [TestCase] = [
            TestCase(input: ["response_type": "null"], expectedError: "Invalid Input: response_type value cannot be empty or null"),
            TestCase(input: ["response_type": ""], expectedError: "Invalid Input: response_type value cannot be empty or null"),
            TestCase(input: ["response_type": "nil"], expectedError: "Invalid Input: response_type value cannot be empty or null"),
            TestCase(input: ["response_type": nil], expectedError: "Missing Input: response_type param is required")
        ]
        
        for testCase in testCases {
            let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValue, requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfPreRegistered, testCase.input)) as [String : Any]
            let clientIdSchemeBasedAuthorizationRequestHandler = ClientIdSchemeBasedAuthorizationRequestHandlerBaseClass(authorizationRequestParameters: authorizationRequestParameters, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
            
            do{
                try await clientIdSchemeBasedAuthorizationRequestHandler.validateAndParseRequestFields()
                XCTFail("error should have been captured but not captured")
            }
            catch{
                XCTAssertEqual(testCase.expectedError, error.localizedDescription)
            }
        }
    }
    
    func testInvalidRequestFieldErrorForStateField() async {
        let testCases: [TestCase] = [
            TestCase(input: ["state": "null"], expectedError: "Invalid Input: state value cannot be empty or null"),
            TestCase(input: ["state": ""], expectedError: "Invalid Input: state value cannot be empty or null"),
            TestCase(input: ["state": "nil"], expectedError: "Invalid Input: state value cannot be empty or null"),
        ]
        
        for testCase in testCases {
            let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValue, requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfPreRegistered, testCase.input)) as [String : Any]
            let clientIdSchemeBasedAuthorizationRequestHandler = ClientIdSchemeBasedAuthorizationRequestHandlerBaseClass(authorizationRequestParameters: authorizationRequestParameters, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
            
            do{
                try await clientIdSchemeBasedAuthorizationRequestHandler.validateAndParseRequestFields()
                XCTFail("error should have been captured but not captured")
            }
            catch{
                XCTAssertEqual(testCase.expectedError, error.localizedDescription)
            }
        }
    }
    
    func testInvalidRequestFieldErrorForResponseModeField() async {
        let testCases: [TestCase] = [
            TestCase(input: ["response_mode": "null"], expectedError: "Invalid Input: response_mode value cannot be empty or null"),
            TestCase(input: ["response_mode": ""], expectedError: "Invalid Input: response_mode value cannot be empty or null"),
            TestCase(input: ["response_mode": "nil"], expectedError: "Invalid Input: response_mode value cannot be empty or null"),
        ]
        
        for testCase in testCases {
            let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValue, requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfPreRegistered, testCase.input)) as [String : Any]
            let clientIdSchemeBasedAuthorizationRequestHandler = ClientIdSchemeBasedAuthorizationRequestHandlerBaseClass(authorizationRequestParameters: authorizationRequestParameters, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
            
            do{
                try await clientIdSchemeBasedAuthorizationRequestHandler.validateAndParseRequestFields()
                XCTFail("error should have been captured but not captured")
            }
            catch{
                XCTAssertEqual(testCase.expectedError, error.localizedDescription)
            }
        }
    }
    
    func testInvalidRequestFieldErrorForNonceField() async {
        let testCases: [TestCase] = [
            TestCase(input: ["nonce": "null"], expectedError: "Invalid Input: nonce value cannot be empty or null"),
            TestCase(input: ["nonce": ""], expectedError: "Invalid Input: nonce value cannot be empty or null"),
            TestCase(input: ["nonce": "nil"], expectedError: "Invalid Input: nonce value cannot be empty or null"),
            TestCase(input: ["nonce": nil], expectedError: "Missing Input: nonce param is required")
        ]
        
        for testCase in testCases {
            let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValue, requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfPreRegistered, testCase.input)) as [String : Any]
            let clientIdSchemeBasedAuthorizationRequestHandler = ClientIdSchemeBasedAuthorizationRequestHandlerBaseClass(authorizationRequestParameters: authorizationRequestParameters, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
            
            do{
                try await clientIdSchemeBasedAuthorizationRequestHandler.validateAndParseRequestFields()
                XCTFail("error should have been captured but not captured")
            }
            catch{
                XCTAssertEqual(testCase.expectedError, error.localizedDescription)
            }
        }
    }
    
    func testShouldThrowErrorWhenInvalidClientMetadataIsProvided() async{
        let authorizationRequestParameters: [String : Any] = mergeMaps(resquestUriResponseData,["client_metadata": "{}"])
        let clientIdSchemeBasedAuthorizationRequestHandler = ClientIdSchemeBasedAuthorizationRequestHandlerBaseClass(authorizationRequestParameters: authorizationRequestParameters, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
        
        do{
            try await clientIdSchemeBasedAuthorizationRequestHandler.validateAndParseRequestFields()
            XCTFail("error should have been captured but not captured")
        }
        catch{
            XCTAssertEqual("Invalid Input: client_metadata value cannot be empty or null", error.localizedDescription)
        }
    }
    
    func testShouldThrowErrorWhenBothPresenentationDefinitionAndPresenentationDefinitionUriArePresent() async{
        let authorizationRequestParameters: [String : Any] = mergeMaps(resquestUriResponseData,["presentation_definition_uri": "https://mock-verifier.com/presentation-definition", "presentation_definition": presentationDefinition])
        let clientIdSchemeBasedAuthorizationRequestHandler = ClientIdSchemeBasedAuthorizationRequestHandlerBaseClass(authorizationRequestParameters: authorizationRequestParameters, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
        
        do{
            try await clientIdSchemeBasedAuthorizationRequestHandler.validateAndParseRequestFields()
            XCTFail("error should have been captured but not captured")
        }
        catch {
            XCTAssertEqual("Either presentation_definition or presentation_definition_uri request param can be provided but not both", error.localizedDescription)
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
}
