
import Foundation
import XCTest
@testable import OpenID4VP

class ClientIdSchemeBasedAuthorizationRequestTests : XCTestCase {
    let mockNetworkManager: MockNetworkManager! = MockNetworkManager()
    let mockSetResponseUri: (String) -> Void = { value in
    }
    
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
            let preRegistered = try! getAuthRequestHandler( trustedVerifiers: preRegisteredVerifiers, authRequestParams: createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValue, requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfPreRegistered, testCase.input)), shouldValidateClient: true, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
            
            XCTAssertThrowsError(try preRegistered.validateClientId()){ error in
                XCTAssertEqual(testCase.expectedError, error.localizedDescription)
            }
        }
    }
    
    //Gather info for sending response (error or authorization response) to verifier
    func testGatherInfoForSendingResponseToVerifierForFragmentResponseModeThrowInvalidResponseModeError()throws{
        let authorizationRequestParameters: [String : String?] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfPreRegistered, ["response_mode": "fragment"]))
        let preRegistered = try! getAuthRequestHandler( trustedVerifiers: preRegisteredVerifiers, authRequestParams: authorizationRequestParameters as [String : Any], shouldValidateClient: true, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
        
        XCTAssertThrowsError(try preRegistered.gatherInfoForSendingResponseToVerifier()){ error in
            XCTAssertEqual("Missing Input: redirect_uri param is required", error.localizedDescription)
        }
    }
    
    func testGatherInfoForSendingResponseToVerifierInvalidResponseModeErrorWhenResponseModeIsNotAvailable()throws{
        let authorizationRequestParameters: [String : String?] = createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue.map { $0 == AuthorizationRequestFieldConstants.responseMode.rawValue ? AuthorizationRequestFieldConstants.redirectUri.rawValue : $0 } , requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfPreRegistered))
        let preRegistered = try! getAuthRequestHandler( trustedVerifiers: preRegisteredVerifiers, authRequestParams: authorizationRequestParameters as [String : Any], shouldValidateClient: true, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
        
        XCTAssertThrowsError(try preRegistered.gatherInfoForSendingResponseToVerifier()){ error in
            XCTAssertEqual("An unexpected exception occurred: exception type: invalidResponseMode", error.localizedDescription)
        }
    }
    
    func testGatherInfoForSendingResponseToVerifierInvalidResponseModeErrorWhenResponseModeIsNullValue()throws{
        let authorizationRequestParameters: [String : String?] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfPreRegistered, ["response_mode": "null"]))
        let preRegistered = try! getAuthRequestHandler( trustedVerifiers: preRegisteredVerifiers, authRequestParams: authorizationRequestParameters as [String : Any], shouldValidateClient: true, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
        
        XCTAssertThrowsError(try preRegistered.gatherInfoForSendingResponseToVerifier()){ error in
            XCTAssertEqual("An unexpected exception occurred: exception type: invalidResponseMode", error.localizedDescription)
        }
    }
    
    func testGatherInfoForSendingResponseToVerifierInvalidResponseModeErrorWhenResponseModeIsEmptyValue()throws{
        let authorizationRequestParameters: [String : String?] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfPreRegistered, ["response_mode": ""]))
        let preRegistered = try! getAuthRequestHandler( trustedVerifiers: preRegisteredVerifiers, authRequestParams: authorizationRequestParameters as [String : Any], shouldValidateClient: true, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
        
        XCTAssertThrowsError(try preRegistered.gatherInfoForSendingResponseToVerifier()){ error in
            XCTAssertEqual("An unexpected exception occurred: exception type: invalidResponseMode", error.localizedDescription)
        }
    }
    
    //Validate fields in authorization request which are mandatory
    func testInvalidRequestFieldThrowErrorForResponseTypeField() async {
        let testCases: [TestCase] = [
            TestCase(input: ["response_type": "null"], expectedError: "Invalid Input: response_type value cannot be empty or null"),
            TestCase(input: ["response_type": ""], expectedError: "Invalid Input: response_type value cannot be empty or null"),
            TestCase(input: ["response_type": "nil"], expectedError: "Invalid Input: response_type value cannot be empty or null"),
            TestCase(input: ["response_type": nil], expectedError: "Missing Input: response_type param is required")
        ]
        
        for testCase in testCases {
            let preRegistered = try! getAuthRequestHandler( trustedVerifiers: preRegisteredVerifiers, authRequestParams: createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValue, requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfPreRegistered, testCase.input)), shouldValidateClient: true, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
            
            do{
                try await preRegistered.validateAndParseRequestFields()
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
            TestCase(input: ["state": nil], expectedError: "Missing Input: state param is required")
        ]
        
        for testCase in testCases {
            let preRegistered = try! getAuthRequestHandler( trustedVerifiers: preRegisteredVerifiers, authRequestParams: createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValue, requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfPreRegistered, testCase.input)), shouldValidateClient: true, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
            
            do{
                try await preRegistered.validateAndParseRequestFields()
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
            let preRegistered = try! getAuthRequestHandler( trustedVerifiers: preRegisteredVerifiers, authRequestParams: createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValue, requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfPreRegistered, testCase.input)), shouldValidateClient: true, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
            
            do{
                try await preRegistered.validateAndParseRequestFields()
            }
            catch{
                XCTAssertEqual(testCase.expectedError, error.localizedDescription)
            }
        }
    }
    
    func testShouldThrowErrorWhenInvalidClientMetadataIsProvided() async{
        let preRegistered = try! getAuthRequestHandler( trustedVerifiers: preRegisteredVerifiers, authRequestParams: mergeMaps(resquestUriResponseData,["client_metadata": "{}"]), shouldValidateClient: true, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
        
        do{
            try await preRegistered.validateAndParseRequestFields()
        }
        catch{
            XCTAssertEqual("Invalid Input: client_metadata value cannot be empty or null", error.localizedDescription)
        }
    }
    
    func testShouldThrowErrorWhenBothPresenentationDefinitionAndPresenentationDefinitionUriArePresent() async{
        let preRegistered = try! getAuthRequestHandler( trustedVerifiers: preRegisteredVerifiers, authRequestParams: mergeMaps(resquestUriResponseData,["presentation_definition_uri": "https://mock-verifier.com/presentation-definition"]), shouldValidateClient: true, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
        
        do{
            try await preRegistered.validateAndParseRequestFields()
        }
        catch {
            XCTAssertEqual("Either presentation_definition or presentation_definition_uri request param can be provided but not both", error.localizedDescription)
        }
    }
    
    func testShouldThrowErrorWhenClientIdSchemeIsNotSupported() async{
        XCTAssertThrowsError(try getAuthRequestHandler( trustedVerifiers: [], authRequestParams: ["client_id_scheme":"x509_san_dns"], shouldValidateClient: true, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)) { error in
            XCTAssertEqual("Client id scheme in request is not supported", error.localizedDescription)
        }
    }
}
