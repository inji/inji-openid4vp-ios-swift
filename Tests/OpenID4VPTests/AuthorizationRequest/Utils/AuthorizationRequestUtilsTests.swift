import XCTest
@testable import OpenID4VP

class AuthorizationRequestUtilsTests : XCTestCase {
    let mockNetworkManager = MockNetworkManager()
    
    struct TestCase {
        let input: [String: Any]
        let expectedError: String
    }
    
    //Test Decoding of url encoded paramters to Dictionary
    
    func testDecoding() throws {
        let data = "openid4vp://authorize?client_id=https%3A%2F%2F1333-103-101-213-24.ngrok-free.app%2Fverifier%2Fvp-response&presentation_definition_uri=https%3A%2F%2F1333-103-101-213-24.ngrok-free.app%2Fverifier%2Fpresentation_definition_uri&response_type=vp_token&response_mode=direct_post&nonce=97Ls4N6OTVxeVmI73YlOjg%3D%3D&state=rU8RTzcS04e76lM0LzIvsw%3D%3D&response_uri=https%3A%2F%2F1333-103-101-213-24.ngrok-free.app%2Fverifier%2Fvp-response&client_metadata=%5Bobject+Object%5D&client_id_scheme=pre-registered"
        
        let decoded = try extractQueryParameters(data)
        XCTAssertEqual(["response_mode": "direct_post", "response_uri": "https://1333-103-101-213-24.ngrok-free.app/verifier/vp-response", "response_type": "vp_token", "presentation_definition_uri": "https://1333-103-101-213-24.ngrok-free.app/verifier/presentation_definition_uri", "client_metadata": "[object+Object]", "client_id_scheme": "pre-registered", "state": "rU8RTzcS04e76lM0LzIvsw==", "client_id": "https://1333-103-101-213-24.ngrok-free.app/verifier/vp-response", "nonce": "97Ls4N6OTVxeVmI73YlOjg=="], decoded)
        
    }
    
    func testThrowErrorWhenDataIsInvalidWhileExtractingQueryParameters() throws {
        let data = "client_id=https%3A%2F%2F1333-103-101-213-24.ngrok-free.app%2Fverifier%2Fvp-response&presentation_definition_uri=https%3A%2F%2F1333-103-101-213-24.ngrok-free.app%2Fverifier%2Fpresentation_definition_uri&response_type=vp_token&response_mode=direct_post&nonce=97Ls4N6OTVxeVmI73YlOjg%3D%3D&state=rU8RTzcS04e76lM0LzIvsw%3D%3D&response_uri=https%3A%2F%2F1333-103-101-213-24.ngrok-free.app%2Fverifier%2Fvp-response&client_metadata=%5Bobject+Object%5D&client_id_scheme=pre-registered"
        
        XCTAssertThrowsError( try extractQueryParameters(data)){ error in
            XCTAssertEqual("Query parameters are missing in the Authorization request", error.localizedDescription)
        }
    }
    
    //Test validation of attributes
    
    func testValidateAtributeWithInvalidInput() {
        let testCases: [TestCase] = [
            TestCase(input: ["key1": "null"], expectedError: "Invalid Input: key1 value cannot be empty or null"),
            TestCase(input: ["key1": ""], expectedError: "Invalid Input: key1 value cannot be empty or null"),
            TestCase(input: ["key1": "nil"], expectedError: "Invalid Input: key1 value cannot be empty or null"),
            TestCase(input: [:], expectedError: "Missing Input: key1 param is required")
        ]
        
        for testCase in testCases {
            XCTAssertThrowsError(try validateAttribute("key1", values: testCase.input)){ error in
                XCTAssertEqual(testCase.expectedError, error.localizedDescription)
            }
        }
    }
    
    func testValidateAtributeWithValidInput() {
        XCTAssertNoThrow(try validateAttribute("key1", values: ["key1": "valid value"]))
    }
    
    //Test get authorization request handler
    
    func testShouldThrowErrorWhenClientIdSchemeIsNotSupported() async{
        let mockSetResponseUri: (String) -> Void = { value in
        }
        XCTAssertThrowsError(try getAuthorizationRequestHandler( trustedVerifiers: [], authorizationRequestParameters: ["client_id_scheme":"x509_san_dns"], shouldValidateClient: true, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)) { error in
            XCTAssertEqual("Client id scheme in request is not supported", error.localizedDescription)
        }
    }
    
    func testGetAuthorizationRequestHandlerToGiveRespectiveClientIdBasedAuthorizationRequestHandler(){
        let mockSetResponseUri: (String) -> Void = { value in
        }
        let didAuthRequestHandler = try? getAuthorizationRequestHandler(trustedVerifiers: [], authorizationRequestParameters: ["client_id_scheme": "did"], shouldValidateClient: true, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
        let preRegisteredSchemeAuthRequestHandler = try? getAuthorizationRequestHandler(trustedVerifiers: [], authorizationRequestParameters: ["client_id_scheme": "pre-registered"], shouldValidateClient: true, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
        let redirectUriSchemeAuthRequestHandler = try? getAuthorizationRequestHandler(trustedVerifiers: [], authorizationRequestParameters: ["client_id_scheme": "redirect_uri"], shouldValidateClient: true, networkManager: mockNetworkManager, setResponseUri: mockSetResponseUri)
        
        XCTAssertTrue(didAuthRequestHandler is DidSchemeAuthorizationRequestHandler)
        XCTAssertTrue(preRegisteredSchemeAuthRequestHandler is PreRegisteredSchemeAuthorizationRequestHandler)
        XCTAssertTrue(redirectUriSchemeAuthRequestHandler is RedirectUriSchemeAuthorizationRequestHandler)
    }
}
