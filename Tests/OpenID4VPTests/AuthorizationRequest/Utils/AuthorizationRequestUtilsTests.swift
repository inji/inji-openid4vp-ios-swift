import XCTest
@testable import OpenID4VP

class AuthorizationRequestUtilsTests : XCTestCase {
    func testDecoding() {
        let data = "openid4vp://authorize?client_id=https%3A%2F%2F1333-103-101-213-24.ngrok-free.app%2Fverifier%2Fvp-response&presentation_definition_uri=https%3A%2F%2F1333-103-101-213-24.ngrok-free.app%2Fverifier%2Fpresentation_definition_uri&response_type=vp_token&response_mode=direct_post&nonce=97Ls4N6OTVxeVmI73YlOjg%3D%3D&state=rU8RTzcS04e76lM0LzIvsw%3D%3D&response_uri=https%3A%2F%2F1333-103-101-213-24.ngrok-free.app%2Fverifier%2Fvp-response&client_metadata=%5Bobject+Object%5D&client_id_scheme=pre-registered"
        
        let decoded = extractQueryParameters(data)
        XCTAssertEqual(["response_mode": "direct_post", "response_uri": "https://1333-103-101-213-24.ngrok-free.app/verifier/vp-response", "response_type": "vp_token", "presentation_definition_uri": "https://1333-103-101-213-24.ngrok-free.app/verifier/presentation_definition_uri", "client_metadata": "[object+Object]", "client_id_scheme": "pre-registered", "state": "rU8RTzcS04e76lM0LzIvsw==", "client_id": "https://1333-103-101-213-24.ngrok-free.app/verifier/vp-response", "nonce": "97Ls4N6OTVxeVmI73YlOjg=="], decoded)
        
    }
}
