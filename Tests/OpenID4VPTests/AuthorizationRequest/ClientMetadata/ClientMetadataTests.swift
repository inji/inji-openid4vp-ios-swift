import XCTest
@testable import OpenID4VP

final class ClientMetadataValidationTests: XCTestCase {

    func testValidate_ClientMetadata() {
        let testCases: [TestCase<Data>] = [
            TestCase(
                input: """
                {
                    "client_name": null,
                    "logo_uri": "https://example.com/logo.png",
                    "authorization_encrypted_response_alg": "RSA-OAEP",
                    "authorization_encrypted_response_enc": "A256GCM",
                    "vp_formats": { "format1": { "type1": ["value1"] } },
                    "jwks": null
                }
                """.data(using: .utf8)!,
                expectedError: "Validation failed: client_name is required"
            ),
            TestCase(
                input: """
                {
                    "client_name": "Test Client",
                    "logo_uri": null,
                    "authorization_encrypted_response_alg": "RSA-OAEP",
                    "authorization_encrypted_response_enc": "A256GCM",
                    "vp_formats": { "format1": { "type1": ["value1"] } },
                    "jwks": null
                }
                """.data(using: .utf8)!,
                expectedError: "Validation failed: logo_uri is required"
            ),
            TestCase(
                input: """
                {
                    "client_name": "Test Client",
                    "logo_uri": "https://example.com/logo.png",
                    "authorization_encrypted_response_alg": null,
                    "authorization_encrypted_response_enc": "A256GCM",
                    "vp_formats": { "format1": { "type1": ["value1"] } },
                    "jwks": null
                }
                """.data(using: .utf8)!,
                expectedError: "Validation failed: authorization_encrypted_response_alg is required"
            ),
            TestCase(
                input: """
                {
                    "client_name": "Test Client",
                    "logo_uri": "https://example.com/logo.png",
                    "authorization_encrypted_response_alg": "RSA-OAEP",
                    "authorization_encrypted_response_enc": null,
                    "vp_formats": { "format1": { "type1": ["value1"] } },
                    "jwks": null
                }
                """.data(using: .utf8)!,
                expectedError: "Validation failed: authorization_encrypted_response_enc is required"
            ),
            TestCase(
                input: """
                {
                    "client_name": "Test Client",
                    "logo_uri": "https://example.com/logo.png",
                    "authorization_encrypted_response_alg": "RSA-OAEP",
                    "authorization_encrypted_response_enc": "A256GCM",
                    "vp_formats": {},
                    "jwks": null
                }
                """.data(using: .utf8)!,
                expectedError: "Validation failed: vp_formats is required"
            ),
            TestCase(
                input: """
                {
                    "client_name": "Test Client",
                    "logo_uri": "https://example.com/logo.png",
                    "authorization_encrypted_response_alg": "RSA-OAEP",
                    "authorization_encrypted_response_enc": "A256GCM",
                    "vp_formats": { "format1": { "type1": ["value1"] } },
                    "jwks": { "keys": [] }
                }
                """.data(using: .utf8)!,
                expectedError: "Validation failed: jwks is required"
            )
        ]

        for testCase in testCases {
            if let expectedError = testCase.expectedError {
                XCTAssertThrowsError(try ClientMetadata.deserializeAndValidate(clientMetadata: testCase.input)) { error in
                    XCTAssertEqual(error.localizedDescription, expectedError)
                }
            }
        }
    }

    func testValidate_Success() {
        let validMetadataJSON = """
            {
                "client_name": "Valid Client",
                "logo_uri": "https://example.com/logo.png",
                "authorization_encrypted_response_alg": "RSA-OAEP",
                "authorization_encrypted_response_enc": "A256GCM",
                "vp_formats": { "format1": { "type1": ["value1"] } },
                "jwks": { "keys": [{ "kty": "RSA", "crv": "curve", "use": "sig", "alg": "RS256", "kid": "1", "x": "ur76ru" }] }
            }
            """.data(using: .utf8)!

        XCTAssertNoThrow(try ClientMetadata.deserializeAndValidate(clientMetadata: validMetadataJSON))
    }
}
