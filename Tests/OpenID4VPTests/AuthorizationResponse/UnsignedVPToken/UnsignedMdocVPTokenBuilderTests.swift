import XCTest
@testable import OpenID4VP

final class UnsignedMdocVPTokenBuilderTests: XCTestCase {
    func testThrowErrorWhenUnableToDecodeCredential() throws {
        let builder = UnsignedMdocVPTokenBuilder(
            mdocCredentials: ["invalidCBOR"],
            clientId: "client-id",
            responseUri: "response-uri",
            verifierNonce: "verifier-nonce",
            mdocGeneratedNonce: "mock-nonce"
        )

        XCTAssertThrowsError(try builder.build()) { error in
            assertOpenID4VPException(error,
                expectedMessage: "Invalid Verifiable Credential: Error while decoding credential",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testThrowErrorWhenSelectedCredentialsHaveMoreThanOneCredentialWithSameDocType() throws {
        let builder = UnsignedMdocVPTokenBuilder(
            mdocCredentials: [sampleMdoc, sampleMdoc],
            clientId: "client-id",
            responseUri: "response-uri",
            verifierNonce: "verifier-nonce",
            mdocGeneratedNonce: "mock-nonce"
        )

        XCTAssertThrowsError(try builder.build()) { error in
            assertOpenID4VPException(error,
                expectedMessage: "Invalid Verifiable Credential: Error while decoding credential",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    // MARK: - Sample Mdoc Hex CBOR

    private var sampleMdoc: String {
        return "2BhYhYV0RGV2aWNlQXV0aGVudGljYXRpb27z9vYNYiBfBjYG/0XKyv2z1ABxDzp0nY4S2MKeUX91dUj+319wpWIK/eLk7ANjnsV+cFIQtmWibSTJdm0LajRqluWQ0qVrbtsd2FsbGV0LW5vbmNldXNlcmlzby4xODAxMy41LjEubURGzRhBoA=="
    }

    private func assertDictionariesEqual(expected: [String: String], actual: [String: String], file: StaticString = #file, line: UInt = #line) {
        XCTAssertEqual(expected.count, actual.count, "Dictionary count mismatch", file: file, line: line)
        for (key, expectedValue) in expected {
            guard let actualValue = actual[key] else {
                XCTFail("Missing key \(key)", file: file, line: line)
                return
            }
            XCTAssertEqual(expectedValue, actualValue, "Mismatch for key '\(key)'", file: file, line: line)
        }
    }
}
