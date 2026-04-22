import XCTest
@testable import OpenID4VP

final class CredentialUtilsTests: XCTestCase {

    private let classNameValue = "CredentialUtilsTests"

    // MARK: - extractSdJwtPayload

    func testExtractSdJwtPayloadReturnsCredentialAndPayload() throws {
        let credential = AnyCodable(sampeVcSdJwtWithHolderBinding)

        let (rawCredential, payload) = try extractSdJwtPayload(credential, className: className)

        XCTAssertEqual(rawCredential, sampeVcSdJwtWithHolderBinding)
        XCTAssertNotNil(payload["vct"])
        XCTAssertEqual(payload["vct"] as? String, "https://example.eudi.ec.europa.eu/cor/1")
    }

    func testExtractSdJwtPayloadThrowsWhenCredentialIsNotString() throws {
        let credential = AnyCodable(["key": "value"])

        XCTAssertThrowsError(try extractSdJwtPayload(credential, className: className)) { error in
            assertOpenID4VPException(error, expectedMessage: "SD-JWT credential is not a String", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    func testExtractSdJwtPayloadThrowsWhenStringIsEmpty() throws {
        let credential = AnyCodable("")

        XCTAssertThrowsError(try extractSdJwtPayload(credential, className: className)) { error in
            assertOpenID4VPException(error, expectedMessage: "SD-JWT credential is malformed or empty", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    func testExtractSdJwtPayloadThrowsWhenJwtIsInvalid() throws {
        let credential = AnyCodable("not.a.valid~jwt")

        XCTAssertThrowsError(try extractSdJwtPayload(credential, className: className))
    }

    func testExtractSdJwtPayloadWorksWithNoHolderBinding() throws {
        let credential = AnyCodable(sampleVcSdJwtWithNoHolderBinding)

        let (rawCredential, payload) = try extractSdJwtPayload(credential, className: className)

        XCTAssertEqual(rawCredential, sampleVcSdJwtWithNoHolderBinding)
        XCTAssertNotNil(payload["vct"])
    }

    // MARK: - extractSDJwtString

    func testExtractSDJwtStringReturnsStringValue() throws {
        let credential = AnyCodable(sampeVcSdJwtWithHolderBinding)

        let result = try extractSDJwtString(from: credential, className: className)

        XCTAssertEqual(result, sampeVcSdJwtWithHolderBinding)
    }

    func testExtractSDJwtStringThrowsWhenValueIsNotString() throws {
        let credential = AnyCodable(42)

        XCTAssertThrowsError(try extractSDJwtString(from: credential, className: className)) { error in
            assertOpenID4VPException(error, expectedMessage: "SD-JWT credential is not a String", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    func testExtractSDJwtStringThrowsWhenValueIsArray() throws {
        let credential = AnyCodable(["a", "b"])

        XCTAssertThrowsError(try extractSDJwtString(from: credential, className: className)) { error in
            assertOpenID4VPException(error, expectedMessage: "SD-JWT credential is not a String", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    func testExtractSDJwtStringThrowsWhenValueIsDictionary() throws {
        let credential = AnyCodable(["key": "value"])

        XCTAssertThrowsError(try extractSDJwtString(from: credential, className: className)) { error in
            assertOpenID4VPException(error, expectedMessage: "SD-JWT credential is not a String", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }
}
