import XCTest
@testable import OpenID4VP

final class VPTokenBuilderUtilsTests: XCTestCase {

    private let clazzName = "VPTokenBuilderUtilsTests"

    // MARK: - Helpers

    private func makeSigningResult(id: String, signedData: Data = Data("signature".utf8)) -> VPTokenSigningResult {
        VPTokenSigningResult(id: id, signedData: signedData)
    }

    private func makeUnsignedToken(id: String) -> UnsignedVPToken {
        UnsignedVPToken(id: id, format: .ldp_vc, holderKeyReference: "key-ref", signatureAlgorithm: "ES256", dataToSign: Data("data".utf8))
    }

    // MARK: - getVPTokenSigningResult — happy path

    func testGetVPTokenSigningResultReturnsMatchingResult() throws {
        let target = makeSigningResult(id: "id-1")
        let results = [makeSigningResult(id: "id-0"), target, makeSigningResult(id: "id-2")]

        let result = try getVPTokenSigningResult(
            vpTokenSigningResults: results,
            identifier: "id-1",
            className: clazzName
        )

        XCTAssertEqual(result.id, "id-1")
        XCTAssertEqual(result.signedData, Data("signature".utf8))
    }

    // MARK: - getVPTokenSigningResult — nil identifier

    func testGetVPTokenSigningResultThrowsWhenIdentifierIsNil() {
        XCTAssertThrowsError(try getVPTokenSigningResult(
            vpTokenSigningResults: [makeSigningResult(id: "id-1")],
            identifier: nil,
            className: clazzName
        )) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Missing identifier",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    // MARK: - getVPTokenSigningResult — missing (0 matches)

    func testGetVPTokenSigningResultThrowsWhenListIsEmpty() {
        XCTAssertThrowsError(try getVPTokenSigningResult(
            vpTokenSigningResults: [],
            identifier: "id-1",
            className: clazzName
        )) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Missing VP token signing result for credential identifier id-1",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testGetVPTokenSigningResultThrowsWhenNoMatchFound() {
        XCTAssertThrowsError(try getVPTokenSigningResult(
            vpTokenSigningResults: [makeSigningResult(id: "id-1")],
            identifier: "id-unknown",
            className: clazzName
        )) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Missing VP token signing result for credential identifier id-unknown",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    // MARK: - getVPTokenSigningResult — duplicate (>1 matches)

    func testGetVPTokenSigningResultThrowsWhenDuplicateFound() {
        let results = [makeSigningResult(id: "id-1"), makeSigningResult(id: "id-1")]

        XCTAssertThrowsError(try getVPTokenSigningResult(
            vpTokenSigningResults: results,
            identifier: "id-1",
            className: clazzName
        )) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Duplicate VP token signing result for credential identifier id-1",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    // MARK: - getVPTokenSigningResult — empty signedData

    func testGetVPTokenSigningResultThrowsWhenSignedDataIsEmpty() {
        XCTAssertThrowsError(try getVPTokenSigningResult(
            vpTokenSigningResults: [makeSigningResult(id: "id-1", signedData: Data())],
            identifier: "id-1",
            className: clazzName
        )) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Invalid signature for identifier id-1",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    // MARK: - getUnsignedVPToken — happy path

    func testGetUnsignedVPTokenReturnsMatchingToken() throws {
        let target = makeUnsignedToken(id: "id-1")
        let tokens = [makeUnsignedToken(id: "id-0"), target, makeUnsignedToken(id: "id-2")]

        let result = try getUnsignedVPToken(
            unsignedVPTokens: tokens,
            identifier: "id-1",
            className: clazzName
        )

        XCTAssertEqual(result.id, "id-1")
    }

    // MARK: - getUnsignedVPToken — missing (0 matches)

    func testGetUnsignedVPTokenThrowsWhenListIsEmpty() {
        XCTAssertThrowsError(try getUnsignedVPToken(
            unsignedVPTokens: [],
            identifier: "id-1",
            className: clazzName
        )) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Missing unsigned VP token for identifier id-1",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testGetUnsignedVPTokenThrowsWhenNoMatchFound() {
        XCTAssertThrowsError(try getUnsignedVPToken(
            unsignedVPTokens: [makeUnsignedToken(id: "id-1")],
            identifier: "id-unknown",
            className: clazzName
        )) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Missing unsigned VP token for identifier id-unknown",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    // MARK: - getUnsignedVPToken — duplicate (>1 matches)

    func testGetUnsignedVPTokenThrowsWhenDuplicateFound() {
        let tokens = [makeUnsignedToken(id: "id-1"), makeUnsignedToken(id: "id-1")]

        XCTAssertThrowsError(try getUnsignedVPToken(
            unsignedVPTokens: tokens,
            identifier: "id-1",
            className: clazzName
        )) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Duplicate unsigned VP token for identifier id-1",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
}
