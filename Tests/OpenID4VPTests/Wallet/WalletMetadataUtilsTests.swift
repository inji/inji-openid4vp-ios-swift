import XCTest
@testable import OpenID4VP

final class WalletMetadataUtilsTests: XCTestCase {

    // MARK: - parseClientIdPrefixesSupported

    func testParseClientIdPrefixesSupportedReturnsDefaultWhenNil() throws {
        let result = try parseClientIdPrefixesSupported(nil)
        XCTAssertEqual(result, [.preRegistered])
    }

    func testParseClientIdPrefixesSupportedParsesValidValues() throws {
        let result = try parseClientIdPrefixesSupported(["pre-registered", "redirect_uri", "decentralized_identifier"])
        XCTAssertEqual(result, [.preRegistered, .redirectUri, .decentralizedIdentifier])
    }

    func testParseClientIdPrefixesSupportedThrowsForUnsupportedValue() {
        XCTAssertThrowsError(try parseClientIdPrefixesSupported(["unknown-scheme"])) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Invalid ClientIdPrefix value: unknown-scheme. Its is not supported by the library.",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    // MARK: - parseVPFormatsSupported (VPFormatSupportedV2)

    func testParseVPFormatsSupportedV2ParsesValidFormats() throws {
        let formats: [String: VPFormatSupported] = [
            "ldp_vc": LdpVcFormatSupported(),
            "mso_mdoc": MsoMdocVcFormatSupported()
        ]
        let result = try parseVPFormatsSupported(formats)
        XCTAssertEqual(result.count, 2)
        XCTAssertNotNil(result[.ldp_vc])
        XCTAssertNotNil(result[.mso_mdoc])
    }

    func testParseVPFormatsSupportedV2ThrowsForUnsupportedFormatKey() {
        let formats: [String: VPFormatSupported] = [
            "unsupported_format": LdpVcFormatSupported()
        ]
        XCTAssertThrowsError(try parseVPFormatsSupported(formats)) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Invalid VPFormatType value: unsupported_format. Its is not supported by the library.",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testParseVPFormatsSupportedV2ThrowsForEmptyKey() {
        let formats: [String: VPFormatSupported] = [
            "  ": LdpVcFormatSupported()
        ]
        XCTAssertThrowsError(try parseVPFormatsSupported(formats)) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "vp_formats_supported cannot have empty keys.",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    // MARK: - parseRequestObjectSigningAlgValuesSupported

    func testParseRequestObjectSigningAlgValuesSupportedReturnsNilWhenNil() throws {
        let result = try parseRequestObjectSigningAlgValuesSupported(nil)
        XCTAssertNil(result)
    }

    func testParseRequestObjectSigningAlgValuesSupportedParsesValidValues() throws {
        let result = try parseRequestObjectSigningAlgValuesSupported(["EdDSA"])
        XCTAssertEqual(result, [.edDsa])
    }

    func testParseRequestObjectSigningAlgValuesSupportedThrowsForUnsupportedValue() {
        XCTAssertThrowsError(try parseRequestObjectSigningAlgValuesSupported(["RS256"])) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Invalid RequestSigningAlgorithm value: RS256. Its is not supported by the library.",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    // MARK: - parseAuthorizationEncryptionAlgValuesSupported

    func testParseAuthorizationEncryptionAlgValuesSupportedReturnsNilWhenNil() throws {
        let result = try parseAuthorizationEncryptionAlgValuesSupported(nil)
        XCTAssertNil(result)
    }

    func testParseAuthorizationEncryptionAlgValuesSupportedParsesValidValues() throws {
        let result = try parseAuthorizationEncryptionAlgValuesSupported(["ECDH-ES"])
        XCTAssertEqual(result, [.ecdhEs])
    }

    func testParseAuthorizationEncryptionAlgValuesSupportedThrowsForUnsupportedValue() {
        XCTAssertThrowsError(try parseAuthorizationEncryptionAlgValuesSupported(["RSA-OAEP"])) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Invalid KeyManagementAlgorithm value: RSA-OAEP. Its is not supported by the library.",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    // MARK: - parseAuthorizationEncryptionEncValuesSupported

    func testParseAuthorizationEncryptionEncValuesSupportedReturnsNilWhenNil() throws {
        let result = try parseAuthorizationEncryptionEncValuesSupported(nil)
        XCTAssertNil(result)
    }

    func testParseAuthorizationEncryptionEncValuesSupportedParsesValidValues() throws {
        let result = try parseAuthorizationEncryptionEncValuesSupported(["A256GCM"])
        XCTAssertEqual(result, [.A256GCM])
    }

    func testParseAuthorizationEncryptionEncValuesSupportedThrowsForUnsupportedValue() {
        XCTAssertThrowsError(try parseAuthorizationEncryptionEncValuesSupported(["A128CBC-HS256"])) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Invalid ContentEncryptionAlgorithm value: A128CBC-HS256. Its is not supported by the library.",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    // MARK: - validateVPFormatsSupported (VPFormatSupportedV2)

    func testValidateVPFormatsSupportedV2ThrowsWhenEmpty() {
        let emptyFormats: [VPFormatType: VPFormatSupported] = [:]
        XCTAssertThrowsError(try validateVPFormatsSupported(emptyFormats)) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "vp_formats_supported should at least have one supported vp_format",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testValidateVPFormatsSupportedV2DoesNotThrowWhenNonEmpty() {
        let formats: [VPFormatType: VPFormatSupported] = [.ldp_vc: LdpVcFormatSupported()]
        XCTAssertNoThrow(try validateVPFormatsSupported(formats))
    }

    // MARK: - validateVPFormatsSupported (VPFormatSupported)

//    func testValidateVPFormatsSupportedThrowsWhenEmpty() {
//        let emptyFormats: [VPFormatType: VPFormatSupported] = [:]
//        XCTAssertThrowsError(try validateVPFormatsSupported(emptyFormats)) { error in
//            assertOpenID4VPException(
//                error,
//                expectedMessage: "vp_formats_supported should at least have one supported vp_format",
//                expectedCode: OpenID4VPErrorCodes.invalidRequest
//            )
//        }
//    }
//
//    func testValidateVPFormatsSupportedDoesNotThrowWhenNonEmpty() {
//        let formats: [VPFormatType: VPFormatSupported] = [.ldp_vc: VPFormatSupported(algValuesSupported: ["EdDSA"])]
//        XCTAssertNoThrow(try validateVPFormatsSupported(formats))
//    }

    // MARK: - parseClientIdSchemesSupported

    func testParseClientIdSchemesSupportedReturnsDefaultWhenNil() throws {
        let result = try parseClientIdSchemesSupported(nil)
        XCTAssertEqual(result, [.preRegistered])
    }

    func testParseClientIdSchemesSupportedParsesValidValues() throws {
        let result = try parseClientIdSchemesSupported(["pre-registered", "redirect_uri", "did"])
        XCTAssertEqual(result, [.preRegistered, .redirectUri, .did])
    }

    func testParseClientIdSchemesSupportedThrowsForUnsupportedValue() {
        XCTAssertThrowsError(try parseClientIdSchemesSupported(["https"])) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Invalid ClientIdScheme value: https. Its is not supported by the library.",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    // MARK: - parseVPFormatsSupported (VPFormatSupported)
//
//    func testParseVPFormatsSupportedParsesValidFormats() throws {
//        let formats: [String: VPFormatSupported] = [
//            "ldp_vc": VPFormatSupported(algValuesSupported: ["EdDSA"]),
//            "mso_mdoc": VPFormatSupported(algValuesSupported: ["ES256"])
//        ]
//        let result = try parseVPFormatsSupported(formats)
//        XCTAssertEqual(result.count, 2)
//        XCTAssertNotNil(result[.ldp_vc])
//        XCTAssertNotNil(result[.mso_mdoc])
//    }
//
//    func testParseVPFormatsSupportedThrowsForUnsupportedFormatKey() {
//        let formats: [String: VPFormatSupported] = [
//            "sd-jwt": VPFormatSupported(algValuesSupported: ["EdDSA"])
//        ]
//        XCTAssertThrowsError(try parseVPFormatsSupported(formats)) { error in
//            assertOpenID4VPException(
//                error,
//                expectedMessage: "Invalid VPFormatType value: sd-jwt. Its is not supported by the library.",
//                expectedCode: OpenID4VPErrorCodes.invalidRequest
//            )
//        }
//    }
//
//    func testParseVPFormatsSupportedThrowsForEmptyKey() {
//        let formats: [String: VPFormatSupported] = [
//            "": VPFormatSupported(algValuesSupported: ["EdDSA"])
//        ]
//        XCTAssertThrowsError(try parseVPFormatsSupported(formats)) { error in
//            assertOpenID4VPException(
//                error,
//                expectedMessage: "vp_formats_supported cannot have empty keys.",
//                expectedCode: OpenID4VPErrorCodes.invalidRequest
//            )
//        }
//    }

    // MARK: - WalletMetadataDefaults

    func testWalletMetadataDefaultsValues() {
        XCTAssertTrue(WalletMetadataDefaults.presentationDefinitionURISupported)
//        XCTAssertFalse(WalletMetadataDefaults.vpFormatsSupportedSpecVersionDraft23.isEmpty)
        XCTAssertFalse(WalletMetadataDefaults.vpFormatsSupported.isEmpty)
        XCTAssertEqual(WalletMetadataDefaults.clientIdPrefixesSupported, [.preRegistered, .redirectUri, .decentralizedIdentifier])
        XCTAssertEqual(WalletMetadataDefaults.requestObjectSigningAlgValuesSupported, [.edDsa])
        XCTAssertEqual(WalletMetadataDefaults.authorizationEncryptionAlgValuesSupported, [.ecdhEs])
        XCTAssertEqual(WalletMetadataDefaults.authorizationEncryptionEncValuesSupported, [.A256GCM])
        XCTAssertEqual(WalletMetadataDefaults.responseTypesSupported, [.vp_token])
    }

    func testWalletMetadataDefaultsVpFormatsSupportedSpecVersion1ContainsExpectedFormats() {
        let formats = WalletMetadataDefaults.vpFormatsSupported
        XCTAssertNotNil(formats[.ldp_vc])
        XCTAssertNotNil(formats[.mso_mdoc])
        XCTAssertNotNil(formats[.dc_sd_jwt])
    }
}
