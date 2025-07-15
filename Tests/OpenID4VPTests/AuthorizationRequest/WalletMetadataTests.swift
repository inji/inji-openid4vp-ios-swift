import XCTest
@testable import OpenID4VP

final class WalletMetadataTests: XCTestCase {

    func testValidWalletMetadataInitialization() throws {
        let vpFormats: [FormatType: VPFormatSupported] = [
            .ldp_vc : VPFormatSupported(algValuesSupported: ["Ed25519Signature2018"])
        ]

        let metadata = try WalletMetadata(
            presentationDefinitionURISupported: true,
            vpFormatsSupported: vpFormats,
            clientIdSchemesSupported: [ClientIdScheme.redirectUri],
            requestObjectSigningAlgValuesSupported: [.edDsa],
            authorizationEncryptionAlgValuesSupported: [.ecdhEs],
            authorizationEncryptionEncValuesSupported: [.A256GCM]
        )

        XCTAssertTrue(metadata.presentationDefinitionURISupported)
        XCTAssertEqual(metadata.vpFormatsSupported.count, 1)
    }

    func testWalletMetadataThrowsForEmptyVPFormatsSupported() {
        XCTAssertThrowsError(try WalletMetadata(
            presentationDefinitionURISupported: nil,
            vpFormatsSupported: [:],
            clientIdSchemesSupported: nil
        )) { error in
            assertOpenID4VPException(error,
                expectedMessage: "vp_formats_supported should at least have one supported vp_format",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }


    func testWalletMetadataWithNilOptionals() throws {
        let vpFormats: [FormatType: VPFormatSupported] = [
            .ldp_vc: VPFormatSupported(algValuesSupported: ["Ed25519Signature2018"])
        ]

        let metadata = try WalletMetadata(
            presentationDefinitionURISupported: nil,
            vpFormatsSupported: vpFormats,
            clientIdSchemesSupported: nil
        )
        let walletMetadata = try createWalletMetadata(presentationDefinitionURISupported: true, vpFormatsSupported: vpFormats,
                                                      clientIdSchemesSupported: [.preRegistered], requestObjectSigningAlgValuesSupported: nil, authorizationEncryptionAlgValuesSupported: nil, authorizationEncryptionEncValuesSupported: nil)

        assertDictionariesEqual(expected: convertToDictionary(object: walletMetadata)!, actual: convertToDictionary(object: metadata))
        XCTAssertNil(metadata.requestObjectSigningAlgValuesSupported)
        XCTAssertNil(metadata.authorizationEncryptionAlgValuesSupported)
        XCTAssertNil(metadata.authorizationEncryptionEncValuesSupported)
    }
}
