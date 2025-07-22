import XCTest
@testable import OpenID4VP

final class WalletMetadataTests: XCTestCase {
    let vpFormatsRaw: [String: VPFormatSupported] = [
        "ldp_vc": VPFormatSupported(algValuesSupported: ["Ed25519Signature2018"])
    ]
    let vpFormats: [VPFormatType: VPFormatSupported] = [
        .ldp_vc : VPFormatSupported(algValuesSupported: ["Ed25519Signature2018"])
    ]
    let clientIdSchemesSupportedRaw: [String] = [
        "pre_registered",
        "redirect_uri",
        "did"
    ]
    let requestObjectSigningAlgValuesSupportedRaw: [String] = ["ed_dsa"]
    let authorizationEncryptionAlgValuesSupportedRaw: [String] = ["ecdh_es"]
    let authorizationEncryptionEncValuesSupportedRaw: [String] = ["A256GCM"]
    
    func testValidWalletMetadataInitialization() throws {
        
        
        let metadata = try WalletMetadata(
            presentationDefinitionURISupported: true,
            vpFormatsSupported: vpFormatsRaw,
            clientIdSchemesSupported: clientIdSchemesSupportedRaw,
            requestObjectSigningAlgValuesSupported: requestObjectSigningAlgValuesSupportedRaw,
            authorizationEncryptionAlgValuesSupported: authorizationEncryptionAlgValuesSupportedRaw,
            authorizationEncryptionEncValuesSupported: authorizationEncryptionAlgValuesSupportedRaw
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
        let metadata = try WalletMetadata(
            presentationDefinitionURISupported: nil,
            vpFormatsSupported: vpFormatsRaw,
            clientIdSchemesSupported: nil
        )
        let walletMetadata = try createWalletMetadataV1(presentationDefinitionURISupported: true, vpFormatsSupported: vpFormatsRaw,
                                                        clientIdSchemesSupported: [ClientIdScheme.preRegistered.rawValue], requestObjectSigningAlgValuesSupported: nil, authorizationEncryptionAlgValuesSupported: nil, authorizationEncryptionEncValuesSupported: nil)
        
        assertDictionariesEqual(expected: convertToDictionary(object: walletMetadata)!, actual: convertToDictionary(object: metadata))
        XCTAssertNil(metadata.requestObjectSigningAlgValuesSupported)
        XCTAssertNil(metadata.authorizationEncryptionAlgValuesSupported)
        XCTAssertNil(metadata.authorizationEncryptionEncValuesSupported)
    }
    
    func testWalletMetadataDefaults() throws {
        let metadata = try WalletMetadata()
        
        XCTAssertTrue(metadata.presentationDefinitionURISupported)
        XCTAssertEqual(metadata.requestObjectSigningAlgValuesSupported, [.edDsa])
        XCTAssertEqual(metadata.authorizationEncryptionAlgValuesSupported, [.ecdhEs])
        XCTAssertEqual(metadata.authorizationEncryptionEncValuesSupported, [.A256GCM])
        XCTAssertEqual(metadata.responseTypesSupported, [.vp_token])
        XCTAssertEqual(Set(metadata.clientIdSchemesSupported), Set([.preRegistered, .did, .redirectUri]))
        XCTAssertEqual(Set(metadata.vpFormatsSupported.keys), [.ldp_vc, .ldp_vp, .mso_mdoc])
    }
    
    func testWalletMetadataConstructor() throws {
        let metadata = try WalletMetadata(
            presentationDefinitionURISupported: true,
            vpFormatsSupported: vpFormats,
            clientIdSchemesSupported: [.preRegistered, .redirectUri, .did],
            requestObjectSigningAlgValuesSupported: [.edDsa],
            authorizationEncryptionAlgValuesSupported: [.ecdhEs],
            authorizationEncryptionEncValuesSupported: [.A256GCM]
        )
        
        XCTAssertTrue(metadata.presentationDefinitionURISupported)
        XCTAssertEqual(metadata.vpFormatsSupported.count, 1)
        XCTAssertEqual(metadata.clientIdSchemesSupported.count, 3)
        XCTAssertEqual(metadata.requestObjectSigningAlgValuesSupported, [.edDsa])
        XCTAssertEqual(metadata.authorizationEncryptionAlgValuesSupported, [.ecdhEs])
        XCTAssertEqual(metadata.authorizationEncryptionEncValuesSupported, [.A256GCM])

    }
}
