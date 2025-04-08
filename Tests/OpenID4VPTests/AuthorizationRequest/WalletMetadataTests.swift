import XCTest
@testable import OpenID4VP

final class WalletMetadataTests: XCTestCase {
    
    func testValidWalletMetadataInitialization() throws {
        let vpFormats: [String: VPFormatSupported] = [
            "ldp_vc": VPFormatSupported(algValuesSupported: ["Ed25519Signature2018"])
        ]
        
        let metadata = try WalletMetadata(
            presentationDefinitionURISupported: true,
            vpFormatsSupported: vpFormats,
            clientIdSchemesSupported: ["redirect_uri"],
            requestObjectSigningAlgValuesSupported: ["EdDSA"],
            authorizationEncryptionAlgValuesSupported: ["ECDH-ES"],
            authorizationEncryptionEncValuesSupported: ["A256GCM"]
        )
        
        XCTAssertTrue(metadata.presentationDefinitionURISupported)
        XCTAssertEqual(metadata.vpFormatsSupported.count, 1)
    }
    
    func testWalletMetadataThrowsForEmptyVPFormatsSupported() {
        XCTAssertThrowsError(try WalletMetadata(
            vpFormatsSupported: [:]
        )) { error in
            XCTAssertEqual(error.localizedDescription, "vp_formats_supported should at least have one supported vp_format")
        }
    }
    
    func testWalletMetadataThrowsForEmptyKeyInVPFormatsSupported() {
        let badVPFormat: [String: VPFormatSupported] = [
            "": VPFormatSupported(algValuesSupported: ["Ed25519Signature2018"])
        ]
        
        XCTAssertThrowsError(try WalletMetadata(
            vpFormatsSupported: badVPFormat
        )) { error in
            XCTAssertEqual(error.localizedDescription, "vp_formats_supported cannot have empty keys.")
        }
    }
    
    func testWalletMetadataWithNilOptionals() throws {
        let vpFormats: [String: VPFormatSupported] = [
            "ldp_vc": VPFormatSupported(algValuesSupported: ["Ed25519Signature2018"])
        ]
        
        let metadata = try WalletMetadata(
            vpFormatsSupported: vpFormats
        )
        let walletMetadata = try createWalletMetadata(presentationDefinitionURISupported: true, vpFormatsSupported: vpFormats,
                                                      clientIdSchemesSupported: ["pre-registered"], requestObjectSigningAlgValuesSupported: nil, authorizationEncryptionAlgValuesSupported: nil, authorizationEncryptionEncValuesSupported: nil)
        
        assertDictionariesEqual(expected: convertToDictionary(object: walletMetadata)!, actual: convertToDictionary(object: metadata))
        XCTAssertNil(metadata.requestObjectSigningAlgValuesSupported)
        XCTAssertNil(metadata.authorizationEncryptionAlgValuesSupported)
        XCTAssertNil(metadata.authorizationEncryptionEncValuesSupported)
    }
}
