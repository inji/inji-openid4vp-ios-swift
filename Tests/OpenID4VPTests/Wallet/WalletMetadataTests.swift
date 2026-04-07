import XCTest
@testable import OpenID4VP

final class WalletMetadataTests: XCTestCase {
    func testInitWithAllFields() {
        let ldpVc = LdpVcFormatSupported(proofTypeValues: [.ed25519Signature2020], cryptoSuiteValues: ["suite1"])
        let msoMdoc = MsoMdocVcFormatSupported(issuerAuthAlgValues: [-7], deviceAuthAlgValues: [-9])
        let sdJwt = SdJwtVcFormatSupported(sdJwtAlgValues: ["alg3"], kbJwtAlgValues: ["alg4"])
        let vpFormats: [VPFormatType: VPFormatSupported] = [
            .ldp_vc: ldpVc,
            .mso_mdoc: msoMdoc,
            .dc_sd_jwt: sdJwt
        ]
        let clientIdPrefixes: [ClientIdPrefix] = [.preRegistered, .redirectUri, .decentralizedIdentifier]
        let requestAlgs: [RequestSigningAlgorithm] = [.edDsa]
        let keyAlgs: [KeyManagementAlgorithm] = [.ecdhEs]
        let encAlgs: [ContentEncryptionAlgorithm] = [.A256GCM]
        let responseTypes: [ResponseType] = [.vp_token]
        let metadata = WalletMetadata(
            vpFormatsSupported: vpFormats,
            clientIdPrefixesSupported: clientIdPrefixes,
            requestObjectSigningAlgValuesSupported: requestAlgs,
            authorizationEncryptionAlgValuesSupported: keyAlgs,
            authorizationEncryptionEncValuesSupported: encAlgs,
            responseTypesSupported: responseTypes
        )
        XCTAssertEqual(metadata.vpFormatsSupported.count, 3)
        XCTAssertEqual(metadata.clientIdPrefixesSupported, clientIdPrefixes)
        XCTAssertEqual(metadata.requestObjectSigningAlgValuesSupported, requestAlgs)
        XCTAssertEqual(metadata.authorizationEncryptionAlgValuesSupported, keyAlgs)
        XCTAssertEqual(metadata.authorizationEncryptionEncValuesSupported, encAlgs)
        XCTAssertEqual(metadata.responseTypesSupported, responseTypes)
    }

    func testInitWithDefaults() {
        let metadata = WalletMetadata()
        XCTAssertFalse(metadata.vpFormatsSupported.isEmpty)
        XCTAssertFalse(metadata.clientIdPrefixesSupported.isEmpty)
        XCTAssertNotNil(metadata.requestObjectSigningAlgValuesSupported)
        XCTAssertNotNil(metadata.authorizationEncryptionAlgValuesSupported)
        XCTAssertNotNil(metadata.authorizationEncryptionEncValuesSupported)
        XCTAssertFalse(metadata.responseTypesSupported.isEmpty)
    }

    func testEncodingAndDecoding() throws {
        let ldpVc = LdpVcFormatSupported(proofTypeValues: [.ed25519Signature2020], cryptoSuiteValues: ["suite1"])
        let msoMdoc = MsoMdocVcFormatSupported(issuerAuthAlgValues: [-7], deviceAuthAlgValues: [-9])
        let sdJwt = SdJwtVcFormatSupported(sdJwtAlgValues: ["alg3"], kbJwtAlgValues: ["alg4"])
        let vpFormats: [VPFormatType: VPFormatSupported] = [
            .ldp_vc: ldpVc,
            .mso_mdoc: msoMdoc,
            .dc_sd_jwt: sdJwt
        ]
        let metadata = WalletMetadata(
            vpFormatsSupported: vpFormats,
            clientIdPrefixesSupported: [.preRegistered],
            requestObjectSigningAlgValuesSupported: [.edDsa],
            authorizationEncryptionAlgValuesSupported: [.ecdhEs],
            authorizationEncryptionEncValuesSupported: [.A256GCM],
            responseTypesSupported: [.vp_token]
        )
        let encoder = JSONEncoder()
        let data = try encoder.encode(metadata)
        let decoder = JSONDecoder()
        let decoded = try decoder.decode(WalletMetadata.self, from: data)
        XCTAssertEqual(decoded.vpFormatsSupported.count, 3)
        XCTAssertEqual(decoded.clientIdPrefixesSupported, [.preRegistered])
        XCTAssertEqual(decoded.requestObjectSigningAlgValuesSupported, [.edDsa])
        XCTAssertEqual(decoded.authorizationEncryptionAlgValuesSupported, [.ecdhEs])
        XCTAssertEqual(decoded.authorizationEncryptionEncValuesSupported, [.A256GCM])
        XCTAssertEqual(decoded.responseTypesSupported, [.vp_token])
    }

    func testNilOptionals() {
        let ldpVc = LdpVcFormatSupported()
        let vpFormats: [VPFormatType: VPFormatSupported] = [ .ldp_vc: ldpVc ]
        let metadata = WalletMetadata(
            vpFormatsSupported: vpFormats,
            clientIdPrefixesSupported: [.preRegistered],
            requestObjectSigningAlgValuesSupported: nil,
            authorizationEncryptionAlgValuesSupported: nil,
            authorizationEncryptionEncValuesSupported: nil,
            responseTypesSupported: [.vp_token]
        )
        XCTAssertNil(metadata.requestObjectSigningAlgValuesSupported)
        XCTAssertNil(metadata.authorizationEncryptionAlgValuesSupported)
        XCTAssertNil(metadata.authorizationEncryptionEncValuesSupported)
    }

    func testInvalidCastThrows() {
        let jsonString = """
        {
            "vp_formats_supported": {
                "ldp_vc": { "issuerauth_alg_values": [-7], "deviceauth_alg_values": [-9] }
            },
            "client_id_prefixes_supported": ["pre-registered"],
            "response_types_supported": ["vp_token"]
        }
        """
        let data = jsonString.data(using: .utf8)!
        let decoder = JSONDecoder()
        XCTAssertThrowsError(try decoder.decode(WalletMetadata.self, from: data))
    }
}
