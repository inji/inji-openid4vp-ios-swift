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
    
    func testEncodeOfWalletMetadataSpecVersion1() throws {
        let metadata = WalletMetadata(
            vpFormatsSupported: [
                .ldp_vc: LdpVcFormatSupported(proofTypeValues: [.ed25519Signature2020]),
                .mso_mdoc: MsoMdocVcFormatSupported(issuerAuthAlgValues: [-7], deviceAuthAlgValues: [-9])
            ],
            clientIdPrefixesSupported: [.preRegistered, .decentralizedIdentifier],
            requestObjectSigningAlgValuesSupported: [.edDsa],
            authorizationEncryptionAlgValuesSupported: [.ecdhEs],
            authorizationEncryptionEncValuesSupported: [.A256GCM],
            responseTypesSupported: [.vp_token]
        )
        let encoded = try metadata.encode(specVersion: .v1)
        let json = try JSONSerialization.jsonObject(with: encoded.data(using: .utf8)!) as! [String: Any]

        XCTAssertNotNil(json["vp_formats_supported"])
        XCTAssertNotNil(json["client_id_prefixes_supported"])
        XCTAssertNotNil(json["request_object_signing_alg_values_supported"])
        XCTAssertNotNil(json["authorization_encryption_alg_values_supported"])
        XCTAssertNotNil(json["authorization_encryption_enc_values_supported"])
        XCTAssertNotNil(json["response_types_supported"])

        let clientIdPrefixes = json["client_id_prefixes_supported"] as! [String]
        XCTAssertTrue(clientIdPrefixes.contains("pre-registered"))
        XCTAssertTrue(clientIdPrefixes.contains("decentralized_identifier"))

        let requestAlgs = json["request_object_signing_alg_values_supported"] as! [String]
        XCTAssertEqual(requestAlgs, ["EdDSA"])

        let encAlgs = json["authorization_encryption_alg_values_supported"] as! [String]
        XCTAssertEqual(encAlgs, ["ECDH-ES"])

        let encValues = json["authorization_encryption_enc_values_supported"] as! [String]
        XCTAssertEqual(encValues, ["A256GCM"])

        let responseTypes = json["response_types_supported"] as! [String]
        XCTAssertEqual(responseTypes, ["vp_token"])
    }

    func testEncodeOfWalletMetadataSpecVersionDraft_23() throws {
        let metadata = WalletMetadata(
            vpFormatsSupported: [
                .ldp_vc: LdpVcFormatSupported(proofTypeValues: [.ed25519Signature2020]),
                .mso_mdoc: MsoMdocVcFormatSupported(issuerAuthAlgValues: [-7], deviceAuthAlgValues: [-9]),
                .dc_sd_jwt: SdJwtVcFormatSupported()
            ],
            clientIdPrefixesSupported: [.preRegistered, .redirectUri, .decentralizedIdentifier],
            requestObjectSigningAlgValuesSupported: [.edDsa],
            authorizationEncryptionAlgValuesSupported: [.ecdhEs],
            authorizationEncryptionEncValuesSupported: [.A256GCM],
            responseTypesSupported: [.vp_token]
        )
        let encoded = try metadata.encode(specVersion: .draft23)
        let json = try JSONSerialization.jsonObject(with: encoded.data(using: .utf8)!) as! [String: Any]

        XCTAssertEqual(json["presentation_definition_uri_supported"] as? Bool, true)

        let vpFormats = json["vp_formats_supported"] as! [String: Any]
        XCTAssertNotNil(vpFormats["ldp_vc"])
        XCTAssertNotNil(vpFormats["mso_mdoc"])
        let ldpVcFormat = vpFormats["ldp_vc"] as! [String: Any]
        let ldpAlgValues = ldpVcFormat["alg_values_supported"] as! [String]
        XCTAssertTrue(ldpAlgValues.contains("Ed25519Signature2020"))
        let mdocFormat = vpFormats["mso_mdoc"] as! [String: Any]
        let mdocAlgValues = mdocFormat["alg_values_supported"] as! [String]
        XCTAssertTrue(mdocAlgValues.contains("ESP256"))
        let dcSdJwtVcFormat = vpFormats["dc+sd-jwt"] as! [String: Any]
        XCTAssertTrue(dcSdJwtVcFormat.isEmpty)

        let clientIdSchemes = json["client_id_schemes_supported"] as! [String]
        XCTAssertTrue(clientIdSchemes.contains("pre-registered"))
        XCTAssertTrue(clientIdSchemes.contains("redirect_uri"))
        XCTAssertTrue(clientIdSchemes.contains("did"))

        let requestAlgs = json["request_object_signing_alg_values_supported"] as! [String]
        XCTAssertEqual(requestAlgs, ["EdDSA"])

        let encAlgs = json["authorization_encryption_alg_values_supported"] as! [String]
        XCTAssertEqual(encAlgs, ["ECDH-ES"])

        let encValues = json["authorization_encryption_enc_values_supported"] as! [String]
        XCTAssertEqual(encValues, ["A256GCM"])

        let responseTypes = json["response_types_supported"] as! [String]
        XCTAssertEqual(responseTypes, ["vp_token"])
    }

    func testEncodeOfWalletMetadataSpecVersionDraft_23OmitsNilOptionals() throws {
        let metadata = WalletMetadata(
            vpFormatsSupported: [.ldp_vc: LdpVcFormatSupported()],
            clientIdPrefixesSupported: [.preRegistered],
            requestObjectSigningAlgValuesSupported: nil,
            authorizationEncryptionAlgValuesSupported: nil,
            authorizationEncryptionEncValuesSupported: nil,
            responseTypesSupported: [.vp_token]
        )
        let encoded = try metadata.encode(specVersion: .draft23)
        let json = try JSONSerialization.jsonObject(with: encoded.data(using: .utf8)!) as! [String: Any]

        XCTAssertNil(json["request_object_signing_alg_values_supported"])
        XCTAssertNil(json["authorization_encryption_alg_values_supported"])
        XCTAssertNil(json["authorization_encryption_enc_values_supported"])
    }

    func testEncodeOfWalletMetadataSpecVersion1OmitsNilOptionals() throws {
        let metadata = WalletMetadata(
            vpFormatsSupported: [.ldp_vc: LdpVcFormatSupported()],
            clientIdPrefixesSupported: [.preRegistered],
            requestObjectSigningAlgValuesSupported: nil,
            authorizationEncryptionAlgValuesSupported: nil,
            authorizationEncryptionEncValuesSupported: nil,
            responseTypesSupported: [.vp_token]
        )
        let encoded = try metadata.encode(specVersion: .v1)
        let json = try JSONSerialization.jsonObject(with: encoded.data(using: .utf8)!) as! [String: Any]

        XCTAssertNil(json["request_object_signing_alg_values_supported"])
        XCTAssertNil(json["authorization_encryption_alg_values_supported"])
        XCTAssertNil(json["authorization_encryption_enc_values_supported"])
    }

    func testEncodeOfWalletMetadataSpecVersionDraft_23MapsDecentralizedIdentifierToDid() throws {
        let metadata = WalletMetadata(
            vpFormatsSupported: [.ldp_vc: LdpVcFormatSupported()],
            clientIdPrefixesSupported: [.decentralizedIdentifier],
            responseTypesSupported: [.vp_token]
        )
        let encoded = try metadata.encode(specVersion: .draft23)
        let json = try JSONSerialization.jsonObject(with: encoded.data(using: .utf8)!) as! [String: Any]

        let clientIdSchemes = json["client_id_schemes_supported"] as! [String]
        XCTAssertEqual(clientIdSchemes, ["did"])
    }
}
