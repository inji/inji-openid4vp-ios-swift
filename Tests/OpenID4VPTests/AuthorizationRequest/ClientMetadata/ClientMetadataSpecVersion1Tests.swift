import XCTest
@testable import OpenID4VP

final class ClientMetadataSpecVersion1Tests: XCTestCase {

    private let validJwks = """
    {"keys": [{"kty": "EC", "use": "enc", "alg": "ECDH-ES", "kid": "1", "crv": "P-256", "x": "ur76rg", "y": "ur76rg"}]}
    """

    // MARK: - init (memberwise)

    func testInitStoresAllFields() {
        let ldp = LdpVcFormatSupported(proofTypeValues: [.ed25519Signature2020])
        let metadata = ClientMetadataSpecVersion1(
            clientName: "Client",
            logoUri: "https://example.com/logo.png",
            vpFormatsSupported: ["ldp_vc": ldp],
            authorizationEncryptedResponseAlg: "ECDH-ES",
            authorizationEncryptedResponseEncValuesSupported: ["A256GCM"],
            jwks: nil
        )
        XCTAssertEqual(metadata.clientName, "Client")
        XCTAssertEqual(metadata.logoUri, "https://example.com/logo.png")
        XCTAssertEqual(metadata.vpFormatsSupported.count, 1)
        XCTAssertEqual(metadata.authorizationEncryptedResponseAlg, "ECDH-ES")
        XCTAssertEqual(metadata.authorizationEncryptedResponseEncValuesSupported, ["A256GCM"])
        XCTAssertNil(metadata.jwks)
    }

    func testInitAllOptionalFieldsNil() {
        let metadata = ClientMetadataSpecVersion1(
            vpFormatsSupported: [:]
        )
        XCTAssertNil(metadata.clientName)
        XCTAssertNil(metadata.logoUri)
        XCTAssertNil(metadata.authorizationEncryptedResponseAlg)
        XCTAssertNil(metadata.authorizationEncryptedResponseEncValuesSupported)
        XCTAssertNil(metadata.jwks)
    }

    // MARK: - init(from decoder)

    func testDecodeAllFields() throws {
        let data = json(jwks: validJwks)
        let decoded = try JSONDecoder().decode(ClientMetadataSpecVersion1.self, from: data)
        XCTAssertEqual(decoded.clientName, "Test Client")
        XCTAssertEqual(decoded.logoUri, "https://example.com/logo.png")
        XCTAssertEqual(decoded.authorizationEncryptedResponseAlg, "ECDH-ES")
        XCTAssertEqual(decoded.authorizationEncryptedResponseEncValuesSupported, ["A256GCM"])
        XCTAssertNotNil(decoded.jwks)
        XCTAssertEqual(decoded.vpFormatsSupported.count, 1)
        XCTAssertNotNil(decoded.vpFormatsSupported["ldp_vc"] as? LdpVcFormatSupported)
    }

    func testDecodeOptionalFieldsAbsent() throws {
        let data = "{ \"vp_formats_supported\": {\"ldp_vc\": {}} }".data(using: .utf8)!
        let decoded = try JSONDecoder().decode(ClientMetadataSpecVersion1.self, from: data)
        XCTAssertNil(decoded.clientName)
        XCTAssertNil(decoded.logoUri)
        XCTAssertNil(decoded.authorizationEncryptedResponseAlg)
        XCTAssertNil(decoded.authorizationEncryptedResponseEncValuesSupported)
        XCTAssertNil(decoded.jwks)
    }

    func testDecodeVpFormatsSupportedLdpVc() throws {
        let data = json()
        let decoded = try JSONDecoder().decode(ClientMetadataSpecVersion1.self, from: data)
        let ldp = decoded.vpFormatsSupported["ldp_vc"] as? LdpVcFormatSupported
        XCTAssertNotNil(ldp)
        XCTAssertEqual(ldp?.proofTypeValues, [.ed25519Signature2020])
    }

    func testDecodeVpFormatsSupportedLdpVp() throws {
        let data = json(vpFormatsSupported: """
        {"ldp_vp": {"proof_type_values": ["JsonWebSignature2020"]}}
        """)
        let decoded = try JSONDecoder().decode(ClientMetadataSpecVersion1.self, from: data)
        XCTAssertNotNil(decoded.vpFormatsSupported["ldp_vp"] as? LdpVcFormatSupported)
    }

    func testDecodeVpFormatsSupportedMsoMdoc() throws {
        let data = json(vpFormatsSupported: """
        {"mso_mdoc": {"issuerauth_alg_values": [-7], "deviceauth_alg_values": [-9]}}
        """)
        let decoded = try JSONDecoder().decode(ClientMetadataSpecVersion1.self, from: data)
        let mdoc = decoded.vpFormatsSupported["mso_mdoc"] as? MsoMdocVcFormatSupported
        XCTAssertNotNil(mdoc)
        XCTAssertEqual(mdoc?.issuerAuthAlgValues, [-7])
        XCTAssertEqual(mdoc?.deviceAuthAlgValues, [-9])
    }

    func testDecodeVpFormatsSupportedDcSdJwt() throws {
        let data = json(vpFormatsSupported: """
        {"dc+sd-jwt": {"sd-jwt_alg_values": ["ES256"], "kb-jwt_alg_values": ["EdDSA"]}}
        """)
        let decoded = try JSONDecoder().decode(ClientMetadataSpecVersion1.self, from: data)
        let sdJwt = decoded.vpFormatsSupported["dc+sd-jwt"] as? SdJwtVcFormatSupported
        XCTAssertNotNil(sdJwt)
        XCTAssertEqual(sdJwt?.sdJwtAlgValues, ["ES256"])
        XCTAssertEqual(sdJwt?.kbJwtAlgValues, ["EdDSA"])
    }

    func testDecodeVpFormatsSupportedVcSdJwt() throws {
        let data = json(vpFormatsSupported: """
        {"vc+sd-jwt": {"sd-jwt_alg_values": ["ES256"]}}
        """)
        let decoded = try JSONDecoder().decode(ClientMetadataSpecVersion1.self, from: data)
        XCTAssertNotNil(decoded.vpFormatsSupported["vc+sd-jwt"] as? SdJwtVcFormatSupported)
    }

    // MARK: - encode(to encoder)

    func testEncodeRoundTrip() throws {
        let ldp = LdpVcFormatSupported(proofTypeValues: [.ed25519Signature2020])
        let original = ClientMetadataSpecVersion1(
            clientName: "Client",
            logoUri: "https://example.com/logo.png",
            vpFormatsSupported: ["ldp_vc": ldp],
            authorizationEncryptedResponseAlg: "ECDH-ES",
            authorizationEncryptedResponseEncValuesSupported: ["A256GCM"],
            jwks: nil
        )
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(ClientMetadataSpecVersion1.self, from: data)
        XCTAssertEqual(decoded.clientName, original.clientName)
        XCTAssertEqual(decoded.logoUri, original.logoUri)
        XCTAssertEqual(decoded.authorizationEncryptedResponseAlg, original.authorizationEncryptedResponseAlg)
        XCTAssertEqual(decoded.authorizationEncryptedResponseEncValuesSupported, original.authorizationEncryptedResponseEncValuesSupported)
        XCTAssertEqual(decoded.vpFormatsSupported.count, original.vpFormatsSupported.count)
    }

    func testEncodeOmitsNilOptionalFields() throws {
        let metadata = ClientMetadataSpecVersion1(
            vpFormatsSupported: ["ldp_vc": LdpVcFormatSupported()]
        )
        let data = try JSONEncoder().encode(metadata)
        let json = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        XCTAssertNil(json["client_name"])
        XCTAssertNil(json["logo_uri"])
        XCTAssertNil(json["authorization_encrypted_response_alg"])
        XCTAssertNil(json["encrypted_response_enc_values_supported"])
        XCTAssertNil(json["jwks"])
    }

    func testEncodeVpFormatsSupportedSkipsUnknownFormatType() throws {
        let metadata = ClientMetadataSpecVersion1(
            vpFormatsSupported: ["unknown_format": LdpVcFormatSupported()]
        )
        let data = try JSONEncoder().encode(metadata)
        let json = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        let vpFormats = json["vp_formats_supported"] as! [String: Any]
        XCTAssertTrue(vpFormats.isEmpty)
    }

    func testEncodeVpFormatsSupportedMsoMdoc() throws {
        let mdoc = MsoMdocVcFormatSupported(issuerAuthAlgValues: [-7], deviceAuthAlgValues: [-9])
        let metadata = ClientMetadataSpecVersion1(
            vpFormatsSupported: ["mso_mdoc": mdoc]
        )
        let data = try JSONEncoder().encode(metadata)
        let json = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        let vpFormats = json["vp_formats_supported"] as! [String: Any]
        XCTAssertNotNil(vpFormats["mso_mdoc"])
    }

    func testEncodeVpFormatsSupportedSdJwt() throws {
        let sdJwt = SdJwtVcFormatSupported(sdJwtAlgValues: ["ES256"], kbJwtAlgValues: ["EdDSA"])
        let metadata = ClientMetadataSpecVersion1(
            vpFormatsSupported: ["dc+sd-jwt": sdJwt]
        )
        let data = try JSONEncoder().encode(metadata)
        let json = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        let vpFormats = json["vp_formats_supported"] as! [String: Any]
        XCTAssertNotNil(vpFormats["dc+sd-jwt"])
    }

    // MARK: - deserializeAndValidate(clientMetadata: Data)

    func testDeserializeAndValidateWithData() throws {
        let data = json()
        let result = try ClientMetadataSpecVersion1.deserializeAndValidate(clientMetadata: data)
        XCTAssertEqual(result.clientName, "Test Client")
    }

    // MARK: - deserializeAndValidate(clientMetadata: String)

    func testDeserializeAndValidateWithString() throws {
        let jsonString = String(data: json(), encoding: .utf8)!
        let result = try ClientMetadataSpecVersion1.deserializeAndValidate(clientMetadata: jsonString)
        XCTAssertEqual(result.clientName, "Test Client")
    }

    func testDeserializeAndValidateWithStringThrowsOnInvalidUTF8() {
        XCTAssertThrowsError(
            try ClientMetadataSpecVersion1.deserializeAndValidate(clientMetadata: 12345)
        )
    }

    func testDeserializeAndValidateThrowsForInvalidType() {
        XCTAssertThrowsError(
            try ClientMetadataSpecVersion1.deserializeAndValidate(clientMetadata: 12345)
        )
    }
    
    
    // MARK: - Helper methods
    
    private func json(
        clientName: String? = "\"Test Client\"",
        logoUri: String? = "\"https://example.com/logo.png\"",
        vpFormatsSupported: String = """
        {"ldp_vc": {"proof_type_values": ["Ed25519Signature2020"]}}
        """,
        authorizationEncryptedResponseAlg: String? = "\"ECDH-ES\"",
        authorizationEncryptedResponseEncValues: String? = "[\"A256GCM\"]",
        jwks: String? = nil
    ) -> Data {
        let jwksField = jwks.map { "\"jwks\": \($0)" } ?? "\"jwks\": {\"keys\": []}"
        let fields: [String] = [
            clientName.map { "\"client_name\": \($0)" },
            logoUri.map { "\"logo_uri\": \($0)" },
            "\"vp_formats_supported\": \(vpFormatsSupported)",
            authorizationEncryptedResponseAlg.map { "\"authorization_encrypted_response_alg\": \($0)" },
            authorizationEncryptedResponseEncValues.map { "\"encrypted_response_enc_values_supported\": \($0)" },
            jwksField
        ].compactMap { $0 }
        return "{\(fields.joined(separator: ", "))}".data(using: .utf8)!
    }
}
