import XCTest
@testable import OpenID4VP

// https://github.com/inji/inji-wallet/issues/2531
// Test: oid4vp-1final-wallet-ignores-unusable-encryption-key
final class LenientJWKSetTests: XCTestCase {

    // A JWKS with one usable EC encryption key, a post-quantum AKP/ML-KEM key
    // and a key with an unsupported key type.
    private let mixedJwks = """
    {
        "keys": [
            {
                "kty": "EC",
                "use": "enc",
                "alg": "ECDH-ES",
                "kid": "valid-enc-key",
                "crv": "P-256",
                "x": "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
                "y": "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps"
            },
            {
                "kty": "AKP",
                "alg": "ML-KEM-9999",
                "use": "enc",
                "kid": "post-quantum-key"
            },
            {
                "kty": "OIDF-CONFORMANCE-UNSUPPORTED",
                "use": "enc",
                "kid": "unsupported-key"
            }
        ]
    }
    """

    func testDraft23IgnoresUnusableEncryptionKeys() throws {
        let input = """
        {
            "client_name": "Test Client",
            "logo_uri": "https://example.com/logo.png",
            "authorization_encrypted_response_alg": "ECDH-ES",
            "authorization_encrypted_response_enc": "A256GCM",
            "vp_formats": { "ldp_vp": { "proof_type_values": ["Ed25519Signature2020"] } },
            "jwks": \(mixedJwks)
        }
        """.data(using: .utf8)!

        let metadata = try ClientMetadataDraft23.deserializeAndValidate(clientMetadata: input)

        XCTAssertEqual(metadata.jwks?.keys.count, 1)
        XCTAssertEqual(metadata.jwks?.keys.first?.keyID, "valid-enc-key")
    }

    func testV1IgnoresUnusableEncryptionKeys() throws {
        let input = """
        {
            "client_name": "Test Client",
            "logo_uri": "https://example.com/logo.png",
            "encrypted_response_enc_values_supported": ["A256GCM"],
            "vp_formats_supported": { "ldp_vc": { "proof_type_values": ["Ed25519Signature2020"] } },
            "jwks": \(mixedJwks)
        }
        """.data(using: .utf8)!

        let metadata = try JSONDecoder().decode(ClientMetadata.self, from: input)

        XCTAssertEqual(metadata.jwks?.keys.count, 1)
        XCTAssertEqual(metadata.jwks?.keys.first?.keyID, "valid-enc-key")
    }

    func testDraft23StillRejectsExplicitNullJwks() {
        let input = """
        {
            "client_name": "Test Client",
            "logo_uri": "https://example.com/logo.png",
            "authorization_encrypted_response_alg": "ECDH-ES",
            "authorization_encrypted_response_enc": "A256GCM",
            "vp_formats": { "ldp_vp": { "proof_type_values": ["Ed25519Signature2020"] } },
            "jwks": null
        }
        """.data(using: .utf8)!

        XCTAssertThrowsError(try ClientMetadataDraft23.deserializeAndValidate(clientMetadata: input))
    }

    func testV1RejectsExplicitNullJwks() {
        let input = """
        {
            "client_name": "Test Client",
            "logo_uri": "https://example.com/logo.png",
            "encrypted_response_enc_values_supported": ["A256GCM"],
            "vp_formats_supported": { "ldp_vc": { "proof_type_values": ["Ed25519Signature2020"] } },
            "jwks": null
        }
        """.data(using: .utf8)!

        XCTAssertThrowsError(try JSONDecoder().decode(ClientMetadata.self, from: input))
    }

    func testV1AcceptsOmittedJwks() throws {
        let input = """
        {
            "client_name": "Test Client",
            "logo_uri": "https://example.com/logo.png",
            "encrypted_response_enc_values_supported": ["A256GCM"],
            "vp_formats_supported": { "ldp_vc": { "proof_type_values": ["Ed25519Signature2020"] } }
        }
        """.data(using: .utf8)!

        let metadata = try JSONDecoder().decode(ClientMetadata.self, from: input)

        XCTAssertNil(metadata.jwks)
    }
}
