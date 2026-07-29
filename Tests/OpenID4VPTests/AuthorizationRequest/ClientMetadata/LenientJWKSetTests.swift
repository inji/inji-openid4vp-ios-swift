import XCTest
@testable import OpenID4VP

// https://github.com/inji/inji-wallet/issues/2531
// Test: oid4vp-1final-wallet-ignores-unusable-encryption-key
final class LenientJWKSetTests: XCTestCase {

    // A single usable EC encryption key.
    private let validJwks = """
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
            }
        ]
    }
    """

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

    // MARK: - LenientJWKSet decoding

    func testParsesValidJwks() throws {
        let decoded = try JSONDecoder().decode(LenientJWKSet.self, from: validJwks.data(using: .utf8)!)

        XCTAssertEqual(decoded.keys.count, 1)
        XCTAssertEqual(decoded.jwkSet.keys.first?.keyID, "valid-enc-key")
    }

    func testIgnoresUnusableKeysAndKeepsValidOnes() throws {
        let decoded = try JSONDecoder().decode(LenientJWKSet.self, from: mixedJwks.data(using: .utf8)!)

        XCTAssertEqual(decoded.keys.count, 1)
        XCTAssertEqual(decoded.jwkSet.keys.first?.keyID, "valid-enc-key")
    }

    func testDefaultsToEmptyKeysWhenKeysArrayMissing() throws {
        let decoded = try JSONDecoder().decode(LenientJWKSet.self, from: "{}".data(using: .utf8)!)

        XCTAssertTrue(decoded.keys.isEmpty)
    }

    // MARK: - ClientMetadata wiring
    //
    // These only verify that ClientMetadata / ClientMetadataDraft23 are wired to
    // LenientJWKSet correctly (i.e. an invalid/unusable JWK does not break
    // client metadata parsing, and an explicit null jwks is still rejected).
    // The underlying decoding/leniency behaviour is already covered above, so
    // each wiring scenario is exercised once rather than for both formats.

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
