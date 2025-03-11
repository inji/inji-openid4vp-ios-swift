import XCTest
@testable import OpenID4VP

public class JWEHandlerTests: XCTestCase {
    let (jweKeyEncryptionAlgorithm, jweContentEncryptionAlgorithm, verifierPublicKey) = (mockClientMetadataObject.authorization_encrypted_response_alg!, mockClientMetadataObject.authorization_encrypted_response_enc!, mockClientMetadataObject.jwks!.keys[0])



    func testCreateResponseSuccess() throws {
        let jweHandler = JWEHandler(keyEncryptionAlgorithm: jweKeyEncryptionAlgorithm, contentEncryptionAlgorithm: jweContentEncryptionAlgorithm, publicKey: verifierPublicKey)
        let bodyParams: [String: Any] = ["key": "value"]

        let response = try jweHandler.createResponse(payload: bodyParams)

        XCTAssertNotNil(response)
        let parts = response.split(separator: ".", omittingEmptySubsequences: false)
        XCTAssertEqual(parts.count, 5, "JWE should have exactly 5 parts")
    }

    func testGetEncryptionSuccess() throws {

        let encryption = try EncryptionProvider.getEncryption("A256GCM")

        XCTAssertTrue(encryption is AESGCMEncryption)

    }

    func testGetEncryptionFailureUnsupportedAlgorithm() throws {
        XCTAssertThrowsError(try EncryptionProvider.getEncryption("UNSUPPORTED")) { error in
            XCTAssertEqual(error.localizedDescription, "Required Encryption algorithm is not supported.")
        }
    }

    func testCreateKeyAgreementSuccess() throws {
        let mockJWK = mockClientMetadataObject.jwks?.keys[0]

        let keyAgreement = try KeyAgreementFactory.createKeyAgreement(for: mockJWK!)

        XCTAssertNotNil(keyAgreement)
        XCTAssertTrue(keyAgreement is X25519KeyAgreement)
    }

    func test_createKeyAgreement_unsupportedCurve() throws {
        let invalidMockJWK = JWK(kty: "OKP", use: "enc", crv: "Ed25519", x: "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4", alg: "ECDH-ES", kid: "ed-key1")

        XCTAssertThrowsError(try KeyAgreementFactory.createKeyAgreement(for: invalidMockJWK)) { error in
            XCTAssertEqual(error.localizedDescription, "Required Key Agreement algorithm is not supported.")
        }
    }
}

