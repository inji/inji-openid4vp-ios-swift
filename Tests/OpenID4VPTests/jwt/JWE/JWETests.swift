import XCTest
@testable import OpenID4VP
import JSONWebKey

final class JWEHandlerTests: XCTestCase {

    let jweKeyEncryptionAlgorithm = "ECDH-ES"
    let jweContentEncryptionAlgorithm = "A256GCM"
    let producerInfo = "mock-nonce"
    let recipientInfo = "verifier-nonce"

    let verificationPublicKey = createInstance([
        "kty": "OKP",
        "crv": "X25519",
        "use": "enc",
        "x": "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
        "alg": "ECDH-ES",
        "kid": "ed-key1"
    ], as: JWK.self)

    private func makeHandler() -> JWEHandler {
        JWEHandler(
            contentEncryptionAlgorithm: jweContentEncryptionAlgorithm,
            keyEncryptionAlgorithm: jweKeyEncryptionAlgorithm,
            publicKey: verificationPublicKey,
            producerInfo: producerInfo,
            recipientInfo: recipientInfo
        )
    }

    private func decodeHeader(_ jwe: String) throws -> [String: Any] {
        let encodedHeader = try XCTUnwrap(jwe.split(separator: ".").first.map(String.init))
        let padded = encodedHeader.base64URLToBase64()
        let data = try XCTUnwrap(Data(base64Encoded: padded))
        return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    // MARK: - JWE structure

    func testCreateResponseSuccess() throws {
        let response = try makeHandler().generateEncryptedResponse(payload: ["key": "value"])

        let parts = response.split(separator: ".", omittingEmptySubsequences: false)
        XCTAssertEqual(parts.count, 5)
    }

    func testJWEHeaderContainsCorrectAlgAndEnc() throws {
        let response = try makeHandler().generateEncryptedResponse(payload: ["key": "value"])

        let header = try decodeHeader(response)
        XCTAssertEqual(header["alg"] as? String, jweKeyEncryptionAlgorithm)
        XCTAssertEqual(header["enc"] as? String, jweContentEncryptionAlgorithm)
    }

    func testJWEHeaderContainsKid() throws {
        let response = try makeHandler().generateEncryptedResponse(payload: ["key": "value"])

        let header = try decodeHeader(response)
        XCTAssertEqual(header["kid"] as? String, "ed-key1")
    }

    func testJWEHeaderContainsApuMatchingProducerInfo() throws {
        let response = try makeHandler().generateEncryptedResponse(payload: ["key": "value"])

        let header = try decodeHeader(response)
        XCTAssertEqual(header["apu"] as? String, producerInfo)
    }

    func testJWEHeaderContainsApvMatchingRecipientInfo() throws {
        let response = try makeHandler().generateEncryptedResponse(payload: ["key": "value"])

        let header = try decodeHeader(response)
        XCTAssertEqual(header["apv"] as? String, recipientInfo)
    }

    func testJWEHeaderContainsEpkWithExpectedFields() throws {
        let response = try makeHandler().generateEncryptedResponse(payload: ["key": "value"])

        let header = try decodeHeader(response)
        let epk = try XCTUnwrap(header["epk"] as? [String: Any])
        XCTAssertEqual(epk["kty"] as? String, "OKP")
        XCTAssertEqual(epk["crv"] as? String, "X25519")
        XCTAssertNotNil(epk["x"])
    }

    func testJWEEncryptedKeyPartIsEmpty() throws {
        let response = try makeHandler().generateEncryptedResponse(payload: ["key": "value"])

        let parts = response.split(separator: ".", omittingEmptySubsequences: false)
        XCTAssertEqual(String(parts[1]), "", "ECDH-ES uses direct key agreement — encrypted key must be empty")
    }

    func testJWEIVAndCiphertextAndTagAreNonEmpty() throws {
        let response = try makeHandler().generateEncryptedResponse(payload: ["key": "value"])

        let parts = response.split(separator: ".", omittingEmptySubsequences: false)
        XCTAssertFalse(parts[2].isEmpty, "IV must be non-empty")
        XCTAssertFalse(parts[3].isEmpty, "Ciphertext must be non-empty")
        XCTAssertFalse(parts[4].isEmpty, "Auth tag must be non-empty")
    }

    func testDifferentPayloadsProduceDifferentCiphertexts() throws {
        let response1 = try makeHandler().generateEncryptedResponse(payload: ["key": "value1"])
        let response2 = try makeHandler().generateEncryptedResponse(payload: ["key": "value2"])

        let ciphertext1 = response1.split(separator: ".")[3]
        let ciphertext2 = response2.split(separator: ".")[3]
        XCTAssertNotEqual(ciphertext1, ciphertext2)
    }

    // MARK: - Error paths

    func testThrowsWhenPayloadCannotBeConverted() throws {
        let handler = makeHandler()
        let unserializablePayload: [String: Any] = ["key": Double.nan]

        XCTAssertThrowsError(try handler.generateEncryptedResponse(payload: unserializablePayload)) { error in
            assertOpenID4VPException(error, expectedMessage: "Failed to convert payload to Data", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    func testThrowsWhenPublicKeyIsMissingAlgorithmProperty() throws {
        let keyWithoutAlg = createInstance([
            "kty": "OKP", "crv": "X25519", "use": "enc",
            "x": "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4", "kid": "ed-key1"
        ], as: JWK.self)
        let handler = JWEHandler(
            contentEncryptionAlgorithm: jweContentEncryptionAlgorithm,
            keyEncryptionAlgorithm: jweKeyEncryptionAlgorithm,
            publicKey: keyWithoutAlg,
            producerInfo: producerInfo,
            recipientInfo: recipientInfo
        )

        XCTAssertThrowsError(try handler.generateEncryptedResponse(payload: ["key": "value"])) { error in
            assertOpenID4VPException(error, expectedMessage: "Public key is missing 'algorithm' property", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    func testThrowsWhenPublicKeyIsMissingXCoordinate() throws {
        let keyWithoutX = createInstance([
            "kty": "OKP", "crv": "X25519", "use": "enc", "alg": "ECDH-ES", "kid": "ed-key1"
        ], as: JWK.self)
        let handler = JWEHandler(
            contentEncryptionAlgorithm: jweContentEncryptionAlgorithm,
            keyEncryptionAlgorithm: jweKeyEncryptionAlgorithm,
            publicKey: keyWithoutX,
            producerInfo: producerInfo,
            recipientInfo: recipientInfo
        )

        XCTAssertThrowsError(try handler.generateEncryptedResponse(payload: ["key": "value"])) { error in
            assertOpenID4VPException(error, expectedMessage: "Public key is missing 'x' coordinate", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }
}
