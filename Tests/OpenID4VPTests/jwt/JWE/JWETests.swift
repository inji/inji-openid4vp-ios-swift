import XCTest
@testable import OpenID4VP
import JSONWebKey

public class JWEHandlerTests: XCTestCase {
    let jweKeyEncryptionAlgorithm: String = "ECDH-ES"
    let jweContentEncryptionAlgorithm: String = "A256GCM"
    let verificationPublicKey = createInstance([
        "kty": "OKP",
        "crv": "X25519",
        "use": "enc",
        "x": "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
        "alg": "ECDH-ES",
        "kid": "ed-key1"
    ], as: JWK.self)



    func testCreateResponseSuccess() throws {
        let jweHandler = JWEHandler(contentEncryptionAlgorithm: jweContentEncryptionAlgorithm, keyEncryptionAlgorithm: jweKeyEncryptionAlgorithm, publicKey: verificationPublicKey, producerInfo: "mock-nonce", recipientInfo: "verifier-nonce")
        let bodyParams: [String: Any] = ["key": "value"]

        let response = try jweHandler.generateEncryptedResponse(payload: bodyParams)

        XCTAssertNotNil(response)
        let parts = response.split(separator: ".", omittingEmptySubsequences: false)
        XCTAssertEqual(parts.count, 5, "JWE should have exactly 5 parts")
    }
}


