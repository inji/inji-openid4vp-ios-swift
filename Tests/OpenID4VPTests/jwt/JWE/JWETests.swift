import XCTest
@testable import OpenID4VP

public class JWEHandlerTests: XCTestCase {
    let (jweKeyEncryptionAlgorithm, jweContentEncryptionAlgorithm, verifierPublicKey) = (mockClientMetadataObject.authorizationEncryptedResponseAlg!, mockClientMetadataObject.authorizationEncryptedResponseEnc!, mockClientMetadataObject.jwks!.keys[0])



    func testCreateResponseSuccess() throws {
        let jweHandler = JWEHandler(contentEncryptionAlgorithm: jweContentEncryptionAlgorithm, keyEncryptionAlgorithm: jweKeyEncryptionAlgorithm, publicKey: verifierPublicKey, producerInfo: "wallet-nonce", recipientInfo: "verifier-nonce")
        let bodyParams: [String: Any] = ["key": "value"]

        let response = try jweHandler.generateEncryptedResponse(payload: bodyParams)

        XCTAssertNotNil(response)
        let parts = response.split(separator: ".", omittingEmptySubsequences: false)
        XCTAssertEqual(parts.count, 5, "JWE should have exactly 5 parts")
    }
}

