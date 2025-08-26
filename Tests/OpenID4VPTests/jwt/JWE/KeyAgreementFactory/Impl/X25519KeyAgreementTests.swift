import XCTest
import JSONWebKey
@testable import OpenID4VP

final class X25519KeyAgreementTests: XCTestCase {
    
    func makeMockJWK() throws -> JWK {
        let json = """
        {
          "kty": "OKP",
          "use": "enc",
          "crv": "X25519",
          "x": "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
          "alg": "ECDH-ES",
          "kid": "x25519-key1"
        }
        """.data(using: .utf8)!
        
        return try JSONDecoder().decode(JWK.self, from: json)
    }

    func testGetJWEHeaderSuccess() throws {
        let mockJWK = try makeMockJWK()
        let keyAgreement = X25519KeyAgreement()
        
        let header = keyAgreement.getJWEHeader(
            alg: "ECDH-ES",
            enc: "A256GCM",
            jwk: mockJWK,
            producerInfo: "mock-nonce",
            recipientInfo: "verifier-nonce"
        )
        
        XCTAssertEqual(header["alg"] as? String, "ECDH-ES")
        XCTAssertEqual(header["enc"] as? String, "A256GCM")
        XCTAssertEqual(header["kid"] as? String, "x25519-key1")
        XCTAssertNotNil(header["apu"])
        XCTAssertNotNil(header["apv"])
    }

    func testGetEphemeralKeyReturnNilWhenCalledBeforeDeriveKey() throws {
        let keyAgreement = X25519KeyAgreement()
        let ephemeralPublicKey = keyAgreement.getEphemeralPublicKey()
        
        XCTAssertNil(ephemeralPublicKey)
    }

    func testThrowErrorWhenInvalidPublicKeyIsPassedToDeriveKey() {
        let keyAgreement = X25519KeyAgreement()
        
        XCTAssertThrowsError(try keyAgreement.deriveKey(publicKey: Data(base64UrlEncoded: "someinvaliddata") ?? Data())) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Key agreement failed. - The operation couldn’t be completed. (CryptoKit.CryptoKitError error 1.)",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
}
