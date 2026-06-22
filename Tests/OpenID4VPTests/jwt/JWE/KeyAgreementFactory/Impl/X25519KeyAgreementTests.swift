import XCTest
import JSONWebKey
import CryptoKit
@testable import OpenID4VP

final class X25519KeyAgreementTests: XCTestCase {
    let producerInfo = NonceProvider().generateNonce()
    let recipientInfo = NonceProvider().generateNonce()
    
    func makeMockJWK(addKid: Bool = true) throws -> JWK {
        // Build a JSON dictionary and serialize to Data to avoid string literal mutation issues
        var jwkDict: [String: Any] = [
            "kty": "OKP",
            "use": "enc",
            "crv": "X25519",
            "x": "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
            "alg": "ECDH-ES"
        ]
        if addKid {
            jwkDict["kid"] = "x25519-key1"
        }
        let jsonData = try JSONSerialization.data(withJSONObject: jwkDict, options: [])
        return try JSONDecoder().decode(JWK.self, from: jsonData)
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
    
    func testGetJWEHeaderReturnEmptyKidWhenJWKHasNoKid() throws {
        let mockJWK = try makeMockJWK(addKid: false)
        let keyAgreement = X25519KeyAgreement()
        
        let header = keyAgreement.getJWEHeader(
            alg: "ECDH-ES",
            enc: "A256GCM",
            jwk: mockJWK,
            producerInfo: "mock-nonce",
            recipientInfo: "verifier-nonce"
        )
        
        XCTAssertEqual(header["kid"] as? String, "")
    }

    func testGetEphemeralKeyReturnNilWhenCalledBeforeDeriveKey() throws {
        let keyAgreement = X25519KeyAgreement()
        let ephemeralPublicKey = keyAgreement.getEphemeralPublicKey()
        
        XCTAssertNil(ephemeralPublicKey)
    }

    func testThrowErrorWhenInvalidPublicKeyIsPassedToDeriveKey() {
        let keyAgreement = X25519KeyAgreement()
        
        XCTAssertThrowsError(try keyAgreement.deriveKey(publicKey: Data(base64UrlEncoded: "someinvaliddata") ?? Data(), apu: producerInfo, apv: recipientInfo)){ error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Key agreement failed. - The operation couldn’t be completed. (CryptoKit.CryptoKitError error 1.)",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testDeriveKeyWithParamsSuccess() throws {
        let keyAgreement = X25519KeyAgreement()
        let privateKey = CryptoKit.Curve25519.KeyAgreement.PrivateKey()
        let publicKeyRaw = privateKey.publicKey.rawRepresentation
        
        let apu = Data("mock-apu".utf8).toBase64UrlEncoded()
        let apv = Data("mock-apv".utf8).toBase64UrlEncoded()
        
        let symmetricKey = try keyAgreement.deriveKey(publicKey: publicKeyRaw, algorithm: "A256GCM", apu: apu, apv: apv)
        
        XCTAssertNotNil(symmetricKey)
        XCTAssertEqual(symmetricKey.bitCount, 256)
    }

    func testDeriveKeyThrowsWhenApuInvalid() throws {
        let keyAgreement = X25519KeyAgreement()
        let privateKey = CryptoKit.Curve25519.KeyAgreement.PrivateKey()
        let publicKeyRaw = privateKey.publicKey.rawRepresentation
        
        let apv = Data("mock-apv".utf8).toBase64UrlEncoded()
        
        XCTAssertThrowsError(try keyAgreement.deriveKey(publicKey: publicKeyRaw, algorithm: "A256GCM", apu: "invalid_base64_url!!", apv: apv)) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Key agreement failed. - Failed to decode producer info (apu)",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testDeriveKeyThrowsWhenAlgorithmInvalid() throws {
        let keyAgreement = X25519KeyAgreement()
        let privateKey = CryptoKit.Curve25519.KeyAgreement.PrivateKey()
        let publicKeyRaw = privateKey.publicKey.rawRepresentation
        
        XCTAssertThrowsError(try keyAgreement.deriveKey(publicKey: publicKeyRaw, algorithm: "UNSUPPORTED", apu: producerInfo, apv: recipientInfo)) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Key agreement failed. - Unsupported content encryption algorithm: UNSUPPORTED",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testGetEphemeralKeyReturnValidKeyWhenCalledAfterDeriveKey() throws {
        let keyAgreement = X25519KeyAgreement()
        let privateKey = CryptoKit.Curve25519.KeyAgreement.PrivateKey()
        let publicKeyRaw = privateKey.publicKey.rawRepresentation
        
        _ = try keyAgreement.deriveKey(publicKey: publicKeyRaw, apu: producerInfo, apv:  recipientInfo)
        
        let ephemeralPublicKey = keyAgreement.getEphemeralPublicKey()
        
        XCTAssertNotNil(ephemeralPublicKey)
        XCTAssertEqual(ephemeralPublicKey?["kty"] as? String, "OKP")
        XCTAssertEqual(ephemeralPublicKey?["crv"] as? String, "X25519")
        XCTAssertNotNil(ephemeralPublicKey?["x"])
    }
    
    func testGetEncryptionKey() {
        let keyAgreement = X25519KeyAgreement()
        
        XCTAssertEqual(keyAgreement.getEncyptionKey(), "")
    }
}
