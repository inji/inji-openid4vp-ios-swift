//import XCTest
//@testable import OpenID4VP
//
//final class X25519KeyAgreementTests: XCTestCase {
//    func testGetJWEHeaderSuccess() throws {
////        let mockJWK = mockClientMetadataObject.jwks?.keys[0]
//        
//        let keyAgreement = X25519KeyAgreement()
//        let header = keyAgreement.getJWEHeader(alg: "ECDH-ES", enc: "A256GCM", jwk: mockJWK!, producerInfo: "wallet-nonce", recipientInfo: "verifier-nonce")
//        
//        XCTAssertEqual(header["alg"] as? String, "ECDH-ES")
//        XCTAssertEqual(header["enc"] as? String, "A256GCM")
//        XCTAssertEqual(header["kid"] as? String, "ed-key1")
//    }
//    
//    func testGetEphemeralKeyReturnNilWhenCalledBeforeDeriveKey() throws {        
//        let keyAgreement = X25519KeyAgreement()
//        let ephemeralPublicKey = keyAgreement.getEphemeralPublicKey()
//        
//        XCTAssertNil(ephemeralPublicKey)
//    }
//    
//    func testThrowErrorWhenInvalidPublicKeyIsPassedToDeriveKey() {
//        let keyAgreement = X25519KeyAgreement()
//        
//        XCTAssertThrowsError(try keyAgreement.deriveKey(publicKey: "some-invalid-data%^&")) { error in
//            XCTAssertEqual("An unexpected exception occurred: exception type: publicKeyConversionFailed", error.localizedDescription)
//        }
//    }
//}
