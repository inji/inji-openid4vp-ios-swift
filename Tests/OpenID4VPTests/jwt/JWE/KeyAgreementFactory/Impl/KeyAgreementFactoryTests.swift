//import XCTest
//@testable import OpenID4VP
//
//final class KeyAgreementFactoryTests: XCTestCase {
//    func testCreateKeyAgreementSuccess() throws {
//        let mockJWK = mockClientMetadataObject.jwks?.keys[0]
//
//        let keyAgreement = try KeyAgreementFactory.createKeyAgreement(for: mockJWK!)
//
//        XCTAssertNotNil(keyAgreement)
//        XCTAssertTrue(keyAgreement is X25519KeyAgreement)
//    }
//
//    func test_createKeyAgreement_unsupportedCurve() throws {
//        let invalidMockJWK = JWK(kty: "OKP", use: "enc", crv: "Ed25519", x: "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4", alg: "ECDH-ES", kid: "ed-key1")
//
//        XCTAssertThrowsError(try KeyAgreementFactory.createKeyAgreement(for: invalidMockJWK)) { error in
//            XCTAssertEqual(error.localizedDescription, "Required Key Agreement algorithm is not supported.")
//        }
//    }
//}
