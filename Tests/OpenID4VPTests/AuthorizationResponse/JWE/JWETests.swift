import XCTest
@testable import OpenID4VP

public func getMockClientMetadata() throws -> ClientMetadata {
    let jsonData = try JSONSerialization.data(withJSONObject: clientMetadata, options: .prettyPrinted)
    return try ClientMetadata.deserializeAndValidate(clientMetadata: jsonData)
}

public func getMockPresentationDefinition() throws -> PresentationDefinition{
    return try convertToInstance(presentationDefinition, as: PresentationDefinition.self)
}

public class JWEHandlerTests: XCTestCase {
    
    func testCreateResponseSuccess() throws {
        
        let jweHandler = JWEProcessor(clientMetadata: try getMockClientMetadata())
        let bodyParams: [String: Any] = ["key": "value"]
        
        let response = try jweHandler.createResponse(bodyParams: bodyParams)
        
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
    
    func testGetJwkSuccess() throws {
        
        let expectedJWK = JWK(kty: "OKP", use: "enc", crv: "X25519", x: "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4", alg: "ECDH-ES", kid: "ed-key1")
        
        let mockClientMetadata = try getMockClientMetadata()
        let mockJWKS = mockClientMetadata.jwks!
        let jweHandler = JWEProcessor(clientMetadata: mockClientMetadata)
        
        let jwk = try jweHandler.getJwk(mockJWKS, "ECDH-ES")
        
        XCTAssertEqual(jwk.alg, expectedJWK.alg)
        XCTAssertEqual(jwk.x, expectedJWK.x)
        XCTAssertEqual(jwk.kid, expectedJWK.kid)
        XCTAssertEqual(jwk.crv, expectedJWK.crv)
        XCTAssertEqual(jwk.kty, expectedJWK.kty)
        XCTAssertEqual(jwk.use, expectedJWK.use)
    }
    
    func testCreateKeyAgreementSuccess() throws {
        
        let mockJWK = try getMockClientMetadata().jwks?.keys[0]
        
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

