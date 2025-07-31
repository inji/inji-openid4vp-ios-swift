import XCTest
@testable import OpenID4VP
import CryptoKit
import JSONWebSignature

final class JWSHandlerTests: XCTestCase {
    let mockNetworkManager = MockNetworkManager()
    
    // Test fixtures
    let validEdDSAJWS = "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDpleGFtcGxlOjEyMzQjZWQyNTUxOSJ9.eyJzdWIiOiJ0ZXN0In0.FKwbuwDC0AdbJ2fP7Rl_WOhmiQzc2Z9LfDxQRefzNrxtlcdXO-Vi4Fdgv9Ca-EJQGgKXB3KQ7fUf1nC_FNbBBA"
//    
//    // Mock PublicKeyResolver for testing
//    class MockPublicKeyResolver: PublicKeyResolver {
//        var keyToReturn: PublicKey
//        var shouldFail = false
//        
//        init(keyToReturn: PublicKey) {
//            self.keyToReturn = keyToReturn
//        }
//        
//        func resolveKey(header: [String : Any]) async throws -> PublicKey {
//            if shouldFail {
//                throw NSError(domain: "MockError", code: 1, userInfo: [NSLocalizedDescriptionKey: "Mock resolution failure"])
//            }
//            return keyToReturn
//        }
//    }
//    
    // MARK: - Tests
    
    func testVerifyWithValidEd25519Signature() async throws {
        // Generate an Ed25519 key pair for testing
        let privateKey = Curve25519.Signing.PrivateKey()
        let publicKey = privateKey.publicKey
        
        // Create a mock resolver that returns our test key
        let resolver = DidPublicKeyResolver(didUrl: "did:web:KiruthikaJeyashankar.github.io:did#key-1", networkManager: mockNetworkManager )
        
        // Create a test JWS with our key
        let header = ["alg": "EdDSA", "kid": "did:example:1234#key1"]
        let payload = ["test": "data"]
//        let jws = try createTestJWS(header: header, payload: payload, privateKey: privateKey)
        
        // Create handler and verify
        let handler = JWSHandler(jws: validEdDSAJWS, publicKeyResolver: resolver)
        
        // This should not throw
        try await handler.verify()
    }
    
//    func testVerifyWithInvalidSignature() async throws {
//        // Generate two different key pairs
//        let signingKey = Curve25519.Signing.PrivateKey()
//        let verificationKey = Curve25519.Signing.PrivateKey().publicKey
//        
//        // Create a mock resolver that returns a different key than what signed the JWS
//        let resolver = MockPublicKeyResolver(keyToReturn: .ed25519(verificationKey))
//        
//        // Create a test JWS with the signing key
//        let header = ["alg": "EdDSA", "kid": "did:example:1234#key1"]
//        let payload = ["test": "data"]
//        let jws = try createTestJWS(header: header, payload: payload, privateKey: signingKey)
//        
//        // Create handler with mismatched verification key
//        let handler = JWSHandler(jws: jws, publicKeyResolver: resolver)
//        
//        // This should throw an InvalidSignature error
//        await XCTAssertThrowsError(try await handler.verify()) { error in
//            XCTAssertTrue(error is InvalidSignature)
//        }
//    }
//    
//    func testVerifyWithKeyResolutionFailure() async {
//        // Create a mock resolver that fails
//        let resolver = MockPublicKeyResolver(keyToReturn: .ed25519(Curve25519.Signing.PrivateKey().publicKey))
//        resolver.shouldFail = true
//        
//        // Create handler with a valid JWS but resolver will fail
//        let handler = JWSHandler(jws: validEdDSAJWS, publicKeyResolver: resolver)
//        
//        // This should throw a VerificationFailure error
//        await XCTAssertThrowsError(try await handler.verify()) { error in
//            XCTAssertTrue(error is VerificationFailure)
//        }
//    }
//    
//    func testExtractDataJsonFromJWS() throws {
//        // Create a test JWS with known values
//        let header = ["alg": "EdDSA", "kid": "test-key-id"]
//        let payload = ["sub": "1234", "name": "Test User"]
//        
//        let privateKey = Curve25519.Signing.PrivateKey()
//        let jws = try createTestJWS(header: header, payload: payload, privateKey: privateKey)
//        
//        let resolver = MockPublicKeyResolver(keyToReturn: .ed25519(privateKey.publicKey))
//        let handler = JWSHandler(jws: jws, publicKeyResolver: resolver)
//        
//        // Extract and verify header
//        let extractedHeader = try handler.extractDataJsonFromJws(jwsPart: .header)
//        XCTAssertEqual(extractedHeader["alg"] as? String, "EdDSA")
//        XCTAssertEqual(extractedHeader["kid"] as? String, "test-key-id")
//        
//        // Extract and verify payload
//        let extractedPayload = try handler.extractDataJsonFromJws(jwsPart: .payload)
//        XCTAssertEqual(extractedPayload["sub"] as? String, "1234")
//        XCTAssertEqual(extractedPayload["name"] as? String, "Test User")
//    }
//    
//    func testExtractDataJsonFromJWSWithInvalidBase64() {
//        // Create an invalid JWS with non-base64 parts
//        let invalidJWS = "invalid.notbase64.parts"
//        
//        let resolver = MockPublicKeyResolver(keyToReturn: .ed25519(Curve25519.Signing.PrivateKey().publicKey))
//        let handler = JWSHandler(jws: invalidJWS, publicKeyResolver: resolver)
//        
//        // This should throw when trying to decode invalid base64
//        XCTAssertThrowsError(try handler.extractDataJsonFromJws(jwsPart: .header))
//    }
//    
//    // Helper method to create a test JWS
//    private func createTestJWS(header: [String: Any], payload: [String: Any], privateKey: Curve25519.Signing.PrivateKey) throws -> String {
//        let headerData = try JSONSerialization.data(withJSONObject: header)
//        let payloadData = try JSONSerialization.data(withJSONObject: payload)
//        
//        let jws = try JWS(header: headerData, payload: payloadData)
//        try jws.sign(key: privateKey)
//        
//        return jws.jwsString
//    }
}
