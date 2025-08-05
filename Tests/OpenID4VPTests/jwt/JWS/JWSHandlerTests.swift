import XCTest
@testable import OpenID4VP
import CryptoKit
import JSONWebSignature

final class JWSHandlerTests: XCTestCase {
    let mockNetworkManager = MockNetworkManager()
    
    let validEdDSAJWS = "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDpleGFtcGxlOjEyMzQjZWQyNTUxOSJ9.eyJzdWIiOiJ0ZXN0In0.FKwbuwDC0AdbJ2fP7Rl_WOhmiQzc2Z9LfDxQRefzNrxtlcdXO-Vi4Fdgv9Ca-EJQGgKXB3KQ7fUf1nC_FNbBBA"
    
    //TODO: Fix me
    func testVerifyWithValidEd25519Signature() async throws {
        mockNetworkManager.setMockResponse(for: didDocumentUrl,responseBody: didResponse)
        
        let resolver = DidPublicKeyResolver(didUrl: didUrl, networkManager: mockNetworkManager )
        let handler = JWSHandler(jws: validEdDSAJWS, publicKeyResolver: resolver)
        
        //        await XCTAssertNoThrowAndVerifyAsync(try await handler.verify()){ result in
        //            print("JWS verification succeeded with valid Ed25519 signature")
        //        }
    }
}
