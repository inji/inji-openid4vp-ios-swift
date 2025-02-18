import Foundation
import XCTest
@testable import OpenID4VP

class DidKeyResolverTests : XCTestCase {
    let mockNetworkManager: MockNetworkManager! = MockNetworkManager()
    
    func testInvalidRequestFieldThrowErrorForResponseTypeField() async {
        mockNetworkManager.setMockResponse(for: URL(string: "https://resolver.identity.foundation/1.0/identifiers/did:example:123#1")!,response: didResponse)
        let didKeyResolver = DidKeyResolver(didUrl: "did:example:123#1", networkManager: mockNetworkManager)
        
        do{
            try await didKeyResolver.resolveKey(header: [
                "typ": "oauth-authz-req+jwt",
                "alg": "EdDSA",
                "kid": "did:example:123#2"
            ])
        }
        catch{
            XCTAssertEqual("No matching public key found in did resolver with the provided key id", error.localizedDescription)
        }
    }
}
