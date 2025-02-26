import Foundation
import XCTest
@testable import OpenID4VP

class DidPublicKeyResolverTests : XCTestCase {
    let mockNetworkManager: MockNetworkManager! = MockNetworkManager()
    
    func testValidPublicKeyResolution() async {
        let did = "did:web:inji-ovp:inji-mock-services:openid4vp-service:docs"
        mockNetworkManager.setMockResponse(for: didDocumentUrl,responseBody: didResponse)
        let didKeyResolver = DidPublicKeyResolver(didUrl: did, networkManager: mockNetworkManager)
        
        do{
            let response = try! await didKeyResolver.resolveKey(header: [
                "typ": "oauth-authz-req+jwt",
                "alg": "EdDSA",
                "kid": "did:web:inji-ovp:inji-mock-services:openid4vp-service:docs#key-0" //Valid key available in did document response
            ])
            
            XCTAssertEqual("IKXhA7W1HD1sAl+OfG59VKAqciWrrOL1Rw5F+PGLhi4=", response)
        }
    }
    
    func testThrowErrorWhenKeyIdIsNotMatchingAnyOfTheKeysInDidDocumentResponse() async {
        let did = "did:web:inji-ovp:inji-mock-services:openid4vp-service:docs"
        let constructedHTTPUrl = URL(string: "https://inji-ovp/inji-mock-services/openid4vp-service/docs/did.json")!
        mockNetworkManager.setMockResponse(for: didDocumentUrl,responseBody: didResponse)
        let didKeyResolver = DidPublicKeyResolver(didUrl: did, networkManager: mockNetworkManager)
        
        do{
//        kid = did:example:123#2 is not available in didResponse
            let _ = try await didKeyResolver.resolveKey(header: [
                "typ": "oauth-authz-req+jwt",
                "alg": "EdDSA",
                "kid": "did:example:123#2"
            ])
            XCTFail("error should been thrown but its not thrown")
        }
        catch{
            XCTAssertEqual("No matching public key found in did resolver with the provided key id", error.localizedDescription)
        }
    }
    
    func testThrowErrorWhenPublicKeyResolutionFailed() async {
        let did = "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9"
        let didKeyResolver = DidPublicKeyResolver(didUrl: did, networkManager: mockNetworkManager)
        
        do{
            let _ = try await didKeyResolver.resolveKey(header: [
                "typ": "oauth-authz-req+jwt",
                "alg": "EdDSA",
                "kid": "did:example:123#2"
            ])
            XCTFail("error should been thrown but its not thrown")
        }
        catch{
            XCTAssertEqual(JwtVerificationException.publicKeyResolutionFailed(message: "Given did url is not supported"), error as? JwtVerificationException)
        }
    }
}
