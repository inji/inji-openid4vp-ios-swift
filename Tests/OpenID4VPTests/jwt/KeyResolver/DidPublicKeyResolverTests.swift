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
        let testCases: [TestCase] = [
            TestCase(input: ""),
            TestCase(input: "did:example:123#2"),
        ]
        
        for testCase in testCases {
            let did = "did:web:inji-ovp:inji-mock-services:openid4vp-service:docs"
            mockNetworkManager.setMockResponse(for: didDocumentUrl, responseBody: didResponse)
            let didKeyResolver = DidPublicKeyResolver(didUrl: did, networkManager: mockNetworkManager)
            
            do {
                // kid = \(testCase.input) is not available in didResponse
                _ = try await didKeyResolver.resolveKey(header: [
                    "typ": "oauth-authz-req+jwt",
                    "alg": "EdDSA",
                    "kid": testCase.input
                ])
                XCTFail("Error should have been thrown but wasn't for input - '\(testCase.input)'")
            } catch {
                let expectedMessage = "Public key extraction failed for kid: \(testCase.input)"
                assertOpenID4VPException(
                    error,
                    expectedMessage: expectedMessage,
                    expectedCode: OpenID4VPErrorCodes.invalidRequest
                )
            }
        }
    }

    
    func testThrowErrorWhenPublicKeyResolutionFailed() async {
        let did = "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9"
        let didKeyResolver = DidPublicKeyResolver(didUrl: did, networkManager: mockNetworkManager)
        
        do {
            _ = try await didKeyResolver.resolveKey(header: [
                "typ": "oauth-authz-req+jwt",
                "alg": "EdDSA",
                "kid": "did:example:123#2"
            ])
            XCTFail("Error should have been thrown but was not")
        } catch {

            assertOpenID4VPException(
                error,
                expectedMessage: "Given did url is not supported",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

}
