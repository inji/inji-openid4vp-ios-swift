import Foundation
@testable import OpenID4VP

import XCTest
final class DidJwkResolverTests: XCTestCase {
    
    let mockNetworkManager = MockNetworkManager()
    
    func testDidJwkResolver() async throws {
        let did = "did:jwk:eyJrdHkiOiAiT0tQIiwgImNydiI6ICJFZDI1NTE5IiwgIngiOiAiOGc5ZF9NQjBpVTJubWdiXzlQNERmMFRSUW01UkpUbWFpRWsySGtaeTVwRSIsICJhbGciOiAiRWREU0EiLCAia2V5X29wcyI6IFsidmVyaWZ5Il0sICJ1c2UiOiAic2lnIn0"
        let resolver = DidJwkResolver(parsedDid: ParsedDID(did: did, method: "jwk", id: "", didUrl: did), networkManager: mockNetworkManager)
        
        let key = try await resolver.resolve(verificationaMethodUri: did)
        
        switch key {
        case .ed25519(let edKey):
            XCTAssertEqual("f20f5dfcc074894da79a06fff4fe037f44d1426e5125399a8849361e4672e691", edKey.jwkRepresentation.x?.toHexString())
        default:
            XCTFail("Expected Ed25519 key type, but got \(key)")
        }
    }
}

