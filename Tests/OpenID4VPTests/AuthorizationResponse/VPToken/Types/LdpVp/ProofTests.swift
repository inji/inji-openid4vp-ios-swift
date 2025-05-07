import XCTest
@testable import OpenID4VP

final class ProofTests: XCTestCase {
    
    func testConstructProofSuccess() {
         
        let mockMetadata = LdpVpTokenSigningResult(
            jws: "testJWS",
            signatureAlgorithm: "ES256",
            publicKey: "testPublicKey",
            domain: "testDomain"
        )
        let challenge = "testChallenge"
        
        let proof = Proof.construct(from: mockMetadata, challenge: challenge)
        
        XCTAssertEqual(proof.type, "ES256")
        XCTAssertEqual(proof.challenge, "testChallenge")
        XCTAssertEqual(proof.domain, "testDomain")
        XCTAssertEqual(proof.jws, "testJWS")
        XCTAssertEqual(proof.proofPurpose, .vpProofPurpose)
        XCTAssertEqual(proof.verificationMethod, "testPublicKey")
        
        let dateFormatter = DateFormatter()
        dateFormatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'"
        dateFormatter.timeZone = TimeZone(secondsFromGMT: 0)
        
        XCTAssertNotNil(dateFormatter.date(from: proof.created), "Created timestamp should match the expected format")
    }
}

