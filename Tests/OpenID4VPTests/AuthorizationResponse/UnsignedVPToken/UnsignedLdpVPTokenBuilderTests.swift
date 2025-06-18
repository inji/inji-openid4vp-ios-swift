import XCTest
@testable import OpenID4VP

final class UnsignedLdpVPTokenBuilderTests: XCTestCase {

    func testCreationOfUnsignedLdpVPToken() throws {
       
        let vc = ldpVC()
        
        let builder = UnsignedLdpVPTokenBuilder(
            verifiableCredential: [AnyCodable(vc)],
            id: "ebc6f1c2",
            holder: "did:example:wallet",
            challenge: "test-challenge",
            domain: "test-domain",
            signatureSuite: SignatureAlgorithm.ed25519Signature2020.rawValue
        )

   
        let result = builder.build()
        
       
        let token = result["vpTokenSigningPayload"] as! LdpVPToken

        XCTAssertEqual(token.context, [
            "https://www.w3.org/2018/credentials/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1"
        ])
        XCTAssertEqual(token.type, ["VerifiablePresentation"])
        XCTAssertEqual(token.id, "ebc6f1c2")
        XCTAssertEqual(token.holder, "did:example:wallet")
        XCTAssertEqual(token.verifiableCredential.count, 1)
    }


    private func ldpVC() -> [String: Any] {
        return [
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiableCredential"],
            "issuer": "did:example:issuer",
            "issuanceDate": "2020-08-19T21:41:50Z",
            "credentialSubject": ["id": "did:example:subject"]
        ]
    }
}
