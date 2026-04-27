import XCTest
@testable import OpenID4VP

final class UnsignedLdpVPTokenBuilderTests: XCTestCase {

    func testCreationOfUnsignedLdpVPToken() async throws {
        let builder = UnsignedLdpVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .draft23),
            specVersion: .draft23,
            id: "ebc6f1c2",
            holder: "did:example:wallet",
            signatureSuite: SignatureAlgorithm.ed25519Signature2020.rawValue
        )
        var mappings = [
            CredentialInputDescriptorMapping(format: .ldp_vc, credential: AnyCodable(ldpVC()), inputDescriptorId: "cred-input-1")
        ]

        let (payload, unsignedVPTokens) = try await builder.build(credentialInputDescriptorMappings: &mappings)

        let ldpToken = payload as? LdpVPToken
        XCTAssertNotNil(ldpToken)
        XCTAssertEqual(ldpToken!.type, ["VerifiablePresentation"])
        XCTAssertEqual(ldpToken!.id, "ebc6f1c2")
        XCTAssertEqual(ldpToken!.holder, "did:example:wallet")
        XCTAssertEqual(ldpToken!.verifiableCredential.count, 1)
        XCTAssertEqual(unsignedVPTokens.count, 1)
        XCTAssertEqual(unsignedVPTokens.first?.format, .ldp_vc)
        XCTAssertEqual(unsignedVPTokens.first?.signatureAlgorithm, SignatureAlgorithm.ed25519Signature2020.rawValue)
        XCTAssertEqual(unsignedVPTokens.first?.holderKeyReference, "did:example:wallet")
    }

    func testContextIncludesEd25519Suite() async throws {
        let builder = UnsignedLdpVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .draft23),
            specVersion: .draft23,
            id: "id1",
            holder: "did:example:wallet",
            signatureSuite: SignatureAlgorithm.ed25519Signature2020.rawValue
        )
        var mappings = [
            CredentialInputDescriptorMapping(format: .ldp_vc, credential: AnyCodable(ldpVC()), inputDescriptorId: "cred-input-1")
        ]

        let (payload, _) = try await builder.build(credentialInputDescriptorMappings: &mappings)

        let ldpToken = payload as! LdpVPToken
        XCTAssertTrue(ldpToken.context.contains("https://w3id.org/security/suites/ed25519-2020/v1"))
    }

    func testContextIncludesJwsSuite() async throws {
        let builder = UnsignedLdpVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .draft23),
            specVersion: .draft23,
            id: "id1",
            holder: "did:example:wallet",
            signatureSuite: SignatureAlgorithm.jsonWebSignature2020.rawValue
        )
        var mappings = [
            CredentialInputDescriptorMapping(format: .ldp_vc, credential: AnyCodable(ldpVC()), inputDescriptorId: "cred-input-1")
        ]

        let (payload, _) = try await builder.build(credentialInputDescriptorMappings: &mappings)

        let ldpToken = payload as! LdpVPToken
        XCTAssertTrue(ldpToken.context.contains("https://w3id.org/security/suites/jws-2020/v1"))
    }

    func testNestedPathIsSetOnMappings() async throws {
        let builder = UnsignedLdpVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .draft23),
            specVersion: .draft23,
            id: "id1",
            holder: "did:example:wallet",
            signatureSuite: SignatureAlgorithm.ed25519Signature2020.rawValue
        )
        var mappings = [
            CredentialInputDescriptorMapping(format: .ldp_vc, credential: AnyCodable(ldpVC()), inputDescriptorId: "cred-input-1"),
            CredentialInputDescriptorMapping(format: .ldp_vc, credential: AnyCodable(ldpVC()), inputDescriptorId: "cred-input-2")
        ]

        let _ = try await builder.build(credentialInputDescriptorMappings: &mappings)

        XCTAssertEqual(mappings[0].nestedPath, "$.verifiableCredential[0]")
        XCTAssertEqual(mappings[1].nestedPath, "$.verifiableCredential[1]")
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
