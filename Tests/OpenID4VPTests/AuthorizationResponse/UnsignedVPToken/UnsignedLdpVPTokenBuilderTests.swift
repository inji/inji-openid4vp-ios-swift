import XCTest
@testable import OpenID4VP

final class UnsignedLdpVPTokenBuilderTests: XCTestCase {

    // MARK: - build(credentialInputDescriptorMappings:) tests

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
        
        let expectedDataToSign = """
        {"holder":"did:example:wallet","type":["VerifiablePresentation"],"@context":["https://www.w3.org/2018/credentials/v1","https://w3id.org/security/suites/ed25519-2020/v1"],"id":"ebc6f1c2","verifiableCredential":[{"type":["VerifiableCredential"],"issuanceDate":"2020-08-19T21:41:50Z","credentialSubject":{"id":"did:example:subject"},"@context":["https://www.w3.org/2018/credentials/v1"],"issuer":"did:example:issuer"}],"proof":{"verificationMethod":"did:example:wallet","challenge":"nonce","domain":"client_id","type":"Ed25519Signature2020"}}
        """
        let actualDataToSign = String(decoding: unsignedVPTokens.first!.dataToSign, as: UTF8.self)
        assertJsonString(expected: expectedDataToSign, actual: actualDataToSign)
    }

    func testContextIncludesEd25519Suite() async throws {
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

        let ldpTokenPayload = payload as! LdpVPToken
        
        let expectedDataToSign = """
        {"holder":"did:example:wallet","type":["VerifiablePresentation"],"@context":["https://www.w3.org/2018/credentials/v1", "https://w3id.org/security/suites/ed25519-2020/v1"],"id":"ebc6f1c2","verifiableCredential":[{"type":["VerifiableCredential"],"issuanceDate":"2020-08-19T21:41:50Z","credentialSubject":{"id":"did:example:subject"},"@context":["https://www.w3.org/2018/credentials/v1"],"issuer":"did:example:issuer"}],"proof":{"verificationMethod":"did:example:wallet","challenge":"nonce","domain":"client_id","type":"Ed25519Signature2020"}}
        """
        let actualDataToSign = String(decoding: unsignedVPTokens.first!.dataToSign, as: UTF8.self)
        assertJsonString(expected: expectedDataToSign, actual: actualDataToSign)
//    TODO:    assert the ldpVPTokenPaylload as well
    }

    func testContextIncludesJwsSuite() async throws {
        JsonLd.setCanonicalizer { _ in "Y2Fub25pY2FsaXplZA" }
        defer { JsonLd.setCanonicalizer(nil) }

        let builder = UnsignedLdpVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .draft23),
            specVersion: .draft23,
            id: "ebc6f1c2",
            holder: "did:example:wallet",
            signatureSuite: SignatureAlgorithm.jsonWebSignature2020.rawValue
        )
        var mappings = [
            CredentialInputDescriptorMapping(format: .ldp_vc, credential: AnyCodable(ldpVC()), inputDescriptorId: "cred-input-1")
        ]

        let (payload, unsignedVPTokens) = try await builder.build(credentialInputDescriptorMappings: &mappings)
        print("unsignedVPTokens.first!.dataToSign \(unsignedVPTokens.first!.dataToSign)")

        let ldpToken = payload as! LdpVPToken
        XCTAssertTrue(ldpToken.context.contains("https://w3id.org/security/suites/jws-2020/v1"))
        
        let expectedDataToSign = """
        {"holder":"did:example:wallet","type":["VerifiablePresentation"],"@context":["https://www.w3.org/2018/credentials/v1","https://w3id.org/security/suites/jws-2020/v1"],"id":"ebc6f1c2","verifiableCredential":[{"type":["VerifiableCredential"],"issuanceDate":"2020-08-19T21:41:50Z","credentialSubject":{"id":"did:example:subject"},"@context":["https://www.w3.org/2018/credentials/v1"],"issuer":"did:example:issuer"}],"proof":{"verificationMethod":"did:example:wallet","challenge":"nonce","domain":"client_id","type":"JsonWebSignature2020"}}
        """
//        assertJsonString(expected: expectedDataToSign, actual: unsignedVPTokens.first!.dataToSign)
        let actualDataToSign = String(decoding: unsignedVPTokens.first!.dataToSign, as: UTF8.self)
        XCTAssertTrue(actualDataToSign.contains("canonicalized"))
        XCTAssertTrue(actualDataToSign.starts(with: "ey"))
        XCTAssertTrue(actualDataToSign.contains("."))
        XCTAssertTrue(actualDataToSign.split(separator: ".").count == 2)
    }

    // MARK: - build(credentialToCredentialQueryIdMappings:) — error paths

    func testThrowsWhenAuthorizationRequestIsNotDcqlRequest() async throws {
        let builder = UnsignedLdpVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .draft23),
            specVersion: .draft23,
            id: "vp-id",
            holder: "did:jwk:holder",
            signatureSuite: SignatureAlgorithm.jsonWebSignature2020.rawValue
        )
        var mappings = [
            CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: AnyCodable(ldpVC()), credentialQueryId: "q1")
        ]

        await XCTAssertAsyncThrowsError(
            try await builder.build(credentialToCredentialQueryIdMappings: &mappings)
        ) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Expected AuthorizationDcqlRequest for DCQL flow",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testThrowsWhenCredentialQueryIdNotFoundInDcqlQuery() async throws {
        let builder = builderWithDcqlRequest(credentialQueryId: "q1", credentialQueryFormat: "ldp_vc")
        var mappings = [
            CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: AnyCodable(ldpVC()), credentialQueryId: "nonexistent-id")
        ]

        await XCTAssertAsyncThrowsError(
            try await builder.build(credentialToCredentialQueryIdMappings: &mappings)
        ) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "No matching credential query found for credential query id: nonexistent-id",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testThrowsWhenCredentialIsNotADictionary() async throws {
        let builder = builderWithDcqlRequest(credentialQueryId: "q1", credentialQueryFormat: "ldp_vc", requireCryptographicHolderBinding: true)
        var mappings = [
            CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: AnyCodable("not-a-dict"), credentialQueryId: "q1")
        ]

        await XCTAssertAsyncThrowsError(
            try await builder.build(credentialToCredentialQueryIdMappings: &mappings)
        ) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Credential is not a valid JSON object",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testThrowsWhenCredentialHasNoHolderId() async throws {
        let builder = builderWithDcqlRequest(credentialQueryId: "q1", credentialQueryFormat: "ldp_vc", requireCryptographicHolderBinding: true)
        var mappings = [
            CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: AnyCodable(ldpVCWithoutHolderBinding()), credentialQueryId: "q1")
        ]

        await XCTAssertAsyncThrowsError(
            try await builder.build(credentialToCredentialQueryIdMappings: &mappings)
        ) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Holder ID not available in the credential",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testThrowsWhenJsonLdCanonicalizerIsNotSet() async throws {
        JsonLd.setCanonicalizer(nil)
        let builder = builderWithDcqlRequest(credentialQueryId: "q1", credentialQueryFormat: "ldp_vc", requireCryptographicHolderBinding: true)
        var mappings = [
            CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: AnyCodable(ldpVC()), credentialQueryId: "q1")
        ]

        await XCTAssertAsyncThrowsError(
            try await builder.build(credentialToCredentialQueryIdMappings: &mappings)
        ) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Failed to get JsonLd canonicalizer.",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    // MARK: - build(credentialToCredentialQueryIdMappings:) — requireCryptographicHolderBinding = false

    func testBuildWithHolderBindingFalseProducesNoUnsignedTokens() async throws {
        let builder = builderWithDcqlRequest(credentialQueryId: "q1", credentialQueryFormat: "ldp_vc", requireCryptographicHolderBinding: false)
        var mappings = [
            CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: AnyCodable(ldpVC()), credentialQueryId: "q1")
        ]

        let (payload, unsignedVPTokens) = try await builder.build(credentialToCredentialQueryIdMappings: &mappings)

        XCTAssertTrue(unsignedVPTokens.isEmpty)

        let vpPayload = payload as? [String: LdpVPToken]
        XCTAssertNotNil(vpPayload)
        XCTAssertEqual(vpPayload?.count, 1)

        let ldpToken = vpPayload?.values.first
        XCTAssertNotNil(ldpToken)
        XCTAssertEqual(ldpToken?.type, ["VerifiablePresentation"])
        XCTAssertNil(ldpToken?.proof)
        XCTAssertEqual(ldpToken?.verifiableCredential.count, 1)
    }

    func testBuildWithHolderBindingFalseSetsIdentifierOnMapping() async throws {
        let builder = builderWithDcqlRequest(credentialQueryId: "q1", credentialQueryFormat: "ldp_vc", requireCryptographicHolderBinding: false)
        var mappings = [
            CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: AnyCodable(ldpVC()), credentialQueryId: "q1")
        ]

        _ = try await builder.build(credentialToCredentialQueryIdMappings: &mappings)

        XCTAssertNotNil(mappings[0].identifier)
        XCTAssertFalse(mappings[0].identifier!.isEmpty)
    }

    func testBuildWithHolderBindingFalseForMultipleMappings() async throws {
        let builder = builderWithDcqlRequest(
            credentials: [("q1", "ldp_vc"), ("q2", "ldp_vc")],
            requireCryptographicHolderBinding: false
        )
        var mappings = [
            CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: AnyCodable(ldpVC()), credentialQueryId: "q1"),
            CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: AnyCodable(ldpVC()), credentialQueryId: "q2")
        ]

        let (payload, unsignedVPTokens) = try await builder.build(credentialToCredentialQueryIdMappings: &mappings)

        XCTAssertTrue(unsignedVPTokens.isEmpty)
        let vpPayload = payload as? [String: LdpVPToken]
        XCTAssertEqual(vpPayload?.count, 2)
        XCTAssertNotNil(mappings[0].identifier)
        XCTAssertNotNil(mappings[1].identifier)
        XCTAssertNotEqual(mappings[0].identifier, mappings[1].identifier)
    }

    // MARK: - build(credentialToCredentialQueryIdMappings:) — requireCryptographicHolderBinding = true

    func testBuildWithHolderBindingTrueProducesUnsignedToken() async throws {
        let canonicalized = "canonicalized-payload"
        JsonLd.setCanonicalizer { _ in canonicalized }
        defer { JsonLd.setCanonicalizer(nil) }

        let builder = builderWithDcqlRequest(credentialQueryId: "q1", credentialQueryFormat: "ldp_vc", requireCryptographicHolderBinding: true)
        let credential = ldpVC()
        var mappings = [
            CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: AnyCodable(credential), credentialQueryId: "q1")
        ]

        let (payload, unsignedVPTokens) = try await builder.build(credentialToCredentialQueryIdMappings: &mappings)

        XCTAssertEqual(unsignedVPTokens.count, 1)
        let token = unsignedVPTokens[0]
        XCTAssertEqual(token.format, .ldp_vc)
        XCTAssertEqual(token.holderKeyReference, "did:example:subject")
        XCTAssertFalse(token.dataToSign.isEmpty)
        let actualDataToSign = String(decoding: unsignedVPTokens.first!.dataToSign, as: UTF8.self)
        XCTAssertTrue(actualDataToSign.contains("."))

        let vpPayload = payload as? [String: LdpVPToken]
        XCTAssertEqual(vpPayload?.count, 1)

        let ldpToken = vpPayload?.values.first
        XCTAssertNotNil(ldpToken?.proof)
        XCTAssertEqual(ldpToken?.proof?.verificationMethod, "did:example:subject")
        XCTAssertEqual(ldpToken?.proof?.challenge, "nonce")
        XCTAssertEqual(ldpToken?.proof?.domain, "client_id")
        XCTAssertEqual(ldpToken?.proof?.type, SignatureAlgorithm.jsonWebSignature2020.rawValue)
        XCTAssertEqual(ldpToken?.verifiableCredential.count, 1)
    }

    func testBuildWithHolderBindingTrueSetsIdentifierOnMapping() async throws {
        JsonLd.setCanonicalizer { _ in "canonicalized" }
        defer { JsonLd.setCanonicalizer(nil) }

        let builder = builderWithDcqlRequest(credentialQueryId: "q1", credentialQueryFormat: "ldp_vc", requireCryptographicHolderBinding: true)
        var mappings = [
            CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: AnyCodable(ldpVC()), credentialQueryId: "q1")
        ]

        _ = try await builder.build(credentialToCredentialQueryIdMappings: &mappings)

        XCTAssertNotNil(mappings[0].identifier)
        XCTAssertFalse(mappings[0].identifier!.isEmpty)
    }

    func testBuildWithHolderBindingTrueVpTokenHasJws2020Context() async throws {
        let canonicalized = "canonicalized"
        JsonLd.setCanonicalizer { _ in canonicalized }
        defer { JsonLd.setCanonicalizer(nil) }

        let builder = builderWithDcqlRequest(credentialQueryId: "q1", credentialQueryFormat: "ldp_vc", requireCryptographicHolderBinding: true)
        var mappings = [
            CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: AnyCodable(ldpVC()), credentialQueryId: "q1")
        ]

        let (payload, _) = try await builder.build(credentialToCredentialQueryIdMappings: &mappings)

        let ldpToken = try XCTUnwrap((payload as? [String: LdpVPToken])?.values.first)
        let expectedContext = ["https://www.w3.org/2018/credentials/v1", "https://w3id.org/security/suites/jws-2020/v1"]
        XCTAssertEqual(ldpToken.context, expectedContext)
        XCTAssertEqual(ldpToken.type, ["VerifiablePresentation"])
        XCTAssertEqual(ldpToken.holder, "did:example:subject")
        XCTAssertEqual(ldpToken.verifiableCredential.count, 1)
        XCTAssertEqual(ldpToken.proof?.type, SignatureAlgorithm.jsonWebSignature2020.rawValue)
        XCTAssertEqual(ldpToken.proof?.verificationMethod, "did:example:subject")
        XCTAssertEqual(ldpToken.proof?.challenge, "nonce")
        XCTAssertEqual(ldpToken.proof?.domain, "client_id")
    }

    func testBuildWithHolderBindingTrueDataToSignContainsJwsHeaderAndPayload() async throws {
        let canonicalized = "canonicalized-ldp-payload"
        JsonLd.setCanonicalizer { _ in canonicalized }
        defer { JsonLd.setCanonicalizer(nil) }

        let builder = builderWithDcqlRequest(credentialQueryId: "q1", credentialQueryFormat: "ldp_vc", requireCryptographicHolderBinding: true)
        var mappings = [
            CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: AnyCodable(ldpVC()), credentialQueryId: "q1")
        ]

        let (_, unsignedVPTokens) = try await builder.build(credentialToCredentialQueryIdMappings: &mappings)

        let actualDataToSign = String(decoding: unsignedVPTokens.first!.dataToSign, as: UTF8.self)
        let parts = actualDataToSign.components(separatedBy: ".")
        XCTAssertEqual(parts.count, 2, "dataToSign must be '<jwsHeader>.<canonicalizedPayload>'")
        XCTAssertFalse(parts[0].isEmpty, "JWS header must be non-empty base64url string")
        XCTAssertEqual(parts[1], canonicalized)
    }

    // MARK: - Helpers

    private func ldpVCWithoutHolderBinding() -> [String: Any] {
        return [
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiableCredential"],
            "issuer": "did:example:issuer",
            "issuanceDate": "2020-08-19T21:41:50Z",
            "credentialSubject": ["given_name": "Bob"]
        ]
    }

    private func buildDcqlQuery(credentials: [(id: String, format: String)], requireCryptographicHolderBinding: Bool) -> DCQLQuery {
        let json: [String: Any] = [
            "credentials": credentials.map { cred in
                [
                    "id": cred.id,
                    "format": cred.format,
                    "meta": [:] as [String: Any],
                    "require_cryptographic_holder_binding": requireCryptographicHolderBinding
                ] as [String: Any]
            }
        ]
        return createInstance(json, as: DCQLQuery.self)
    }

    private func builderWithDcqlRequest(
        credentialQueryId: String,
        credentialQueryFormat: String,
        requireCryptographicHolderBinding: Bool = false
    ) -> UnsignedLdpVPTokenBuilder {
        return builderWithDcqlRequest(
            credentials: [(credentialQueryId, credentialQueryFormat)],
            requireCryptographicHolderBinding: requireCryptographicHolderBinding
        )
    }

    private func builderWithDcqlRequest(
        credentials: [(id: String, format: String)],
        requireCryptographicHolderBinding: Bool = false
    ) -> UnsignedLdpVPTokenBuilder {
        let dcqlQuery = buildDcqlQuery(credentials: credentials, requireCryptographicHolderBinding: requireCryptographicHolderBinding)
        let authorizationRequest = AuthorizationDcqlRequest(
            clientId: "client_id",
            responseType: ResponseType.vp_token.rawValue,
            responseMode: ResponseMode.directPost.rawValue,
            responseUri: "https://mock-verifier.com",
            redirectUri: nil,
            nonce: "nonce",
            walletNonce: nil,
            state: "state",
            dcqlQuery: dcqlQuery,
            clientMetadata: nil
        )
        return UnsignedLdpVPTokenBuilder(
            authorizationRequest: authorizationRequest,
            specVersion: .v1,
            id: "vp-id",
            holder: "did:jwk:holder",
            signatureSuite: SignatureAlgorithm.jsonWebSignature2020.rawValue
        )
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
