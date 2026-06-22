import XCTest
@testable import OpenID4VP

final class UnsignedLdpVPTokenBuilderTests: XCTestCase {
    private let canonicalized = "Y2Fub25pY2FsaXplZA"

    override func setUp() {
        JsonLd.setCanonicalizer { _ in "Y2Fub25pY2FsaXplZA" }
    }

    // MARK: - build(credentialInputDescriptorMappings:) tests

    func testThrowsWhenAuthorizationRequestIsNotPresentationExchangeRequest() async throws {
        let builder = UnsignedLdpVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .v1),
            specVersion: .v1,
            id: "vp-id"
        )
        var mappings = [
            CredentialInputDescriptorMapping(format: .ldp_vc, credential: AnyCodable(ldpVC()), inputDescriptorId: "cred-input-1")
        ]

        await XCTAssertAsyncThrowsError(
            try await builder.build(credentialInputDescriptorMappings: &mappings)
        ) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Expected AuthorizationPresentationExchangeRequest for Presentation Exchange flow",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testCreationOfUnsignedLdpVPToken() async throws {
        let builder = UnsignedLdpVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .draft23),
            specVersion: .draft23,
            id: "ebc6f1c2"
        )
        var mappings = [
            CredentialInputDescriptorMapping(format: .ldp_vc, credential: AnyCodable(ldpVC()), inputDescriptorId: "cred-input-1")
        ]

        let (payload, unsignedVPTokens) = try await builder.build(credentialInputDescriptorMappings: &mappings)

        assertLdpVPTokenPayload(payload, expectedCredentialsInPresentation: convertToJsonString([ldpVC()]))

        assertUnsignedVPTokens(unsignedVPTokens, expected: [
            [
                "format": FormatType.ldp_vc,
                "signatureAlgorithm": SignatureAlgorithm.edDsa.rawValue,
                "holderKeyReference": didJwkKey,
                "dataToSign": [
                    "header": [
                        "alg": "EdDSA",
                        "crit" : ["b64"],
                        "b64": false
                    ],
                    "payload": "canonicalized"
                ]
            ]
        ])
    }

    func testContextIncludesJwsSuite() async throws {
        JsonLd.setCanonicalizer { _ in "Y2Fub25pY2FsaXplZA" }
        defer { JsonLd.setCanonicalizer(nil) }

        let builder = UnsignedLdpVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .draft23),
            specVersion: .draft23,
            id: "ebc6f1c2"
        )
        var mappings = [
            CredentialInputDescriptorMapping(format: .ldp_vc, credential: AnyCodable(ldpVC()), inputDescriptorId: "cred-input-1")
        ]

        let (payload, unsignedVPTokens) = try await builder.build(credentialInputDescriptorMappings: &mappings)

        let ldpVPTokenPayload = try XCTUnwrap(payload as? [String: LdpVP])
        let ldpVP = ldpVPTokenPayload.values.first!
        guard case let .vp(ldpToken) = ldpVP else {
            XCTFail("Expected LdpVP.vp"); return
        }
        XCTAssertEqual(ldpToken.context, ["https://www.w3.org/2018/credentials/v1", "https://w3id.org/security/suites/jws-2020/v1"])
        XCTAssertEqual(ldpToken.type, ["VerifiablePresentation"])
        XCTAssertEqual(ldpToken.id, "ebc6f1c2")
        XCTAssertEqual(ldpToken.holder, didJwkKey)
        XCTAssertEqual(ldpToken.proof?.type, SignatureSuite.jsonWebSignature2020.rawValue)
        XCTAssertEqual(ldpToken.proof?.verificationMethod, didJwkKey)
        XCTAssertNotNil(ldpToken.proof?.challenge)
        XCTAssertEqual(ldpToken.proof?.domain, "client_id")
        XCTAssertEqual(ldpToken.verifiableCredential.count, 1)
        // JsonWebSignature2020: dataToSign is "<base64url-JWS-header>.canonicalized"
        assertUnsignedVPTokens(unsignedVPTokens, expected: [
            [
                "format": FormatType.ldp_vc,
                "signatureAlgorithm": SignatureAlgorithm.edDsa.rawValue,
                "holderKeyReference": didJwkKey,
                "dataToSign": ["header": ["alg": "EdDSA", "crit": ["b64"], "b64": false] as [String: Any], "payload": "canonicalized"] as [String: Any]
            ]
        ])
    }
    
    // MARK: - build(credentialInputDescriptorMappings:) — PE flow: nil holder/signatureSuite

    func testExtractsHolderFromCredentialSubjectIdWhenBothNil() async throws {
        // holder=nil && signatureSuite=nil → extracts from credentialSubject.id
        let builder = UnsignedLdpVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .draft23),
            specVersion: .draft23,
            id: "pe-flow-id"
        )
        var mappings = [
            CredentialInputDescriptorMapping(format: .ldp_vc, credential: AnyCodable(ldpVC()), inputDescriptorId: "cred-input-1")
        ]

        let (payload, unsignedVPTokens) = try await builder.build(credentialInputDescriptorMappings: &mappings)

        let ldpVPTokenPayload = try XCTUnwrap(payload as? [String: LdpVP])
        let ldpVP = ldpVPTokenPayload.values.first!
        guard case let .vp(ldpToken) = ldpVP else { XCTFail("Expected LdpVP.vp"); return }

        // holderId must come from credentialSubject.id (didJwkKey already contains #0, sanitize keeps it unchanged)
        XCTAssertEqual(ldpToken.holder, didJwkKey)
        XCTAssertEqual(ldpToken.proof?.verificationMethod, didJwkKey)
        XCTAssertEqual(unsignedVPTokens.count, 1)
        XCTAssertEqual(unsignedVPTokens[0].holderKeyReference, didJwkKey)
    }

    func testSignatureSuiteContextInBuiltTokenPayload() async throws {
        // holder=nil && signatureSuite=nil → suite defaults to JsonWebSignature2020
        let builder = UnsignedLdpVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .draft23),
            specVersion: .draft23,
            id: "pe-flow-id"
        )
        var mappings = [
            CredentialInputDescriptorMapping(format: .ldp_vc, credential: AnyCodable(ldpVC()), inputDescriptorId: "cred-input-1")
        ]

        let (payload, _) = try await builder.build(credentialInputDescriptorMappings: &mappings)

        let ldpVPTokenPayload = try XCTUnwrap(payload as? [String: LdpVP])
        let ldpVP = ldpVPTokenPayload.values.first!
        guard case let .vp(ldpToken) = ldpVP else { XCTFail("Expected LdpVP.vp"); return }

        XCTAssertEqual(ldpToken.proof?.type, SignatureSuite.jsonWebSignature2020.rawValue)
        XCTAssertEqual(
            ldpToken.context,
            ["https://www.w3.org/2018/credentials/v1", "https://w3id.org/security/suites/jws-2020/v1"]
        )
    }

    func testNestedPathWrittenToFormatToCredentialInputDescriptorMappingForEachCredential() async throws {
        let builder = UnsignedLdpVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .draft23),
            specVersion: .draft23,
            id: "pe-flow-id"
        )
        var mappings = [
            CredentialInputDescriptorMapping(format: .ldp_vc, credential: AnyCodable(ldpVC()), inputDescriptorId: "desc-1"),
            CredentialInputDescriptorMapping(format: .ldp_vc, credential: AnyCodable(ldpVC()), inputDescriptorId: "desc-2"),
        ]

        _ = try await builder.build(credentialInputDescriptorMappings: &mappings)

        // Each mapping must carry the nested path $.verifiableCredential[n]
        XCTAssertEqual(mappings.count, 2)
        XCTAssertEqual(mappings[0].nestedPath, "$.verifiableCredential[0]")
        XCTAssertEqual(mappings[1].nestedPath, "$.verifiableCredential[0]")
    }

    func testThrowsWhenCredentialHasNoCredentialSubjectIdAndBothNil() async throws {
        let credentialWithoutSubjectId: [String: Any] = ["type": ["VerifiableCredential"]]
        let builder = UnsignedLdpVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .draft23),
            specVersion: .draft23,
            id: "pe-flow-id"
        )
        var mappings = [
            CredentialInputDescriptorMapping(format: .ldp_vc, credential: AnyCodable(credentialWithoutSubjectId), inputDescriptorId: "cred-input-1")
        ]

        await XCTAssertAsyncThrowsError(
            try await builder.build(credentialInputDescriptorMappings: &mappings)
        ) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Holder ID not available in the credential",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    // MARK: - build(credentialToCredentialQueryIdMappings:) — error paths

    func testThrowsWhenAuthorizationRequestIsNotDcqlRequest() async throws {
        let builder = UnsignedLdpVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .draft23),
            specVersion: .draft23,
            id: "vp-id"
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
        
        XCTAssertEqual(unsignedVPTokens.count, 0)
        assertLdpVPTokenPayload(payload, expectedCredentialsInPresentation: convertToJsonString([ldpVC()]), tokenType: .vc)
    }

    func testBuildWithHolderBindingFalseSetsIdentifierOnMapping() async throws {
        let builder = builderWithDcqlRequest(credentialQueryId: "q1", credentialQueryFormat: "ldp_vc", requireCryptographicHolderBinding: false)
        var mappings = [
            CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: AnyCodable(ldpVC()), credentialQueryId: "q1")
        ]

        _ = try await builder.build(credentialToCredentialQueryIdMappings: &mappings)

        let identifier = try XCTUnwrap(mappings[0].identifier)
        XCTAssertFalse(identifier.isEmpty)
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

        XCTAssertEqual(unsignedVPTokens.count, 0)
        let vpPayload = try XCTUnwrap(payload as? [String: LdpVP])
        XCTAssertEqual(vpPayload.count, 2)
        let id0 = try XCTUnwrap(mappings[0].identifier)
        let id1 = try XCTUnwrap(mappings[1].identifier)
        XCTAssertFalse(id0.isEmpty)
        XCTAssertFalse(id1.isEmpty)
        XCTAssertNotEqual(id0, id1)
    }

    // MARK: - build(credentialToCredentialQueryIdMappings:) — requireCryptographicHolderBinding = true

    func testBuildWithHolderBindingTrueProducesUnsignedToken() async throws {
        let builder = builderWithDcqlRequest(credentialQueryId: "q1", credentialQueryFormat: "ldp_vc", requireCryptographicHolderBinding: true)
        var mappings = [
            CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: AnyCodable(ldpVCWithJwkHolder()), credentialQueryId: "q1")
        ]

        let (payload, unsignedVPTokens) = try await builder.build(credentialToCredentialQueryIdMappings: &mappings)

        assertUnsignedVPTokens(unsignedVPTokens, expected: [
            [
                "format": FormatType.ldp_vc,
                "signatureAlgorithm": SignatureAlgorithm.edDsa.rawValue,
                "holderKeyReference": didJwkKey,
                "dataToSign": ["header": ["alg": "EdDSA", "crit": ["b64"], "b64": false] as [String: Any], "payload": "canonicalized"] as [String: Any]
            ]
        ])

        let vpPayload = try XCTUnwrap(payload as? [String: LdpVP])
        XCTAssertEqual(vpPayload.count, 1)
        guard case let .vp(ldpToken) = vpPayload.values.first else {
            XCTFail("Expected LdpVP.vp entry in payload"); return
        }
        XCTAssertNotNil(ldpToken.proof)
        XCTAssertEqual(ldpToken.proof?.verificationMethod, didJwkKey)
        XCTAssertEqual(ldpToken.proof?.challenge, "nonce")
        XCTAssertEqual(ldpToken.proof?.domain, "client_id")
        XCTAssertEqual(ldpToken.proof?.type, SignatureSuite.jsonWebSignature2020.rawValue)
        XCTAssertEqual(ldpToken.verifiableCredential.count, 1)
    }

    func testBuildWithHolderBindingTrueSetsIdentifierOnMapping() async throws {
        let builder = builderWithDcqlRequest(credentialQueryId: "q1", credentialQueryFormat: "ldp_vc", requireCryptographicHolderBinding: true)
        var mappings = [
            CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: AnyCodable(ldpVCWithJwkHolder()), credentialQueryId: "q1")
        ]

        _ = try await builder.build(credentialToCredentialQueryIdMappings: &mappings)

        let identifier = try XCTUnwrap(mappings[0].identifier)
        XCTAssertFalse(identifier.isEmpty)
    }

    func testBuildWithHolderBindingTrueVpTokenHasJws2020Context() async throws {
        let builder = builderWithDcqlRequest(credentialQueryId: "q1", credentialQueryFormat: "ldp_vc", requireCryptographicHolderBinding: true)
        var mappings = [
            CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: AnyCodable(ldpVCWithJwkHolder()), credentialQueryId: "q1")
        ]

        let (payload, _) = try await builder.build(credentialToCredentialQueryIdMappings: &mappings)

        let ldpToken = try XCTUnwrap((payload as? [String: LdpVP])?.values.first.flatMap {
            if case let .vp(token) = $0 { return token } else { return nil }
        })
        XCTAssertEqual(ldpToken.context, ["https://www.w3.org/2018/credentials/v1", "https://w3id.org/security/suites/jws-2020/v1"])
        XCTAssertEqual(ldpToken.type, ["VerifiablePresentation"])
        XCTAssertEqual(ldpToken.holder, didJwkKey)
        XCTAssertEqual(ldpToken.verifiableCredential.count, 1)
        XCTAssertEqual(ldpToken.proof?.type, SignatureSuite.jsonWebSignature2020.rawValue)
        XCTAssertEqual(ldpToken.proof?.verificationMethod, didJwkKey)
        XCTAssertEqual(ldpToken.proof?.challenge, "nonce")
        XCTAssertEqual(ldpToken.proof?.domain, "client_id")
    }

    func testBuildWithHolderBindingTrueDataToSignContainsJwsHeaderAndPayload() async throws {
        let builder = builderWithDcqlRequest(credentialQueryId: "q1", credentialQueryFormat: "ldp_vc", requireCryptographicHolderBinding: true)
        var mappings = [
            CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: AnyCodable(ldpVCWithJwkHolder()), credentialQueryId: "q1")
        ]

        let (_, unsignedVPTokens) = try await builder.build(credentialToCredentialQueryIdMappings: &mappings)

        assertUnsignedVPTokens(unsignedVPTokens, expected: [
            [
                "format": FormatType.ldp_vc,
                "signatureAlgorithm": SignatureAlgorithm.edDsa.rawValue,
                "holderKeyReference": didJwkKey,
                "dataToSign": ["header": ["alg": "EdDSA", "crit": ["b64"], "b64": false] as [String: Any], "payload": "canonicalized"] as [String: Any]
            ]
        ])
    }

    // MARK: - Helpers

    private func ldpVC() -> [String: Any] {
        return [
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiableCredential"],
            "issuer": "did:example:issuer",
            "issuanceDate": "2020-08-19T21:41:50Z",
            "credentialSubject": ["id": didJwkKey]
        ]
    }

    private func ldpVCWithJwkHolder() -> [String: Any] {
        // Use the bare JWK DID without the fragment (#0) so that sanitize() appends #0
        // and produces exactly didJwkKey as the holderKeyReference/verificationMethod
        let bareJwkDid = String(didJwkKey.dropLast(2)) // strips "#0"
        return [
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiableCredential"],
            "issuer": "did:example:issuer",
            "issuanceDate": "2020-08-19T21:41:50Z",
            "credentialSubject": ["id": bareJwkDid]
        ]
    }

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
            id: "vp-id"
        )
    }

    private func assertUnsignedVPTokens(
        _ actual: [UnsignedVPToken],
        expected: [[String: Any]],
        file: StaticString = #file,
        line: UInt = #line
    ) {
        XCTAssertEqual(actual.count, expected.count, "Token count mismatch", file: file, line: line)
        for (index, (token, expectedDict)) in zip(actual, expected).enumerated() {
            if let expectedFormat = expectedDict["format"] as? FormatType {
                XCTAssertEqual(token.format, expectedFormat, "Token[\(index)].format mismatch", file: file, line: line)
            }
            if let expectedAlg = expectedDict["signatureAlgorithm"] as? String {
                XCTAssertEqual(token.signatureAlgorithm, expectedAlg, "Token[\(index)].signatureAlgorithm mismatch", file: file, line: line)
            }
            if let expectedRef = expectedDict["holderKeyReference"] as? String {
                XCTAssertEqual(token.holderKeyReference, expectedRef, "Token[\(index)].holderKeyReference mismatch", file: file, line: line)
            }
            if let rawExpected = expectedDict["dataToSign"] as? String {
                let actual = String(decoding: token.dataToSign, as: UTF8.self)
                XCTAssertEqual(actual, rawExpected, "Token[\(index)].dataToSign mismatch", file: file, line: line)
            } else if let jwsExpected = expectedDict["dataToSign"] as? [String: Any],
                      let expectedHeader = jwsExpected["header"] as? [String: Any],
                      let expectedPayload = jwsExpected["payload"] as? String {
                assertJWSDataToSign(token.dataToSign, expectedHeader: expectedHeader, expectedPayload: expectedPayload, file: file, line: line)
            }
        }
    }

    private enum TokenPresentationType {
        case vp
        case vc
    }

    private func assertLdpVPTokenPayload(
        _ payload: Any?,
        holder: String = didJwkKey,
        expectedCredentialsInPresentation: String,
        tokenType: TokenPresentationType = .vp,
        file: StaticString = #file,
        line: UInt = #line
    ) {
        switch tokenType {
        case .vp:
            guard let parsedPayload = payload as? [String: LdpVP] else {
                XCTFail("Expected  string to LdpVP.vp payload", file: file, line: line)
                return
            }
            guard case let .vp(ldpToken) = parsedPayload.values.first else {
                XCTFail("Expected LdpVP.vp entry in payload", file: file, line: line)
                return
            }
            XCTAssertEqual(ldpToken.type, ["VerifiablePresentation"], file: file, line: line)
            XCTAssertEqual(ldpToken.id, "ebc6f1c2", file: file, line: line)
            XCTAssertEqual(ldpToken.holder, holder, file: file, line: line)
            XCTAssertEqual(ldpToken.proof?.type, SignatureSuite.jsonWebSignature2020.rawValue, file: file, line: line)
            XCTAssertEqual(ldpToken.proof?.verificationMethod, holder, file: file, line: line)
            XCTAssertNotNil(ldpToken.proof?.challenge)
            XCTAssertEqual(ldpToken.proof?.domain, "client_id", file: file, line: line)
            assertJsonString(expected: expectedCredentialsInPresentation, actual: convertToJsonString(ldpToken.verifiableCredential), file: file, line: line)

        case .vc:
            guard let dict = payload as? [String: LdpVP],
                  let firstEntry = dict.values.first,
                  case let .vc(ldpVCToken) = firstEntry else {
                XCTFail("Expected [String: LdpVP] payload with LdpVP.vc entries for VC type", file: file, line: line)
                return
            }
            assertJsonString(expected: expectedCredentialsInPresentation, actual: convertToJsonString([ldpVCToken.verifiableCredential.value]), file: file, line: line)
        }
    }

    private func assertJWSDataToSign(_ dataToSign: Data, expectedHeader: [String: Any], expectedPayload: String, file: StaticString = #file, line: UInt = #line) {
        let str = String(decoding: dataToSign, as: UTF8.self)
        let parts = str.components(separatedBy: ".")
        XCTAssertEqual(parts.count, 2, "dataToSign must be '<jwsHeader>.<payload>'", file: file, line: line)
        guard parts.count == 2 else { return }
        guard let headerData = Data(base64Encoded: parts[0].base64URLToBase64()),
              let actualHeader = try? JSONSerialization.jsonObject(with: headerData) as? [String: Any] else {
            XCTFail("Failed to decode JWS header from base64url: \(parts[0])", file: file, line: line)
            return
        }
        assertDictionariesEqual(expected: expectedHeader, actual: actualHeader, file: file, line: line)
        XCTAssertEqual(parts[1], expectedPayload, file: file, line: line)
    }
}
