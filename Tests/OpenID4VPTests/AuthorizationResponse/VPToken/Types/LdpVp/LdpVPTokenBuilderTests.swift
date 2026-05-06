import XCTest
@testable import OpenID4VP

final class LdpVPTokenBuilderTests: XCTestCase {

    let builder = LdpVPTokenBuilder(authorizationRequest: getMockAuthorizationRequest(specVersion: .draft23))

    private let credential = AnyCodable(["@context": ["https://www.w3.org/2018/credentials/v1"], "type": ["VerifiableCredential"]])
    private let unsignedVPToken = UnsignedVPToken(
        format: .ldp_vc,
        holderKeyReference: "did:example:holder",
        signatureAlgorithm: SignatureAlgorithm.edDsA.rawValue,
        // "<base64url-JWS-header>.<payload>" — header decodes to {"alg":"EdDSA","crit":["b64"],"b64":false}
        dataToSign: Data("eyJhbGciOiJFZERTQSIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9.payload".utf8)
    )

    private func makeLdpVPToken(
        proofType: String = SignatureSuite.jsonWebSignature2020.rawValue,
        jws: String? = nil,
        proofValue: String? = nil,
        signatureValue: String? = nil
    ) ->LdpVP {
        let proof = Proof(
            type: proofType,
            created: nil,
            challenge: "nonce",
            domain: "client_id",
            jws: jws,
            verificationMethod: "did:example:holder"
        )
        return .vp(
            LdpVPToken(
                verifiableCredential: [credential],
                id: "vp-id",
                holder: "did:example:holder",
                proof: proof
            )
        )
    }

    // MARK: - build(credentialInputDescriptorMappings:)

    func testBuildWithHolderBindingJsonWebSignature2020() throws {
        let signature = Data("mockSig".utf8)
        let ldpToken = makeLdpVPToken(proofType: SignatureSuite.jsonWebSignature2020.rawValue)
        let mappings = [
            CredentialInputDescriptorMapping(format: .ldp_vc, credential: credential, inputDescriptorId: "desc-1")
        ]
        let unsignedResult = (vpTokenSigningPayload: ldpToken as Any?, unsignedVPTokens: [unsignedVPToken])

        let result = try builder.build(
            credentialInputDescriptorMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [VPTokenSigningResult(signedData: signature)],
            rootIndex: 0
        )

        XCTAssertEqual(result.vpTokens.count, 1)
        let token = try XCTUnwrap(result.vpTokens[0] as? LdpVPToken)
        let expectedJws = "eyJhbGciOiJFZERTQSIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9..\(signature.toBase64UrlEncoded())"
        XCTAssertEqual(token.proof?.jws, expectedJws)
        XCTAssertNil(token.proof?.proofValue)
        XCTAssertNil(token.proof?.signatureValue)
        XCTAssertEqual(result.DescriptorMaps.count, 1)
        XCTAssertEqual(result.DescriptorMaps[0].id, "desc-1")
        XCTAssertEqual(result.DescriptorMaps[0].format, .ldp_vp)
        XCTAssertEqual(result.DescriptorMaps[0].path, "$[0]")
        XCTAssertEqual(result.nextIndex, 1)
    }

    func testBuildWithHolderBindingEd25519Signature2018() throws {
        let signature = Data("mockSig".utf8)
        let ldpToken = makeLdpVPToken(proofType: SignatureSuite.ed25519Signature2018.rawValue)
        let mappings = [
            CredentialInputDescriptorMapping(format: .ldp_vc, credential: credential, inputDescriptorId: "desc-1")
        ]
        let unsignedResult = (vpTokenSigningPayload: ldpToken as Any?, unsignedVPTokens: [unsignedVPToken])

        let result = try builder.build(
            credentialInputDescriptorMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [VPTokenSigningResult(signedData: signature)],
            rootIndex: 0
        )

        let token = try XCTUnwrap(result.vpTokens[0] as? LdpVPToken)
        let expectedJws = "eyJhbGciOiJFZERTQSIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9..\(signature.toBase64UrlEncoded())"
        XCTAssertEqual(token.proof?.jws, expectedJws)
        XCTAssertNil(token.proof?.proofValue)
        XCTAssertNil(token.proof?.signatureValue)
    }

    func testBuildWithHolderBindingRsaSignature2018() throws {
        let signature = Data("mockSig".utf8)
        let ldpToken = makeLdpVPToken(proofType: SignatureSuite.rsaSignature2018.rawValue)
        let mappings = [
            CredentialInputDescriptorMapping(format: .ldp_vc, credential: credential, inputDescriptorId: "desc-1")
        ]
        let unsignedResult = (vpTokenSigningPayload: ldpToken as Any?, unsignedVPTokens: [unsignedVPToken])

        let result = try builder.build(
            credentialInputDescriptorMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [VPTokenSigningResult(signedData: signature)],
            rootIndex: 0
        )

        let token = try XCTUnwrap(result.vpTokens[0] as? LdpVPToken)
        XCTAssertEqual(token.proof?.signatureValue, signature.toBase64UrlEncoded())
        XCTAssertNil(token.proof?.jws)
        XCTAssertNil(token.proof?.proofValue)
    }

    func testBuildWithHolderBindingEd25519Signature2020() throws {
        let signature = Data("mockSig".utf8)
        let ldpToken = makeLdpVPToken(proofType: SignatureSuite.ed25519Signature2020.rawValue)
        let mappings = [
            CredentialInputDescriptorMapping(format: .ldp_vc, credential: credential, inputDescriptorId: "desc-1")
        ]
        let unsignedResult = (vpTokenSigningPayload: ldpToken as Any?, unsignedVPTokens: [unsignedVPToken])

        let result = try builder.build(
            credentialInputDescriptorMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [VPTokenSigningResult(signedData: signature)],
            rootIndex: 0
        )

        let token = try XCTUnwrap(result.vpTokens[0] as? LdpVPToken)
        XCTAssertEqual(token.proof?.proofValue, BaseEncoding.base58BtcEncode(signature))
        XCTAssertNil(token.proof?.jws)
        XCTAssertNil(token.proof?.signatureValue)
    }

    func testBuildRespectsRootIndexOffset() throws {
        let signature = Data("mockSig".utf8)
        let ldpToken = makeLdpVPToken()
        let mappings = [
            CredentialInputDescriptorMapping(format: .ldp_vc, credential: credential, inputDescriptorId: "desc-1")
        ]
        let unsignedResult = (vpTokenSigningPayload: ldpToken as Any?, unsignedVPTokens: [unsignedVPToken])

        let result = try builder.build(
            credentialInputDescriptorMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [VPTokenSigningResult(signedData: signature)],
            rootIndex: 3
        )

        XCTAssertEqual(result.DescriptorMaps[0].path, "$[3]")
        XCTAssertEqual(result.nextIndex, 4)
    }

    func testBuildDescriptorMapContainsAllMappings() throws {
        let signature = Data("mockSig".utf8)
        let ldpToken = makeLdpVPToken()
        let mappings = [
            CredentialInputDescriptorMapping(format: .ldp_vc, credential: credential, inputDescriptorId: "desc-1"),
            CredentialInputDescriptorMapping(format: .ldp_vc, credential: credential, inputDescriptorId: "desc-2"),
        ]
        let unsignedResult = (vpTokenSigningPayload: ldpToken as Any?, unsignedVPTokens: [unsignedVPToken])

        let result = try builder.build(
            credentialInputDescriptorMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [VPTokenSigningResult(signedData: signature)],
            rootIndex: 0
        )

        XCTAssertEqual(result.vpTokens.count, 1)
        XCTAssertEqual(result.DescriptorMaps.count, 2)
        XCTAssertEqual(result.DescriptorMaps[0].id, "desc-1")
        XCTAssertEqual(result.DescriptorMaps[1].id, "desc-2")
        XCTAssertEqual(result.DescriptorMaps[0].format, .ldp_vp)
        XCTAssertEqual(result.DescriptorMaps[1].format, .ldp_vp)
    }

    func testBuildThrowsWhenPayloadIsNotLdpVPToken() {
        let mappings = [
            CredentialInputDescriptorMapping(format: .ldp_vc, credential: credential, inputDescriptorId: "desc-1")
        ]
        let unsignedResult = (vpTokenSigningPayload: "not-an-ldp-token" as Any?, unsignedVPTokens: [unsignedVPToken])

        XCTAssertThrowsError(try builder.build(
            credentialInputDescriptorMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [VPTokenSigningResult(signedData: Data("sig".utf8))],
            rootIndex: 0
        )) { error in
            assertOpenID4VPException(error, expectedMessage: "payload is not available as LdpVPToken", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    func testBuildThrowsWhenSigningResultIsMissing() {
        let ldpToken = makeLdpVPToken()
        let mappings = [
            CredentialInputDescriptorMapping(format: .ldp_vc, credential: credential, inputDescriptorId: "desc-1")
        ]
        let unsignedResult = (vpTokenSigningPayload: ldpToken as Any?, unsignedVPTokens: [unsignedVPToken])

        XCTAssertThrowsError(try builder.build(
            credentialInputDescriptorMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [],
            rootIndex: 0
        )) { error in
            assertOpenID4VPException(error, expectedMessage: "vpTokenSigningResult is missing", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    func testBuildThrowsWhenSignedDataIsEmpty() {
        let ldpToken = makeLdpVPToken()
        let mappings = [
            CredentialInputDescriptorMapping(format: .ldp_vc, credential: credential, inputDescriptorId: "desc-1")
        ]
        let unsignedResult = (vpTokenSigningPayload: ldpToken as Any?, unsignedVPTokens: [unsignedVPToken])

        XCTAssertThrowsError(try builder.build(
            credentialInputDescriptorMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [VPTokenSigningResult(signedData: Data())],
            rootIndex: 0
        )) { error in
            assertOpenID4VPException(error, expectedMessage: "Invalid Input: VPTokenSigningResult->signedData value cannot be empty or null", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    func testBuildThrowsWhenUnsignedVPTokenIsMissing() {
        let ldpToken = makeLdpVPToken()
        let mappings = [
            CredentialInputDescriptorMapping(format: .ldp_vc, credential: credential, inputDescriptorId: "desc-1")
        ]
        let unsignedResult = (vpTokenSigningPayload: ldpToken as Any?, unsignedVPTokens: [UnsignedVPToken]())

        XCTAssertThrowsError(try builder.build(
            credentialInputDescriptorMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [VPTokenSigningResult(signedData: Data("sig".utf8))],
            rootIndex: 0
        )) { error in
            assertOpenID4VPException(error, expectedMessage: "Missing data to sign", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    func testBuildThrowsWhenSignatureSuiteIsUnsupported() {
        let ldpToken = makeLdpVPToken(proofType: "UnsupportedSuite2099")
        let mappings = [
            CredentialInputDescriptorMapping(format: .ldp_vc, credential: credential, inputDescriptorId: "desc-1")
        ]
        let unsignedResult = (vpTokenSigningPayload: ldpToken as Any?, unsignedVPTokens: [unsignedVPToken])

        XCTAssertThrowsError(try builder.build(
            credentialInputDescriptorMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [VPTokenSigningResult(signedData: Data("sig".utf8))],
            rootIndex: 0
        )) { error in
            assertOpenID4VPException(error, expectedMessage: "Unsupported algorithm: UnsupportedSuite2099", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    // MARK: - build(credentialToCredentialQueryIdMappings:)

    func testDcqlBuildWithHolderBindingJsonWebSignature2020() throws {
        let dcqlBuilder = builderWithDcqlRequest(credentialQueryId: "q1", requireCryptographicHolderBinding: true)
        let signature = Data("mockSig".utf8)
        let ldpToken = makeLdpVPToken(proofType: SignatureSuite.jsonWebSignature2020.rawValue)
        var mapping = CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: credential, credentialQueryId: "q1")
        mapping.identifier = "some-uuid"
        let unsignedResult = (vpTokenSigningPayload: ["some-uuid": ldpToken] as [String: LdpVP] as Any?, unsignedVPTokens: [unsignedVPToken])

        let result = try dcqlBuilder.build(
            credentialToCredentialQueryIdMappings: [mapping],
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [VPTokenSigningResult(signedData: signature)]
        )

        XCTAssertEqual(result.keys.sorted(), ["q1"])
        XCTAssertEqual(result["q1"]?.count, 1)
        let token = try XCTUnwrap(result["q1"]?.first as? LdpVPToken)
        let expectedJws = "eyJhbGciOiJFZERTQSIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9..\(signature.toBase64UrlEncoded())"
        XCTAssertEqual(token.proof?.jws, expectedJws)
    }

    func testDcqlBuildWithoutHolderBinding() throws {
        let dcqlBuilder = builderWithDcqlRequest(credentialQueryId: "q1", requireCryptographicHolderBinding: false)
        var mapping = CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: credential, credentialQueryId: "q1")
        mapping.identifier = "some-uuid"
        let unsignedResult = (vpTokenSigningPayload: ["some-uuid": LdpVP.vc(LdpVCToken(verifiableCredential: credential))] as [String: LdpVP] as Any?, unsignedVPTokens: [UnsignedVPToken]())
        
        let result = try dcqlBuilder.build(
            credentialToCredentialQueryIdMappings: [mapping],
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: []
        )
        
        XCTAssertEqual(result.keys.sorted(), ["q1"])
        XCTAssertEqual(result["q1"]?.count, 1)
        let token = try XCTUnwrap(result["q1"]?.first as? LdpVP)
        guard case .vc(let presentation) = token else {
            XCTFail("Expected VC here")
            return
        }
        let credentialDict = try XCTUnwrap(presentation.verifiableCredential.value as? [String: Any])
        XCTAssertEqual(credentialDict["type"] as? [String], ["VerifiableCredential"])
    }

    func testDcqlBuildMultipleCredentialsDifferentQueryIds() throws {
        let dcqlBuilder = builderWithDcqlRequest(credentials: [("q1", true), ("q2", false)])
        let signature = Data("mockSig".utf8)
        let ldpToken1 = makeLdpVPToken(proofType: SignatureSuite.jsonWebSignature2020.rawValue)

        var mapping1 = CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: credential, credentialQueryId: "q1")
        mapping1.identifier = "uuid-1"
        var mapping2 = CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: credential, credentialQueryId: "q2")
        mapping2.identifier = "uuid-2"

        let payload: [String: LdpVP] = [
            "uuid-1": ldpToken1,
            "uuid-2": .vc(LdpVCToken(verifiableCredential: credential))
        ]
        let unsignedResult = (vpTokenSigningPayload: payload as Any?, unsignedVPTokens: [unsignedVPToken])

        let result = try dcqlBuilder.build(
            credentialToCredentialQueryIdMappings: [mapping1, mapping2],
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [VPTokenSigningResult(signedData: signature)]
        )

        XCTAssertEqual(result.keys.sorted(), ["q1", "q2"])
        XCTAssertEqual(result["q1"]?.count, 1)
        XCTAssertEqual(result["q2"]?.count, 1)

        let token1 = try XCTUnwrap(result["q1"]?.first as? LdpVPToken)
        XCTAssertNotNil(token1.proof?.jws)

        let tokenData = try XCTUnwrap(result["q2"]?.first as? LdpVP)
        guard case .vc(_) = tokenData else {
            XCTFail("Expected LdpVCToken for no-binding query")
            return
        }
    }

    func testDcqlBuildMultipleCredentialsSameQueryId() throws {
        let dcqlBuilder = builderWithDcqlRequest(credentialQueryId: "q1", requireCryptographicHolderBinding: true)
        let signature = Data("mockSig".utf8)
        let ldpToken1 = makeLdpVPToken(proofType: SignatureSuite.jsonWebSignature2020.rawValue)
        let ldpToken2 = makeLdpVPToken(proofType: SignatureSuite.jsonWebSignature2020.rawValue)

        var mapping1 = CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: credential, credentialQueryId: "q1")
        mapping1.identifier = "uuid-1"
        var mapping2 = CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: credential, credentialQueryId: "q1")
        mapping2.identifier = "uuid-2"

        let payload = ["uuid-1": ldpToken1, "uuid-2": ldpToken2] as [String: LdpVP]
        let unsignedResult = (vpTokenSigningPayload: payload as Any?, unsignedVPTokens: [unsignedVPToken, unsignedVPToken])

        let result = try dcqlBuilder.build(
            credentialToCredentialQueryIdMappings: [mapping1, mapping2],
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [VPTokenSigningResult(signedData: signature), VPTokenSigningResult(signedData: signature)]
        )

        XCTAssertEqual(result.keys.sorted(), ["q1"])
        XCTAssertEqual(result["q1"]?.count, 2)
        XCTAssertTrue(result["q1"]?.first is LdpVPToken)
        XCTAssertTrue(result["q1"]?.last is LdpVPToken)
    }

    func testDcqlBuildThrowsWhenPayloadIsNotLdpVPTokenDictionary() {
        let dcqlBuilder = builderWithDcqlRequest(credentialQueryId: "q1", requireCryptographicHolderBinding: false)
        var mapping = CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: credential, credentialQueryId: "q1")
        mapping.identifier = "some-uuid"
        let unsignedResult = (vpTokenSigningPayload: "invalid" as Any?, unsignedVPTokens: [unsignedVPToken])

        XCTAssertThrowsError(try dcqlBuilder.build(
            credentialToCredentialQueryIdMappings: [mapping],
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: []
        )) { error in
            assertOpenID4VPException(error, expectedMessage: "Missing uuidToUnsignedKBT in payload", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    func testDcqlBuildThrowsWhenCredentialQueryIdNotFoundInDcqlQuery() {
        let dcqlBuilder = builderWithDcqlRequest(credentialQueryId: "q1", requireCryptographicHolderBinding: false)
        var mapping = CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: credential, credentialQueryId: "nonexistent")
        mapping.identifier = "some-uuid"
        let unsignedResult = (vpTokenSigningPayload: ["some-uuid": LdpVP.vc(LdpVCToken(verifiableCredential: credential))] as [String: LdpVP] as Any?, unsignedVPTokens: [UnsignedVPToken]())

        XCTAssertThrowsError(try dcqlBuilder.build(
            credentialToCredentialQueryIdMappings: [mapping],
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: []
        )) { error in
            assertOpenID4VPException(error, expectedMessage: "No matching credential query found for credentialQueryId: nonexistent", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    func testDcqlBuildThrowsWhenPayloadMissingForIdentifier() {
        let dcqlBuilder = builderWithDcqlRequest(credentialQueryId: "q1", requireCryptographicHolderBinding: true)
        let signature = Data("mockSig".utf8)
        var mapping = CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: credential, credentialQueryId: "q1")
        mapping.identifier = "uuid-missing"
        let unsignedResult = (vpTokenSigningPayload: [String: LdpVP]() as Any?, unsignedVPTokens: [unsignedVPToken])

        XCTAssertThrowsError(try dcqlBuilder.build(
            credentialToCredentialQueryIdMappings: [mapping],
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [VPTokenSigningResult(signedData: signature)]
        )) { error in
            assertOpenID4VPException(error, expectedMessage: "payload is not available as LdpVPToken", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    func testDcqlBuildThrowsWhenSigningResultMissing() {
        let dcqlBuilder = builderWithDcqlRequest(credentialQueryId: "q1", requireCryptographicHolderBinding: true)
        let ldpToken = makeLdpVPToken()
        var mapping = CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: credential, credentialQueryId: "q1")
        mapping.identifier = "some-uuid"
        let unsignedResult = (vpTokenSigningPayload: ["some-uuid": ldpToken] as [String: LdpVP] as Any?, unsignedVPTokens: [unsignedVPToken])

        XCTAssertThrowsError(try dcqlBuilder.build(
            credentialToCredentialQueryIdMappings: [mapping],
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: []
        )) { error in
            assertOpenID4VPException(error, expectedMessage: "vpTokenSigningResult is missing", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    func testDcqlBuildThrowsWhenSignedDataIsEmpty() {
        let dcqlBuilder = builderWithDcqlRequest(credentialQueryId: "q1", requireCryptographicHolderBinding: true)
        let ldpToken = makeLdpVPToken()
        var mapping = CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: credential, credentialQueryId: "q1")
        mapping.identifier = "some-uuid"
        let unsignedResult = (vpTokenSigningPayload: ["some-uuid": ldpToken] as [String: LdpVP] as Any?, unsignedVPTokens: [unsignedVPToken])

        XCTAssertThrowsError(try dcqlBuilder.build(
            credentialToCredentialQueryIdMappings: [mapping],
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [VPTokenSigningResult(signedData: Data())]
        )) { error in
            assertOpenID4VPException(error, expectedMessage: "Invalid Input: VPTokenSigningResult->signedData value cannot be empty or null", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    func testDcqlBuildThrowsWhenUnsignedVPTokenMissing() {
        let dcqlBuilder = builderWithDcqlRequest(credentialQueryId: "q1", requireCryptographicHolderBinding: true)
        let ldpToken = makeLdpVPToken()
        var mapping = CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: credential, credentialQueryId: "q1")
        mapping.identifier = "some-uuid"
        let unsignedResult = (vpTokenSigningPayload: ["some-uuid": ldpToken] as [String: LdpVP] as Any?, unsignedVPTokens: [UnsignedVPToken]())

        XCTAssertThrowsError(try dcqlBuilder.build(
            credentialToCredentialQueryIdMappings: [mapping],
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [VPTokenSigningResult(signedData: Data("sig".utf8))]
        )) { error in
            assertOpenID4VPException(error, expectedMessage: "Missing data to sign", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    func testDcqlBuildThrowsWhenSignatureSuiteIsUnsupported() {
        let dcqlBuilder = builderWithDcqlRequest(credentialQueryId: "q1", requireCryptographicHolderBinding: true)
        let ldpToken = makeLdpVPToken(proofType: "UnsupportedSuite2099")
        var mapping = CredentialToCredentialQueryIdMapping(format: .ldp_vc, credential: credential, credentialQueryId: "q1")
        mapping.identifier = "some-uuid"
        let unsignedResult = (vpTokenSigningPayload: ["some-uuid": ldpToken] as [String: LdpVP] as Any?, unsignedVPTokens: [unsignedVPToken])

        XCTAssertThrowsError(try dcqlBuilder.build(
            credentialToCredentialQueryIdMappings: [mapping],
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [VPTokenSigningResult(signedData: Data("sig".utf8))]
        )) { error in
            assertOpenID4VPException(error, expectedMessage: "Unsupported algorithm: UnsupportedSuite2099", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    // MARK: - Helpers

    private func builderWithDcqlRequest(credentialQueryId: String, requireCryptographicHolderBinding: Bool) -> LdpVPTokenBuilder {
        builderWithDcqlRequest(credentials: [(credentialQueryId, requireCryptographicHolderBinding)])
    }

    private func builderWithDcqlRequest(credentials: [(id: String, requireCryptographicHolderBinding: Bool)]) -> LdpVPTokenBuilder {
        let dcqlJson: [String: Any] = [
            "credentials": credentials.map { cred in
                [
                    "id": cred.id,
                    "format": "ldp_vc",
                    "meta": [:] as [String: Any],
                    "require_cryptographic_holder_binding": cred.requireCryptographicHolderBinding
                ] as [String: Any]
            }
        ]
        let dcqlQuery = createInstance(dcqlJson, as: DCQLQuery.self)
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
        return LdpVPTokenBuilder(authorizationRequest: authorizationRequest)
    }
}
