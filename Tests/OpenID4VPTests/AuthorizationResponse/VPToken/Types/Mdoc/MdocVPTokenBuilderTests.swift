import XCTest
@testable import OpenID4VP

final class MdocVPTokenBuilderTests: XCTestCase {

    let builder = MdocVPTokenBuilder(authorizationRequest: getMockAuthorizationRequest())
    let docType = "org.iso.18013.5.1.mDL"
    let deviceAuthBytes = "d818587e847444657669636541757468656e7469636174696f6e"

    // MARK: - build(credentialInputDescriptorMappings:)

    func testBuildSuccess() throws {
        let signature = Data("mock-signature".utf8)
        let mappings = [
            CredentialInputDescriptorMapping(format: .mso_mdoc, credential: AnyCodable(sampleMdoc), inputDescriptorId: "id-1", identifier: docType)
        ]
        let unsignedResult: (vpTokenSigningPayload: Any?, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: [docType: deviceAuthBytes] as [String: String],
            unsignedVPTokens: []
        )
        let signingResults = [VPTokenSigningResult(signedData: signature)]

        let result = try builder.build(
            credentialInputDescriptorMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: signingResults,
            rootIndex: 0
        )

        XCTAssertEqual(result.vpTokens.count, 1)
        let mdocToken = try XCTUnwrap(result.vpTokens.first as? MdocVPToken)
        XCTAssertFalse(mdocToken.base64EncodedDeviceResponse.isEmpty)
        XCTAssertEqual(result.DescriptorMaps.count, 1)
        XCTAssertEqual(result.DescriptorMaps[0].id, "id-1")
        XCTAssertEqual(result.DescriptorMaps[0].format, .mso_mdoc)
        XCTAssertEqual(result.DescriptorMaps[0].path, "$[0]")
        XCTAssertEqual(result.nextIndex, 1)
    }

    func testBuildThrowsWhenPayloadMissing() {
        let mappings = [
            CredentialInputDescriptorMapping(format: .mso_mdoc, credential: AnyCodable(sampleMdoc), inputDescriptorId: "id-1", identifier: docType)
        ]
        let unsignedResult: (vpTokenSigningPayload: Any?, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: nil,
            unsignedVPTokens: []
        )

        XCTAssertThrowsError(try builder.build(
            credentialInputDescriptorMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [],
            rootIndex: 0
        )) { error in
            assertOpenID4VPException(error, expectedMessage: "Missing docTypeToDeviceAuthenticationBytes in payload", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    func testBuildThrowsWhenSigningResultMissing() {
        let mappings = [
            CredentialInputDescriptorMapping(format: .mso_mdoc, credential: AnyCodable(sampleMdoc), inputDescriptorId: "id-1", identifier: docType)
        ]
        let unsignedResult: (vpTokenSigningPayload: Any?, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: [docType: deviceAuthBytes] as [String: String],
            unsignedVPTokens: []
        )

        XCTAssertThrowsError(try builder.build(
            credentialInputDescriptorMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [],
            rootIndex: 0
        )) { error in
            assertOpenID4VPException(error, expectedMessage: "Missing signing result for \(docType)", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    func testBuildThrowsWhenExtraSigningResults() {
        let signature = Data("mock-signature".utf8)
        let mappings = [
            CredentialInputDescriptorMapping(format: .mso_mdoc, credential: AnyCodable(sampleMdoc), inputDescriptorId: "id-1", identifier: docType)
        ]
        let unsignedResult: (vpTokenSigningPayload: Any?, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: [docType: deviceAuthBytes] as [String: String],
            unsignedVPTokens: []
        )
        let signingResults = [
            VPTokenSigningResult(signedData: signature),
            VPTokenSigningResult(signedData: signature)
        ]

        XCTAssertThrowsError(try builder.build(
            credentialInputDescriptorMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: signingResults,
            rootIndex: 0
        )) { error in
            assertOpenID4VPException(error, expectedMessage: "Extra signing results provided for mso_mdoc", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    // MARK: - build(credentialToCredentialQueryIdMappings:)

    func testDcqlBuildSuccess() throws {
        let signature = Data("mock-signature".utf8)
        var mapping = CredentialToCredentialQueryIdMapping(format: .mso_mdoc, credential: AnyCodable(sampleMdoc), credentialQueryId: "q1")
        mapping.identifier = docType
        let mappings = [mapping]
        let unsignedResult: (vpTokenSigningPayload: Any?, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: [docType: deviceAuthBytes] as [String: String],
            unsignedVPTokens: []
        )

        let result = try builder.build(
            credentialToCredentialQueryIdMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [VPTokenSigningResult(signedData: signature)]
        )

        XCTAssertEqual(result.keys.sorted(), ["q1"])
        XCTAssertEqual(result["q1"]?.count, 1)
        let mdocToken = try XCTUnwrap(result["q1"]?.first as? MdocVPToken)
        XCTAssertFalse(mdocToken.base64EncodedDeviceResponse.isEmpty)
    }

    func testDcqlBuildMultipleCredentialsDifferentQueryIds() throws {
        let docType1 = "org.iso.18013.5.1.mDL"
        let docType2 = "org.iso.18013.5.1.mDL2"
        let sig1 = Data("sig1".utf8)
        let sig2 = Data("sig2".utf8)

        var mapping1 = CredentialToCredentialQueryIdMapping(format: .mso_mdoc, credential: AnyCodable(sampleMdoc), credentialQueryId: "q1")
        mapping1.identifier = docType1
        var mapping2 = CredentialToCredentialQueryIdMapping(format: .mso_mdoc, credential: AnyCodable(sampleMdoc), credentialQueryId: "q2")
        mapping2.identifier = docType2
        let mappings = [mapping1, mapping2]
        let unsignedResult: (vpTokenSigningPayload: Any?, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: [docType1: deviceAuthBytes, docType2: deviceAuthBytes] as [String: String],
            unsignedVPTokens: []
        )

        let result = try builder.build(
            credentialToCredentialQueryIdMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [VPTokenSigningResult(signedData: sig1), VPTokenSigningResult(signedData: sig2)]
        )

        XCTAssertEqual(result.keys.sorted(), ["q1", "q2"])
        XCTAssertEqual(result["q1"]?.count, 1)
        XCTAssertEqual(result["q2"]?.count, 1)
        XCTAssertNotNil(result["q1"]?.first as? MdocVPToken)
        XCTAssertNotNil(result["q2"]?.first as? MdocVPToken)
    }

    func testDcqlBuildMultipleCredentialsSameQueryId() throws {
        let docType1 = "org.iso.18013.5.1.mDL"
        let docType2 = "org.iso.18013.5.1.mDL2"
        let sig1 = Data("sig1".utf8)
        let sig2 = Data("sig2".utf8)

        var mapping1 = CredentialToCredentialQueryIdMapping(format: .mso_mdoc, credential: AnyCodable(sampleMdoc), credentialQueryId: "q1")
        mapping1.identifier = docType1
        var mapping2 = CredentialToCredentialQueryIdMapping(format: .mso_mdoc, credential: AnyCodable(sampleMdoc), credentialQueryId: "q1")
        mapping2.identifier = docType2
        let mappings = [mapping1, mapping2]
        let unsignedResult: (vpTokenSigningPayload: Any?, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: [docType1: deviceAuthBytes, docType2: deviceAuthBytes] as [String: String],
            unsignedVPTokens: []
        )

        let result = try builder.build(
            credentialToCredentialQueryIdMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [VPTokenSigningResult(signedData: sig1), VPTokenSigningResult(signedData: sig2)]
        )

        XCTAssertEqual(result.keys.sorted(), ["q1"])
        XCTAssertEqual(result["q1"]?.count, 1)
        XCTAssertNotNil(result["q1"]?.first as? MdocVPToken)
    }

    func testDcqlBuildThrowsWhenPayloadMissing() {
        var mapping = CredentialToCredentialQueryIdMapping(format: .mso_mdoc, credential: AnyCodable(sampleMdoc), credentialQueryId: "q1")
        mapping.identifier = docType
        let unsignedResult: (vpTokenSigningPayload: Any?, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: nil,
            unsignedVPTokens: []
        )

        XCTAssertThrowsError(try builder.build(
            credentialToCredentialQueryIdMappings: [mapping],
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: []
        )) { error in
            assertOpenID4VPException(error, expectedMessage: "Missing docTypeToDeviceAuthenticationBytes in payload", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    func testDcqlBuildThrowsWhenSigningResultMissing() {
        var mapping = CredentialToCredentialQueryIdMapping(format: .mso_mdoc, credential: AnyCodable(sampleMdoc), credentialQueryId: "q1")
        mapping.identifier = docType
        let unsignedResult: (vpTokenSigningPayload: Any?, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: [docType: deviceAuthBytes] as [String: String],
            unsignedVPTokens: []
        )

        XCTAssertThrowsError(try builder.build(
            credentialToCredentialQueryIdMappings: [mapping],
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: []
        )) { error in
            assertOpenID4VPException(error, expectedMessage: "Missing signing result for \(docType)", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    func testDcqlBuildThrowsWhenMappingMissingForDocType() {
        let unsignedResult: (vpTokenSigningPayload: Any?, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: [docType: deviceAuthBytes] as [String: String],
            unsignedVPTokens: []
        )

        XCTAssertThrowsError(try builder.build(
            credentialToCredentialQueryIdMappings: [],
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [VPTokenSigningResult(signedData: Data("sig".utf8))]
        )) { error in
            assertOpenID4VPException(error, expectedMessage: "Missing mapping for \(docType)", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    func testDcqlBuildThrowsWhenCredentialIsNotString() {
        var mapping = CredentialToCredentialQueryIdMapping(format: .mso_mdoc, credential: AnyCodable(12345), credentialQueryId: "q1")
        mapping.identifier = docType
        let unsignedResult: (vpTokenSigningPayload: Any?, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: [docType: deviceAuthBytes] as [String: String],
            unsignedVPTokens: []
        )

        XCTAssertThrowsError(try builder.build(
            credentialToCredentialQueryIdMappings: [mapping],
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [VPTokenSigningResult(signedData: Data("sig".utf8))]
        )) { error in
            assertOpenID4VPException(error, expectedMessage: "Invalid MSO-MDOC token: expected String", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    func testDcqlBuildThrowsWhenCredentialIsInvalidCBOR() {
        var mapping = CredentialToCredentialQueryIdMapping(format: .mso_mdoc, credential: AnyCodable("invalidCBOR"), credentialQueryId: "q1")
        mapping.identifier = docType
        let unsignedResult: (vpTokenSigningPayload: Any?, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: [docType: deviceAuthBytes] as [String: String],
            unsignedVPTokens: []
        )

        XCTAssertThrowsError(try builder.build(
            credentialToCredentialQueryIdMappings: [mapping],
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [VPTokenSigningResult(signedData: Data("sig".utf8))]
        )) { error in
            assertOpenID4VPException(error, expectedMessage: "Invalid Verifiable Credential: Error while decoding credential", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    func testDcqlBuildThrowsWhenExtraSigningResults() {
        var mapping = CredentialToCredentialQueryIdMapping(format: .mso_mdoc, credential: AnyCodable(sampleMdoc), credentialQueryId: "q1")
        mapping.identifier = docType
        let signature = Data("mock-signature".utf8)
        let unsignedResult: (vpTokenSigningPayload: Any?, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: [docType: deviceAuthBytes] as [String: String],
            unsignedVPTokens: []
        )

        XCTAssertThrowsError(try builder.build(
            credentialToCredentialQueryIdMappings: [mapping],
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [VPTokenSigningResult(signedData: signature), VPTokenSigningResult(signedData: signature)]
        )) { error in
            assertOpenID4VPException(error, expectedMessage: "Extra signing results provided for mso_mdoc", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    func testDcqlBuildEmptyMappingsReturnsEmptyResult() throws {
        let unsignedResult: (vpTokenSigningPayload: Any?, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: [String: String]() as [String: String],
            unsignedVPTokens: []
        )

        let result = try builder.build(
            credentialToCredentialQueryIdMappings: [],
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: []
        )

        XCTAssertEqual(result.count, 0)
    }
}
