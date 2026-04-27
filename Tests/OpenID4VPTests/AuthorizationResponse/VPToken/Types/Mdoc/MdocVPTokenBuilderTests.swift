import XCTest
@testable import OpenID4VP

final class MdocVPTokenBuilderTests: XCTestCase {

    let builder = MdocVPTokenBuilder(authorizationRequest: getMockAuthorizationRequest())
    let docType = "org.iso.18013.5.1.mDL"
    let deviceAuthBytes = "d818587e847444657669636541757468656e7469636174696f6e"

    func testBuildSuccess() throws {
        let signature = Data("mock-signature".utf8).base64EncodedString()
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
        XCTAssertTrue(result.vpTokens.first is MdocVPToken)
        XCTAssertEqual(result.DescriptorMaps.count, 1)
        XCTAssertEqual(result.DescriptorMaps.first?.id, "id-1")
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
        let signature = Data("mock-signature".utf8).base64EncodedString()
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
}
