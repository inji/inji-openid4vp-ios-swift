import Foundation
import XCTest
@testable import OpenID4VP

final class SdJwtVPTokenBuilderTests: XCTestCase {
    let builder = SdJwtVPTokenBuilder()

    let credentialWithBinding = sampeVcSdJwtWithHolderBinding
    let credentialWithoutBinding = sampleVcSdJwtWithNoHolderBinding

    // MARK: - Single credential with holder binding

    func testBuildWithHolderBinding() throws {
        let uuid = "uuid-with-binding"
        let unsignedKBJwt = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImtiK2p3dCJ9.eyJpYXQiOjE3NTc0NzcxNjQsIm5vbmNlIjoibm9uY2UifQ"
        let signature = "kbSignature"

        let mappings = [
            CredentialInputDescriptorMapping(
                format: .vc_sd_jwt,
                credential: AnyCodable(credentialWithBinding),
                inputDescriptorId: "id1",
                identifier: uuid
            )
        ]
        let unsignedResult: (vpTokenSigningPayload: Any?, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: [uuid: unsignedKBJwt] as [String: String],
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
        let vpToken = result.vpTokens[0] as! SdJwtVPToken
        XCTAssertTrue(vpToken.value.hasSuffix("\(unsignedKBJwt).\(signature)"))
        XCTAssertTrue(vpToken.value.hasPrefix(credentialWithBinding))
        XCTAssertEqual(result.DescriptorMaps.count, 1)
        XCTAssertEqual(result.DescriptorMaps[0].id, "id1")
        XCTAssertEqual(result.DescriptorMaps[0].format, .vc_sd_jwt)
        XCTAssertEqual(result.DescriptorMaps[0].path, "$[0]")
        XCTAssertEqual(result.nextIndex, 1)
    }

    // MARK: - Single credential without holder binding

    func testBuildWithoutHolderBinding() throws {
        let uuid = "uuid-no-binding"

        let mappings = [
            CredentialInputDescriptorMapping(
                format: .vc_sd_jwt,
                credential: AnyCodable(credentialWithoutBinding),
                inputDescriptorId: "id1",
                identifier: uuid
            )
        ]
        let unsignedResult: (vpTokenSigningPayload: Any?, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: [String: String](),
            unsignedVPTokens: []
        )

        let result = try builder.build(
            credentialInputDescriptorMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [],
            rootIndex: 0
        )

        XCTAssertEqual(result.vpTokens.count, 1)
        let vpToken = result.vpTokens[0] as! SdJwtVPToken
        XCTAssertEqual(vpToken.value, credentialWithoutBinding)
        XCTAssertEqual(result.DescriptorMaps.count, 1)
        XCTAssertEqual(result.DescriptorMaps[0].id, "id1")
        XCTAssertEqual(result.DescriptorMaps[0].format, .vc_sd_jwt)
        XCTAssertEqual(result.DescriptorMaps[0].path, "$[0]")
        XCTAssertEqual(result.nextIndex, 1)
    }

    // MARK: - Mixed: credentials with and without holder binding

    func testBuildWithMixOfHolderBindingAndNoHolderBinding() throws {
        let uuidWithBinding = "uuid-with-binding"
        let uuidNoBinding = "uuid-no-binding"
        let unsignedKBJwt = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImtiK2p3dCJ9.eyJpYXQiOjE3NTc0NzcxNjQsIm5vbmNlIjoibm9uY2UifQ"
        let signature = "kbSignature"

        let mappings = [
            CredentialInputDescriptorMapping(
                format: .vc_sd_jwt,
                credential: AnyCodable(credentialWithBinding),
                inputDescriptorId: "id_with_binding",
                identifier: uuidWithBinding
            ),
            CredentialInputDescriptorMapping(
                format: .vc_sd_jwt,
                credential: AnyCodable(credentialWithoutBinding),
                inputDescriptorId: "id_no_binding",
                identifier: uuidNoBinding
            )
        ]
        let unsignedResult: (vpTokenSigningPayload: Any?, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: [uuidWithBinding: unsignedKBJwt] as [String: String],
            unsignedVPTokens: []
        )
        let signingResults = [VPTokenSigningResult(signedData: signature)]

        let result = try builder.build(
            credentialInputDescriptorMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: signingResults,
            rootIndex: 0
        )

        XCTAssertEqual(result.vpTokens.count, 2)

        let boundToken = result.vpTokens[0] as! SdJwtVPToken
        XCTAssertTrue(boundToken.value.hasSuffix("\(unsignedKBJwt).\(signature)"))
        XCTAssertTrue(boundToken.value.hasPrefix(credentialWithBinding))

        let unboundToken = result.vpTokens[1] as! SdJwtVPToken
        XCTAssertEqual(unboundToken.value, credentialWithoutBinding)

        XCTAssertEqual(result.DescriptorMaps[0].id, "id_with_binding")
        XCTAssertEqual(result.DescriptorMaps[0].path, "$[0]")
        XCTAssertEqual(result.DescriptorMaps[1].id, "id_no_binding")
        XCTAssertEqual(result.DescriptorMaps[1].path, "$[1]")
        XCTAssertEqual(result.nextIndex, 2)
    }

    func testBuildWithMixNoBindingFirst() throws {
        let uuidWithBinding = "uuid-with-binding"
        let uuidNoBinding = "uuid-no-binding"
        let unsignedKBJwt = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImtiK2p3dCJ9.eyJpYXQiOjE3NTc0NzcxNjQsIm5vbmNlIjoibm9uY2UifQ"
        let signature = "kbSignature"

        let mappings = [
            CredentialInputDescriptorMapping(
                format: .vc_sd_jwt,
                credential: AnyCodable(credentialWithoutBinding),
                inputDescriptorId: "id_no_binding",
                identifier: uuidNoBinding
            ),
            CredentialInputDescriptorMapping(
                format: .vc_sd_jwt,
                credential: AnyCodable(credentialWithBinding),
                inputDescriptorId: "id_with_binding",
                identifier: uuidWithBinding
            )
        ]
        let unsignedResult: (vpTokenSigningPayload: Any?, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: [uuidWithBinding: unsignedKBJwt] as [String: String],
            unsignedVPTokens: []
        )
        let signingResults = [VPTokenSigningResult(signedData: signature)]

        let result = try builder.build(
            credentialInputDescriptorMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: signingResults,
            rootIndex: 0
        )

        XCTAssertEqual(result.vpTokens.count, 2)

        let unboundToken = result.vpTokens[0] as! SdJwtVPToken
        XCTAssertEqual(unboundToken.value, credentialWithoutBinding)

        let boundToken = result.vpTokens[1] as! SdJwtVPToken
        XCTAssertTrue(boundToken.value.hasSuffix("\(unsignedKBJwt).\(signature)"))

        XCTAssertEqual(result.DescriptorMaps[0].id, "id_no_binding")
        XCTAssertEqual(result.DescriptorMaps[0].path, "$[0]")
        XCTAssertEqual(result.DescriptorMaps[1].id, "id_with_binding")
        XCTAssertEqual(result.DescriptorMaps[1].path, "$[1]")
        XCTAssertEqual(result.nextIndex, 2)
    }

    // MARK: - Multiple credentials all with holder binding

    func testBuildMultipleCredentialsAllWithHolderBinding() throws {
        let uuid1 = "uuid-1"
        let uuid2 = "uuid-2"
        let unsignedKBJwt1 = "eyJhbGciOiJFUzI1NiJ9.payload1"
        let unsignedKBJwt2 = "eyJhbGciOiJFUzI1NiJ9.payload2"
        let sig1 = "sig1"
        let sig2 = "sig2"

        let mappings = [
            CredentialInputDescriptorMapping(
                format: .vc_sd_jwt,
                credential: AnyCodable(credentialWithBinding),
                inputDescriptorId: "id1",
                identifier: uuid1
            ),
            CredentialInputDescriptorMapping(
                format: .dc_sd_jwt,
                credential: AnyCodable(credentialWithBinding),
                inputDescriptorId: "id2",
                identifier: uuid2
            )
        ]
        let unsignedResult: (vpTokenSigningPayload: Any?, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: [uuid1: unsignedKBJwt1, uuid2: unsignedKBJwt2] as [String: String],
            unsignedVPTokens: []
        )
        let signingResults = [
            VPTokenSigningResult(signedData: sig1),
            VPTokenSigningResult(signedData: sig2)
        ]

        let result = try builder.build(
            credentialInputDescriptorMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: signingResults,
            rootIndex: 0
        )

        XCTAssertEqual(result.vpTokens.count, 2)
        let token1 = result.vpTokens[0] as! SdJwtVPToken
        XCTAssertTrue(token1.value.hasSuffix("\(unsignedKBJwt1).\(sig1)"))
        let token2 = result.vpTokens[1] as! SdJwtVPToken
        XCTAssertTrue(token2.value.hasSuffix("\(unsignedKBJwt2).\(sig2)"))
        XCTAssertEqual(result.DescriptorMaps[0].format, .vc_sd_jwt)
        XCTAssertEqual(result.DescriptorMaps[1].format, .dc_sd_jwt)
        XCTAssertEqual(result.nextIndex, 2)
    }

    // MARK: - Multiple credentials all without holder binding

    func testBuildMultipleCredentialsAllWithoutHolderBinding() throws {
        let mappings = [
            CredentialInputDescriptorMapping(
                format: .vc_sd_jwt,
                credential: AnyCodable(credentialWithoutBinding),
                inputDescriptorId: "id1",
                identifier: "uuid-1"
            ),
            CredentialInputDescriptorMapping(
                format: .dc_sd_jwt,
                credential: AnyCodable(credentialWithoutBinding),
                inputDescriptorId: "id2",
                identifier: "uuid-2"
            )
        ]
        let unsignedResult: (vpTokenSigningPayload: Any?, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: [String: String](),
            unsignedVPTokens: []
        )

        let result = try builder.build(
            credentialInputDescriptorMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [],
            rootIndex: 0
        )

        XCTAssertEqual(result.vpTokens.count, 2)
        let token1 = result.vpTokens[0] as! SdJwtVPToken
        XCTAssertEqual(token1.value, credentialWithoutBinding)
        let token2 = result.vpTokens[1] as! SdJwtVPToken
        XCTAssertEqual(token2.value, credentialWithoutBinding)
        XCTAssertEqual(result.nextIndex, 2)
    }

    // MARK: - rootIndex offset

    func testBuildRespectsRootIndexOffset() throws {
        let mappings = [
            CredentialInputDescriptorMapping(
                format: .vc_sd_jwt,
                credential: AnyCodable(credentialWithoutBinding),
                inputDescriptorId: "id1",
                identifier: "uuid-1"
            )
        ]
        let unsignedResult: (vpTokenSigningPayload: Any?, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: [String: String](),
            unsignedVPTokens: []
        )

        let result = try builder.build(
            credentialInputDescriptorMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [],
            rootIndex: 5
        )

        XCTAssertEqual(result.DescriptorMaps[0].path, "$[5]")
        XCTAssertEqual(result.nextIndex, 6)
    }

    // MARK: - dc+sd-jwt format mapping

    func testBuildMapsDcSdJwtFormat() throws {
        let mappings = [
            CredentialInputDescriptorMapping(
                format: .dc_sd_jwt,
                credential: AnyCodable(credentialWithoutBinding),
                inputDescriptorId: "id1",
                identifier: "uuid-1"
            )
        ]
        let unsignedResult: (vpTokenSigningPayload: Any?, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: [String: String](),
            unsignedVPTokens: []
        )

        let result = try builder.build(
            credentialInputDescriptorMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [],
            rootIndex: 0
        )

        XCTAssertEqual(result.DescriptorMaps[0].format, .dc_sd_jwt)
    }

    // MARK: - Error: missing identifier

    func testBuildThrowsWhenIdentifierIsMissing() {
        let mappings = [
            CredentialInputDescriptorMapping(
                format: .vc_sd_jwt,
                credential: AnyCodable(credentialWithBinding),
                inputDescriptorId: "id1",
                identifier: nil
            )
        ]
        let unsignedResult: (vpTokenSigningPayload: Any?, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: [String: String](),
            unsignedVPTokens: []
        )

        XCTAssertThrowsError(try builder.build(
            credentialInputDescriptorMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [],
            rootIndex: 0
        )) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "identifier is null in CredentialInputDescriptorMapping for SD-JWT",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    // MARK: - Error: invalid payload type

    func testBuildThrowsWhenPayloadIsNotStringDictionary() {
        let mappings = [
            CredentialInputDescriptorMapping(
                format: .vc_sd_jwt,
                credential: AnyCodable(credentialWithBinding),
                inputDescriptorId: "id1",
                identifier: "uuid-1"
            )
        ]
        let unsignedResult: (vpTokenSigningPayload: Any?, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: "invalid-payload",
            unsignedVPTokens: []
        )

        XCTAssertThrowsError(try builder.build(
            credentialInputDescriptorMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [],
            rootIndex: 0
        )) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Missing uuidToUnsignedKBT in payload",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    // MARK: - Error: credential is not a string

    func testBuildThrowsWhenCredentialIsNotString() {
        let mappings = [
            CredentialInputDescriptorMapping(
                format: .vc_sd_jwt,
                credential: AnyCodable(12345),
                inputDescriptorId: "id1",
                identifier: "uuid-1"
            )
        ]
        let unsignedResult: (vpTokenSigningPayload: Any?, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: [String: String](),
            unsignedVPTokens: []
        )

        XCTAssertThrowsError(try builder.build(
            credentialInputDescriptorMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [],
            rootIndex: 0
        )) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "SD-JWT credential is not a String",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    // MARK: - Error: extra signing results

    func testBuildThrowsWhenExtraSigningResultsProvided() {
        let mappings = [
            CredentialInputDescriptorMapping(
                format: .vc_sd_jwt,
                credential: AnyCodable(credentialWithoutBinding),
                inputDescriptorId: "id1",
                identifier: "uuid-1"
            )
        ]
        let unsignedResult: (vpTokenSigningPayload: Any?, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: [String: String](),
            unsignedVPTokens: []
        )

        XCTAssertThrowsError(try builder.build(
            credentialInputDescriptorMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [VPTokenSigningResult(signedData: "unexpected")],
            rootIndex: 0
        )) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Extra signing results provided for SD-JWT",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    // MARK: - Error: missing signing result for bound credential

    func testBuildThrowsWhenSigningResultMissingForBoundCredential() {
        let uuid = "uuid-with-binding"
        let unsignedKBJwt = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImtiK2p3dCJ9.eyJpYXQiOjE3NTc0NzcxNjR9"

        let mappings = [
            CredentialInputDescriptorMapping(
                format: .vc_sd_jwt,
                credential: AnyCodable(credentialWithBinding),
                inputDescriptorId: "id1",
                identifier: uuid
            )
        ]
        let unsignedResult: (vpTokenSigningPayload: Any?, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: [uuid: unsignedKBJwt] as [String: String],
            unsignedVPTokens: []
        )

        XCTAssertThrowsError(try builder.build(
            credentialInputDescriptorMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [],
            rootIndex: 0
        )) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Missing signing result for \(uuid)",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    // MARK: - Error: empty signature for bound credential

    func testBuildThrowsWhenSignatureIsEmptyForBoundCredential() {
        let uuid = "uuid-with-binding"
        let unsignedKBJwt = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImtiK2p3dCJ9.eyJpYXQiOjE3NTc0NzcxNjR9"

        let mappings = [
            CredentialInputDescriptorMapping(
                format: .vc_sd_jwt,
                credential: AnyCodable(credentialWithBinding),
                inputDescriptorId: "id1",
                identifier: uuid
            )
        ]
        let unsignedResult: (vpTokenSigningPayload: Any?, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: [uuid: unsignedKBJwt] as [String: String],
            unsignedVPTokens: []
        )

        XCTAssertThrowsError(try builder.build(
            credentialInputDescriptorMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [VPTokenSigningResult(signedData: "")],
            rootIndex: 0
        )) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Missing Input: \(uuid) param is required",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    // MARK: - Mixed with three credentials: binding, no binding, binding

    func testBuildMixedThreeCredentials() throws {
        let uuid1 = "uuid-bound-1"
        let uuid2 = "uuid-unbound"
        let uuid3 = "uuid-bound-2"
        let unsignedKB1 = "eyJhbGciOiJFUzI1NiJ9.kb1"
        let unsignedKB2 = "eyJhbGciOiJFUzI1NiJ9.kb2"
        let sig1 = "sig1"
        let sig2 = "sig2"

        let mappings = [
            CredentialInputDescriptorMapping(
                format: .vc_sd_jwt,
                credential: AnyCodable(credentialWithBinding),
                inputDescriptorId: "desc1",
                identifier: uuid1
            ),
            CredentialInputDescriptorMapping(
                format: .dc_sd_jwt,
                credential: AnyCodable(credentialWithoutBinding),
                inputDescriptorId: "desc2",
                identifier: uuid2
            ),
            CredentialInputDescriptorMapping(
                format: .vc_sd_jwt,
                credential: AnyCodable(credentialWithBinding),
                inputDescriptorId: "desc3",
                identifier: uuid3
            )
        ]
        let unsignedResult: (vpTokenSigningPayload: Any?, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: [uuid1: unsignedKB1, uuid3: unsignedKB2] as [String: String],
            unsignedVPTokens: []
        )
        let signingResults = [
            VPTokenSigningResult(signedData: sig1),
            VPTokenSigningResult(signedData: sig2)
        ]

        let result = try builder.build(
            credentialInputDescriptorMappings: mappings,
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: signingResults,
            rootIndex: 3
        )

        XCTAssertEqual(result.vpTokens.count, 3)

        let token1 = result.vpTokens[0] as! SdJwtVPToken
        XCTAssertTrue(token1.value.hasSuffix("\(unsignedKB1).\(sig1)"))

        let token2 = result.vpTokens[1] as! SdJwtVPToken
        XCTAssertEqual(token2.value, credentialWithoutBinding)

        let token3 = result.vpTokens[2] as! SdJwtVPToken
        XCTAssertTrue(token3.value.hasSuffix("\(unsignedKB2).\(sig2)"))

        XCTAssertEqual(result.DescriptorMaps[0].id, "desc1")
        XCTAssertEqual(result.DescriptorMaps[0].path, "$[3]")
        XCTAssertEqual(result.DescriptorMaps[0].format, .vc_sd_jwt)
        XCTAssertEqual(result.DescriptorMaps[1].id, "desc2")
        XCTAssertEqual(result.DescriptorMaps[1].path, "$[4]")
        XCTAssertEqual(result.DescriptorMaps[1].format, .dc_sd_jwt)
        XCTAssertEqual(result.DescriptorMaps[2].id, "desc3")
        XCTAssertEqual(result.DescriptorMaps[2].path, "$[5]")
        XCTAssertEqual(result.DescriptorMaps[2].format, .vc_sd_jwt)
        XCTAssertEqual(result.nextIndex, 6)
    }

    // MARK: - Empty mappings

    func testBuildWithEmptyMappings() throws {
        let unsignedResult: (vpTokenSigningPayload: Any?, unsignedVPTokens: [UnsignedVPToken]) = (
            vpTokenSigningPayload: [String: String](),
            unsignedVPTokens: []
        )

        let result = try builder.build(
            credentialInputDescriptorMappings: [],
            unsignedVPTokenResult: unsignedResult,
            vpTokenSigningResults: [],
            rootIndex: 0
        )

        XCTAssertTrue(result.vpTokens.isEmpty)
        XCTAssertTrue(result.DescriptorMaps.isEmpty)
        XCTAssertEqual(result.nextIndex, 0)
    }
}
