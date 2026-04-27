import XCTest
@testable import OpenID4VP

final class UnsignedMdocVPTokenBuilderTests: XCTestCase {

    func testCreationOfUnsignedMdocVPToken() async throws {
        let builder = try UnsignedMdocVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .v1),
            specVersion: .v1,
            mdocGeneratedNonce: "mock-nonce"
        )
        var mappings = [
            CredentialInputDescriptorMapping(format: .mso_mdoc, credential: AnyCodable(sampleMdoc), inputDescriptorId: "id-1")
        ]

        let (payload, unsignedVPTokens) = try await builder.build(credentialInputDescriptorMappings: &mappings)

        let docTypeToBytes = payload as? [String: String]
        XCTAssertNotNil(docTypeToBytes)
        XCTAssertEqual("org.iso.18013.5.1.mDL", docTypeToBytes!.keys.first)
        XCTAssertTrue(docTypeToBytes!.values.first!.starts(with: "d8"))
        XCTAssertEqual(unsignedVPTokens.count, 1)
        XCTAssertEqual(unsignedVPTokens.first?.format, .mso_mdoc)
        XCTAssertEqual("org.iso.18013.5.1.mDL", mappings.first?.identifier)
    }

    func testCreationOfUnsignedMdocVPTokenForDraft23() async throws {
        let builder = try UnsignedMdocVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .draft23),
            specVersion: .draft23,
            mdocGeneratedNonce: "mock-nonce"
        )
        var mappings = [
            CredentialInputDescriptorMapping(format: .mso_mdoc, credential: AnyCodable(sampleMdoc), inputDescriptorId: "id-1")
        ]

        let (payload, unsignedVPTokens) = try await builder.build(credentialInputDescriptorMappings: &mappings)

        let docTypeToBytes = payload as? [String: String]
        XCTAssertNotNil(docTypeToBytes)
        XCTAssertEqual("org.iso.18013.5.1.mDL", docTypeToBytes!.keys.first)
        XCTAssertEqual(unsignedVPTokens.count, 1)
        XCTAssertEqual("org.iso.18013.5.1.mDL", mappings.first?.identifier)
    }

    func testDeviceAuthenticationBytesAreDifferentBetweenSpecVersions() async throws {
        var mappingsDraft23 = [
            CredentialInputDescriptorMapping(format: .mso_mdoc, credential: AnyCodable(sampleMdoc), inputDescriptorId: "id-1")
        ]
        var mappingsV1 = [
            CredentialInputDescriptorMapping(format: .mso_mdoc, credential: AnyCodable(sampleMdoc), inputDescriptorId: "id-1")
        ]

        let (draft23Payload, _) = try await UnsignedMdocVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .draft23),
            specVersion: .draft23,
            mdocGeneratedNonce: "mock-nonce"
        ).build(credentialInputDescriptorMappings: &mappingsDraft23)

        let (v1Payload, _) = try await UnsignedMdocVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .v1),
            specVersion: .v1,
            mdocGeneratedNonce: "mock-nonce"
        ).build(credentialInputDescriptorMappings: &mappingsV1)

        let draft23Bytes = (draft23Payload as! [String: String])["org.iso.18013.5.1.mDL"]
        let v1Bytes = (v1Payload as! [String: String])["org.iso.18013.5.1.mDL"]

        XCTAssertNotNil(draft23Bytes)
        XCTAssertNotNil(v1Bytes)
        XCTAssertNotEqual(draft23Bytes, v1Bytes)
    }

    func testThrowErrorWhenUnableToDecodeCredential() async throws {
        let builder = try UnsignedMdocVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(),
            specVersion: .v1,
            mdocGeneratedNonce: "mock-nonce"
        )
        var mappings = [
            CredentialInputDescriptorMapping(format: .mso_mdoc, credential: AnyCodable("invalidCBOR"), inputDescriptorId: "id-1")
        ]

        await XCTAssertAsyncThrowsError(try await builder.build(credentialInputDescriptorMappings: &mappings)) { error in
            assertOpenID4VPException(error,
                expectedMessage: "Invalid Verifiable Credential: Error while decoding credential",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testThrowErrorWhenMdocIsNotString() async {
        do {
            let builder = try UnsignedMdocVPTokenBuilder(
                authorizationRequest: getMockAuthorizationRequest(),
                specVersion: .v1,
                mdocGeneratedNonce: "mock-nonce"
            )
            var mappings = [
                CredentialInputDescriptorMapping(format: .mso_mdoc, credential: AnyCodable(12345), inputDescriptorId: "id-1")
            ]

            await XCTAssertAsyncThrowsError(try await builder.build(credentialInputDescriptorMappings: &mappings)) { error in
                assertOpenID4VPException(error,
                    expectedMessage: "MDOC credential is not a String",
                    expectedCode: OpenID4VPErrorCodes.invalidRequest
                )
            }
        } catch {
            XCTFail("Builder init should not throw: \(error)")
        }
    }

    func testThrowErrorWhenDuplicateDocTypes() async throws {
        let builder = try UnsignedMdocVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(),
            specVersion: .v1,
            mdocGeneratedNonce: "mock-nonce"
        )
        var mappings = [
            CredentialInputDescriptorMapping(format: .mso_mdoc, credential: AnyCodable(sampleMdoc), inputDescriptorId: "id-1"),
            CredentialInputDescriptorMapping(format: .mso_mdoc, credential: AnyCodable(sampleMdoc), inputDescriptorId: "id-2"),
        ]

        await XCTAssertAsyncThrowsError(try await builder.build(credentialInputDescriptorMappings: &mappings)) { error in
            assertOpenID4VPException(error,
                expectedMessage: "Duplicate Mdoc Credentials with same doctype found",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
}
