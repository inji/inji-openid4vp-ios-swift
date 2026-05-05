import XCTest
@testable import OpenID4VP

final class UnsignedMdocVPTokenBuilderTests: XCTestCase {

    private let expectedDocType = "org.iso.18013.5.1.mDL"

    // MARK: - build(credentialInputDescriptorMappings:)

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

        let docTypeToBytes = try XCTUnwrap(payload as? [String: String])
        XCTAssertEqual(docTypeToBytes.keys.sorted(), [expectedDocType])
        let bytes = try XCTUnwrap(docTypeToBytes[expectedDocType])
        XCTAssertTrue(bytes.hasPrefix("d8"), "Expected CBOR-tagged hex starting with 'd8', got: \(bytes.prefix(4))")
        XCTAssertEqual(unsignedVPTokens.count, 1)
        XCTAssertEqual(unsignedVPTokens[0].format, .mso_mdoc)
        XCTAssertEqual(mappings[0].identifier, expectedDocType)
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

        let docTypeToBytes = try XCTUnwrap(payload as? [String: String])
        XCTAssertEqual(docTypeToBytes.keys.sorted(), [expectedDocType])
        let bytes = try XCTUnwrap(docTypeToBytes[expectedDocType])
        XCTAssertTrue(bytes.hasPrefix("d8"), "Expected CBOR-tagged hex starting with 'd8', got: \(bytes.prefix(4))")
        XCTAssertEqual(unsignedVPTokens.count, 1)
        XCTAssertEqual(unsignedVPTokens[0].format, .mso_mdoc)
        XCTAssertEqual(mappings[0].identifier, expectedDocType)
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

        let draft23Bytes = try XCTUnwrap((draft23Payload as? [String: String])?[expectedDocType])
        let v1Bytes = try XCTUnwrap((v1Payload as? [String: String])?[expectedDocType])
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

    // MARK: - build(credentialToCredentialQueryIdMappings:)

    func testDcqlBuildReturnsCorrectPayloadAndUnsignedTokensForV1() async throws {
        let builder = try UnsignedMdocVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .v1),
            specVersion: .v1,
            mdocGeneratedNonce: "mock-nonce"
        )
        var mappings = [
            CredentialToCredentialQueryIdMapping(format: .mso_mdoc, credential: AnyCodable(sampleMdoc), credentialQueryId: "q1")
        ]

        let (payload, unsignedVPTokens) = try await builder.build(credentialToCredentialQueryIdMappings: &mappings)

        let docTypeToBytes = try XCTUnwrap(payload as? [String: String])
        XCTAssertEqual(docTypeToBytes.keys.sorted(), [expectedDocType])
        let bytes = try XCTUnwrap(docTypeToBytes[expectedDocType])
        XCTAssertTrue(bytes.hasPrefix("d8"), "Expected CBOR-tagged hex starting with 'd8', got: \(bytes.prefix(4))")
        XCTAssertEqual(unsignedVPTokens.count, 1)
        XCTAssertEqual(unsignedVPTokens[0].format, .mso_mdoc)
        XCTAssertEqual(String(decoding: unsignedVPTokens[0].dataToSign, as: UTF8.self), bytes)
        XCTAssertEqual(mappings[0].identifier, expectedDocType)
    }

    func testDcqlBuildReturnsCorrectPayloadAndUnsignedTokensForDraft23() async throws {
        let builder = try UnsignedMdocVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .draft23),
            specVersion: .draft23,
            mdocGeneratedNonce: "mock-nonce"
        )
        var mappings = [
            CredentialToCredentialQueryIdMapping(format: .mso_mdoc, credential: AnyCodable(sampleMdoc), credentialQueryId: "q1")
        ]

        let (payload, unsignedVPTokens) = try await builder.build(credentialToCredentialQueryIdMappings: &mappings)

        let docTypeToBytes = try XCTUnwrap(payload as? [String: String])
        XCTAssertEqual(docTypeToBytes.keys.sorted(), [expectedDocType])
        let bytes = try XCTUnwrap(docTypeToBytes[expectedDocType])
        XCTAssertTrue(bytes.hasPrefix("d8"), "Expected CBOR-tagged hex starting with 'd8', got: \(bytes.prefix(4))")
        XCTAssertEqual(unsignedVPTokens.count, 1)
        XCTAssertEqual(unsignedVPTokens[0].format, .mso_mdoc)
        XCTAssertEqual(String(decoding: unsignedVPTokens[0].dataToSign, as: UTF8.self), bytes)
        XCTAssertEqual(mappings[0].identifier, expectedDocType)
    }

    func testDcqlBuildDeviceAuthBytesAreDifferentBetweenSpecVersions() async throws {
        var mappingsDraft23 = [CredentialToCredentialQueryIdMapping(format: .mso_mdoc, credential: AnyCodable(sampleMdoc), credentialQueryId: "q1")]
        var mappingsV1 = [CredentialToCredentialQueryIdMapping(format: .mso_mdoc, credential: AnyCodable(sampleMdoc), credentialQueryId: "q1")]

        let (draft23Payload, _) = try await UnsignedMdocVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .draft23),
            specVersion: .draft23,
            mdocGeneratedNonce: "mock-nonce"
        ).build(credentialToCredentialQueryIdMappings: &mappingsDraft23)

        let (v1Payload, _) = try await UnsignedMdocVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .v1),
            specVersion: .v1,
            mdocGeneratedNonce: "mock-nonce"
        ).build(credentialToCredentialQueryIdMappings: &mappingsV1)

        let draft23Bytes = try XCTUnwrap((draft23Payload as? [String: String])?[expectedDocType])
        let v1Bytes = try XCTUnwrap((v1Payload as? [String: String])?[expectedDocType])
        XCTAssertNotEqual(draft23Bytes, v1Bytes)
    }

    func testDcqlBuildThrowsWhenCredentialIsNotString() async throws {
        let builder = try UnsignedMdocVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .v1),
            specVersion: .v1,
            mdocGeneratedNonce: "mock-nonce"
        )
        var mappings = [CredentialToCredentialQueryIdMapping(format: .mso_mdoc, credential: AnyCodable(12345), credentialQueryId: "q1")]

        await XCTAssertAsyncThrowsError(try await builder.build(credentialToCredentialQueryIdMappings: &mappings)) { error in
            assertOpenID4VPException(error,
                expectedMessage: "MDOC credential is not a String",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testDcqlBuildThrowsWhenCredentialIsInvalidCBOR() async throws {
        let builder = try UnsignedMdocVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .v1),
            specVersion: .v1,
            mdocGeneratedNonce: "mock-nonce"
        )
        var mappings = [CredentialToCredentialQueryIdMapping(format: .mso_mdoc, credential: AnyCodable("invalidCBOR"), credentialQueryId: "q1")]

        await XCTAssertAsyncThrowsError(try await builder.build(credentialToCredentialQueryIdMappings: &mappings)) { error in
            assertOpenID4VPException(error,
                expectedMessage: "Invalid Verifiable Credential: Error while decoding credential",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testDcqlBuildThrowsWhenDuplicateDocTypes() async throws {
        let builder = try UnsignedMdocVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .v1),
            specVersion: .v1,
            mdocGeneratedNonce: "mock-nonce"
        )
        var mappings = [
            CredentialToCredentialQueryIdMapping(format: .mso_mdoc, credential: AnyCodable(sampleMdoc), credentialQueryId: "q1"),
            CredentialToCredentialQueryIdMapping(format: .mso_mdoc, credential: AnyCodable(sampleMdoc), credentialQueryId: "q2")
        ]

        await XCTAssertAsyncThrowsError(try await builder.build(credentialToCredentialQueryIdMappings: &mappings)) { error in
            assertOpenID4VPException(error,
                expectedMessage: "Duplicate Mdoc Credentials with same doctype found",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testDcqlBuildSetsIdentifierToDocTypeOnMapping() async throws {
        let builder = try UnsignedMdocVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .v1),
            specVersion: .v1,
            mdocGeneratedNonce: "mock-nonce"
        )
        var mappings = [
            CredentialToCredentialQueryIdMapping(format: .mso_mdoc, credential: AnyCodable(sampleMdoc), credentialQueryId: "q1")
        ]

        _ = try await builder.build(credentialToCredentialQueryIdMappings: &mappings)

        XCTAssertEqual(mappings[0].identifier, expectedDocType)
    }

    func testDcqlBuildUnsignedTokensAreSortedByDocType() async throws {
        let builder = try UnsignedMdocVPTokenBuilder(
            authorizationRequest: getMockAuthorizationRequest(specVersion: .v1),
            specVersion: .v1,
            mdocGeneratedNonce: "mock-nonce"
        )
        var mappings = [
            CredentialToCredentialQueryIdMapping(format: .mso_mdoc, credential: AnyCodable(sampleMdoc), credentialQueryId: "q1")
        ]

        let (payload, unsignedVPTokens) = try await builder.build(credentialToCredentialQueryIdMappings: &mappings)

        let docTypeToBytes = try XCTUnwrap(payload as? [String: String])
        let expectedBytes = try XCTUnwrap(docTypeToBytes[expectedDocType])
        XCTAssertEqual(String(decoding: unsignedVPTokens[0].dataToSign, as: UTF8.self), expectedBytes)
    }
}
