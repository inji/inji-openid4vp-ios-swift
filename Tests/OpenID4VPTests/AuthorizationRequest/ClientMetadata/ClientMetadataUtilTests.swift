import XCTest
@testable import OpenID4VP

final class ClientMetadataUtilTests: XCTestCase {
    private let clientMetadataKey = AuthorizationRequestFieldConstants.clientMetadata.rawValue
    private let responseModeKey = AuthorizationRequestFieldConstants.responseMode.rawValue
    
    // Spec version Draft 23 client metadata parsing tests
    func testParsingOfClientMetadataAvailableAsString() throws {
        let clientMetadataString = """
                {
                    "client_name": "Valid Client",
                    "logo_uri": "https://example.com/logo.png",
                    "vp_formats": { "format1": { "type1": ["value1"] } },
                    "jwks": { "keys": [{ "kty": "RSA", "crv": "P-256", "use": "sig", "alg": "RS256", "kid": "1", "x": "ur76rg" }] }
                }
            """
        
        let authorizationRequest = createAuthorizationRequest(clientMetadata: clientMetadataString)
        
        let updatedAuthorizationRequest = try ClientMetadataSpecVersionHandler.of(.draft23).parseAndValidate(authorizationRequest: authorizationRequest, shouldValidateWithWalletMetadata: false, walletMetadata: nil)
        
        XCTAssertNotNil(updatedAuthorizationRequest[clientMetadataKey])
        assertJsonString(expected: clientMetadataString, actual: convertToJsonString(updatedAuthorizationRequest[clientMetadataKey] as! ClientMetadataSpecVersionDraft23))
    }
    
    func testParsingOfClientMetadataAvailableAsDictionary() throws {
        let clientMetadataDict: [String: Any] = [
            "client_name": "Valid Client",
            "logo_uri": "https://example.com/logo.png",
            "vp_formats": ["format1": ["type1": ["value1"]]],
            "jwks": ["keys": [["kty": "RSA", "crv": "P-256", "use": "sig", "alg": "RS256", "kid": "1", "x": "ur76rg"]]]
        ]
        let authorizationRequest = createAuthorizationRequest(clientMetadata: clientMetadataDict)
        
        let updatedAuthorizationRequest = try ClientMetadataSpecVersionHandler.of(.draft23).parseAndValidate(authorizationRequest: authorizationRequest, shouldValidateWithWalletMetadata: false, walletMetadata: nil)
        
        XCTAssertNotNil(updatedAuthorizationRequest[clientMetadataKey])
        // performing force unwrap here as we know the type is ClientMetadata for sure
        assertDictionariesEqual(expected: clientMetadataDict, actual: convertToDictionary(object: updatedAuthorizationRequest[clientMetadataKey] as! ClientMetadataSpecVersionDraft23))
    }
    
    func testParsingOfClientMetadataWhenClientMetadataAvailableButNotOfExpectedType() throws {
        let authorizationRequest = createAuthorizationRequest(clientMetadata: 12345) // Invalid type for client metadata, accepted - string / map
        XCTAssertThrowsError(try ClientMetadataSpecVersionHandler.of(.draft23).parseAndValidate(authorizationRequest: authorizationRequest, shouldValidateWithWalletMetadata: false, walletMetadata: nil)) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "client_metadata must be of type String or Map",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testParsingOfClientMetadataNotThrowErrorWhenClientMetadataNotPresentAndResponseModeIsDirectPost() throws {
        let authorizationRequest = createAuthorizationRequest()
        
        XCTAssertNoThrowAndVerify(try ClientMetadataSpecVersionHandler.of(.draft23).parseAndValidate(authorizationRequest: authorizationRequest, shouldValidateWithWalletMetadata: false, walletMetadata: nil)) { result in
            XCTAssertNil(result[clientMetadataKey], "Client metadata should not be present when not provided")
        }
    }
    
    // In case of response mode direct_post_jwt, client_metadata is mandatory as the response will be signed which required shared key information available in client_metadata.
    func testParsingOfClientMetadataThrowErrorWhenClientMetadataNotPresentAndResponseModeIsDirectPostJwt() throws {
        let authorizationRequest = createAuthorizationRequest(responseMode: ResponseMode.directPostJwt.rawValue)
        
        XCTAssertThrowsError(try ClientMetadataSpecVersionHandler.of(.draft23).parseAndValidate(authorizationRequest: authorizationRequest, shouldValidateWithWalletMetadata: false, walletMetadata: nil)) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "client_metadata must be present for given response mode",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    
    // Spec version v1 client metadata parsing tests

    func testV1ParsingOfClientMetadataAvailableAsString() throws {
        let clientMetadataString = """
            {
                "client_name": "Valid Client",
                "logo_uri": "https://example.com/logo.png",
                "vp_formats_supported": { "ldp_vc": { "proof_type_values": ["Ed25519Signature2020"] } },
                "jwks": { "keys": [{ "kty": "EC", "use": "enc", "alg": "ECDH-ES", "kid": "1", "crv": "P-256", "x": "ur76rg", "y": "ur76rg" }] }
            }
        """

        let authorizationRequest = createAuthorizationRequest(clientMetadata: clientMetadataString)

        let updatedAuthorizationRequest = try ClientMetadataSpecVersionHandler.of(.v1).parseAndValidate(authorizationRequest: authorizationRequest, shouldValidateWithWalletMetadata: false, walletMetadata: nil as WalletMetadata?)

        XCTAssertNotNil(updatedAuthorizationRequest[clientMetadataKey])
        XCTAssertTrue(updatedAuthorizationRequest[clientMetadataKey] is ClientMetadata)
    }

    func testV1ParsingOfClientMetadataAvailableAsDictionary() throws {
        let clientMetadataDict: NSDictionary = [
            "client_name": "Valid Client",
            "logo_uri": "https://example.com/logo.png",
            "vp_formats_supported": ["ldp_vc": ["proof_type_values": ["Ed25519Signature2020"]]],
            "jwks": ["keys": [["kty": "EC", "use": "enc", "alg": "ECDH-ES", "kid": "1", "crv": "P-256", "x": "ur76rg", "y": "ur76rg"]]]
        ]
        let authorizationRequest = createAuthorizationRequest(clientMetadata: clientMetadataDict)

        let updatedAuthorizationRequest = try ClientMetadataSpecVersionHandler.of(.v1).parseAndValidate(authorizationRequest: authorizationRequest, shouldValidateWithWalletMetadata: false, walletMetadata: nil as WalletMetadata?)

        XCTAssertNotNil(updatedAuthorizationRequest[clientMetadataKey])
        XCTAssertTrue(updatedAuthorizationRequest[clientMetadataKey] is ClientMetadata)
    }

    func testV1ParsingOfClientMetadataWhenAlreadyClientMetadataSpecVersion1Instance() throws {
        let clientMetadataInstance = ClientMetadata(
            vpFormatsSupported: ["ldp_vc": LdpVcFormatSupported()]
        )
        let authorizationRequest = createAuthorizationRequest(clientMetadata: clientMetadataInstance)

        let updatedAuthorizationRequest = try ClientMetadataSpecVersionHandler.of(.v1).parseAndValidate(authorizationRequest: authorizationRequest, shouldValidateWithWalletMetadata: false, walletMetadata: nil as WalletMetadata?)

        XCTAssertTrue(updatedAuthorizationRequest[clientMetadataKey] is ClientMetadata)
    }

    func testV1ParsingOfClientMetadataWhenClientMetadataAvailableButNotOfExpectedType() throws {
        let authorizationRequest = createAuthorizationRequest(clientMetadata: 12345)
        XCTAssertThrowsError(try ClientMetadataSpecVersionHandler.of(.v1).parseAndValidate(authorizationRequest: authorizationRequest, shouldValidateWithWalletMetadata: false, walletMetadata: nil as WalletMetadata?)) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "client_metadata must be of type String or Map",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testV1ParsingOfClientMetadataNotThrowErrorWhenClientMetadataNotPresentAndResponseModeIsDirectPost() throws {
        let authorizationRequest = createAuthorizationRequest()

        XCTAssertNoThrowAndVerify(try ClientMetadataSpecVersionHandler.of(.v1).parseAndValidate(authorizationRequest: authorizationRequest, shouldValidateWithWalletMetadata: false, walletMetadata: nil as WalletMetadata?)) { result in
            XCTAssertNil(result[clientMetadataKey], "Client metadata should not be present when not provided")
        }
    }

    func testV1ParsingOfClientMetadataThrowErrorWhenClientMetadataNotPresentAndResponseModeIsDirectPostJwt() throws {
        let authorizationRequest = createAuthorizationRequest(responseMode: ResponseMode.directPostJwt.rawValue)

        XCTAssertThrowsError(try ClientMetadataSpecVersionHandler.of(.v1).parseAndValidate(authorizationRequest: authorizationRequest, shouldValidateWithWalletMetadata: false, walletMetadata: nil as WalletMetadata?)) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "client_metadata must be present for given response mode",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    private func createAuthorizationRequest(clientMetadata: Any? = nil, responseMode: String = ResponseMode.directPost.rawValue) -> [String: Any] {
        if let clientMetadata = clientMetadata {
            return [
                clientMetadataKey: clientMetadata,
                responseModeKey: responseMode
            ]
        }
        
        return [responseModeKey: responseMode]
    }
}
