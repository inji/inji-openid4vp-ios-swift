import Foundation
import XCTest
@testable import OpenID4VP


class RedirectUriSchemeAuthRequestHandlerTests : XCTestCase {
    let mockNetworkManager: MockNetworkManager! = MockNetworkManager()
    let mockSetResponseUri: (String) -> Void = { value in
    }
    let requestUri: URL = URL(string: "https://mock-verifier.com/verifier/get-auth-request-obj")!
    let clientId: String = "redirect_uri:https://mock-verifier.com"
    
    private var walletConfig: WalletConfig!
    
    override func setUpWithError() throws {
        walletConfig = createWalletConfig()
    }
    
    func setup(){
        super.setUp()
        mockNetworkManager.clearResponses()
    }
    
    // Support for Authorization request by reference or by value
    
    func testReturnFalseForAuthorizationRequestByReferenceSupport() {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest( paramList: authRequestWithPreRegisteredByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdParameter)) as [String : Any]
        let handler = RedirectUriPrefixAuthorizationRequestHandler(clientId: clientId,specVersion: .v1, authorizationRequestParameters: authorizationRequestParameters, walletConfig: walletConfig, setResponseUri: mockSetResponseUri,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        XCTAssertFalse(handler.isSignedRequestSupported(), "redirect_uri client_id_prefix should not support request by reference")
    }
    
    func testReturnTrueForAuthorizationRequestByValueSupport() {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdParameter)) as [String : Any]
        let handler = RedirectUriPrefixAuthorizationRequestHandler(clientId: clientId,specVersion: .v1, authorizationRequestParameters: authorizationRequestParameters, walletConfig: walletConfig, setResponseUri: mockSetResponseUri,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        XCTAssertTrue(handler.isUnsignedRequestSupported(), "redirect_uri client_id_prefix should support request by value")
    }
    
    /// validate and parse request fields
    
    func testThrowNoErrorForValidAuthorizationRequestWhileValidateAndParseRequestFields() async {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdParameter), addEncryptionClientMetadataParams: false) as [String : Any]
        let redirectUriSchemeAuthRequestHandler = RedirectUriPrefixAuthorizationRequestHandler(clientId: clientId,specVersion: .v1, authorizationRequestParameters: authorizationRequestParameters, walletConfig: walletConfig, setResponseUri: mockSetResponseUri,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        await XCTAssertAsyncNoThrowsError(try await redirectUriSchemeAuthRequestHandler.validateAndParseRequestFields())
    }
    
    func testThrowErrorWhenClientIdIsNotEqualToResponseUriWithDirectPostResponseMode() async{
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdParameter, ["response_uri": "http://invalid-mock-verifier.com"]), addEncryptionClientMetadataParams: false) as [String : Any]
        let redirectUriSchemeAuthRequestHandler = RedirectUriPrefixAuthorizationRequestHandler(clientId: clientId,specVersion: .v1, authorizationRequestParameters: authorizationRequestParameters, walletConfig: walletConfig, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce",networkManager: mockNetworkManager)
        
        await XCTAssertAsyncThrowsError(try await redirectUriSchemeAuthRequestHandler.validateAndParseRequestFields()) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "response_uri should be equal to client_id for given client_id_prefix",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testThrowErrorWhenBothResponseUriAndRedirectUriPresentForDirectPost() {
        var authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdParameter), addEncryptionClientMetadataParams: false) as [String : Any]
        authorizationRequestParameters[AuthorizationRequestFieldConstants.redirectUri] = "https://mock-verifier.com"
        let redirectUriSchemeAuthRequestHandler = RedirectUriPrefixAuthorizationRequestHandler(clientId: clientId,specVersion: .v1, authorizationRequestParameters: authorizationRequestParameters, walletConfig: walletConfig, setResponseUri: mockSetResponseUri, walletNonce: "mock-nonce",networkManager: mockNetworkManager)

        XCTAssertThrowsError(try redirectUriSchemeAuthRequestHandler.setResponseUrl()) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "redirect_uri should not be present for given response_mode",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testThrowErrorWhenAuthorizationRequestObjectClientIdIsNotMatchingWithRequestParameterClientIdInDirectPostResponseMode() async {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdParameter, [AuthorizationRequestFieldConstants.responseMode: "fragment","redirect_uri": "http://invalid-mock-verifier.com"])) as [String : Any]
        let redirectUriSchemeAuthRequestHandler = RedirectUriPrefixAuthorizationRequestHandler(clientId: clientId,specVersion: .v1, authorizationRequestParameters: authorizationRequestParameters, walletConfig: walletConfig, setResponseUri: mockSetResponseUri,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        await XCTAssertAsyncThrowsError(try await redirectUriSchemeAuthRequestHandler.validateAndParseRequestFields()) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Given response_mode - fragment is not supported",
                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testProcessingWalletMetadataSuccessfully() async throws {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, [
            AuthorizationRequestFieldConstants.clientId: "mock-client",
        ])) as [String : Any]
        let redirectScheme = RedirectUriPrefixAuthorizationRequestHandler(clientId: clientId,specVersion: .v1, authorizationRequestParameters: authorizationRequestParameters, walletConfig: walletConfig, setResponseUri: mockSetResponseUri,walletNonce: "mock-nonce", networkManager: mockNetworkManager!)
        
        let expectedWalletMetadata : [String: Any] = [
            "authorization_encryption_alg_values_supported": ["ECDH-ES"],
            "authorization_encryption_enc_values_supported": ["A256GCM"],
            "response_types_supported": ["vp_token"],
            "client_id_prefixes_supported": ["pre-registered", "redirect_uri", "decentralized_identifier"],
            "vp_formats_supported": [
                "mso_mdoc": [:],
                "dc+sd-jwt": [:],
                "ldp_vc": [
                    "proof_type_values": ["Ed25519Signature2020", "JsonWebSignature2020"]
                ]
            ]
        ] as [String : Any]
        
        let processedMetadata = try redirectScheme.getWalletMetadata(walletConfig: walletConfig)
        
        assertDictionariesEqual(expected: expectedWalletMetadata, actual: (processedMetadata))
    }

    func testShouldThrowErrorWhenResponseUriNotEqualToClientId() async {
        let mockClientId = "http://mock-client.com"
        let invalidResponseUri = "http://invalid-mock-client.com"
        
        let authParams: [String: Any] = createAuthorizationRequest(
            paramList: authRequestWithRedirectUriByValue,
            requestParams: mergeMaps(
                authorizationRequestParamsWithValue,
                redirectUriSchemeClientIdParameter,
                [
                    "client_id": mockClientId,
                    "response_mode": "direct_post",
                    "response_uri": invalidResponseUri,
                    "scope": "openid",
                    "response_type": "vp_token",
                    "nonce": "123456"
                ]
            ),
            addEncryptionClientMetadataParams: false
        ) as [String : Any]
        
        let redirectUriSchemeHandler = RedirectUriPrefixAuthorizationRequestHandler(clientId: clientId,specVersion: .v1, 
            authorizationRequestParameters: authParams,
            walletConfig: walletConfig,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager
        )
        
        await XCTAssertAsyncThrowsError(
            try await redirectUriSchemeHandler.validateAndParseRequestFields()
        ) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "response_uri should be equal to client_id for given client_id_prefix",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testThrowErrorWhenExtractPublicKeyIsInvoked() async {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdParameter)) as [String : Any]
        let handler = RedirectUriPrefixAuthorizationRequestHandler(clientId: clientId,specVersion: .v1, authorizationRequestParameters: authorizationRequestParameters, walletConfig: walletConfig, setResponseUri: mockSetResponseUri,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        await XCTAssertAsyncThrowsError(try await handler.extractPublicKey(keyId: nil, algorithm: "edDsa")) { error in
            assertOpenID4VPException(error,
                                     expectedMessage: "Public key extraction is not supported for redirect_uri client_id_prefix",
                                     expectedCode: "unsupported_operation"
            )
        }
    }
    

    func testValidateAndParseRequestFieldsSucceedsWithIarPostResponseMode() async {
        let params = createAuthorizationRequest(
            paramList: authRequestWithRedirectUriByValue,
            requestParams: mergeMaps(
                authorizationRequestParamsWithValue,
                redirectUriSchemeClientIdParameter,
                [
                    "response_mode": "iar-post",
                    "response_uri": "https://mock-verifier.com/redirect"
                ]
            ),
            addEncryptionClientMetadataParams: false
        ) as [String : Any]

        let handler = RedirectUriPrefixAuthorizationRequestHandler(clientId: clientId,specVersion: .v1, 
            authorizationRequestParameters: params,
            walletConfig: walletConfig,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager
        )

        await XCTAssertAsyncNoThrowsError(try await handler.validateAndParseRequestFields())
    }
    
    func testValidateAndParseRequestFieldsSucceedsWithIaeResponseModes() async {

        let testCases = [
            ("iae_post", false),
            ("iae_post.jwt", true)
        ]

        for (responseMode, addEncryptionMetadata) in testCases {

            let params = createAuthorizationRequest(
                paramList: authRequestWithRedirectUriByValue,
                requestParams: mergeMaps(
                    authorizationRequestParamsWithValue,
                    redirectUriSchemeClientIdParameter,
                    [
                        "response_mode": responseMode,
                        "response_uri": "https://mock-verifier.com/redirect"
                    ]
                ),
                addEncryptionClientMetadataParams: addEncryptionMetadata
            ) as [String : Any]

            let handler = RedirectUriPrefixAuthorizationRequestHandler(
                clientId: clientId,
                specVersion: .v1,
                authorizationRequestParameters: params,
                walletConfig: walletConfig,
                setResponseUri: mockSetResponseUri,
                walletNonce: "mock-nonce",
                networkManager: mockNetworkManager
            )

            await XCTAssertAsyncNoThrowsError(
                try await handler.validateAndParseRequestFields()
            )
        }
    }

    func testValidateAndParseRequestFieldsSucceedsWithIarPostJwtResponseMode() async {
        let params = createAuthorizationRequest(
            paramList: authRequestWithRedirectUriByValue,
            requestParams: mergeMaps(
                authorizationRequestParamsWithValue,
                redirectUriSchemeClientIdParameter,
                [
                    "response_mode": "iar-post.jwt",
                    "response_uri": "https://mock-verifier.com/redirect"
                ]
            )
        ) as [String : Any]

        let handler = RedirectUriPrefixAuthorizationRequestHandler(clientId: clientId,specVersion: .v1, 
            authorizationRequestParameters: params,
            walletConfig: walletConfig,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager
        )

        await XCTAssertAsyncNoThrowsError(try await handler.validateAndParseRequestFields())
    }
    
    func testValidateAndParseRequestFieldsSucceedsWithIarPostWithoutResponseUri() async {
        let params = createAuthorizationRequest(
            paramList: authRequestWithRedirectUriByValue,
            requestParams: mergeMaps(
                authorizationRequestParamsWithValue,
                redirectUriSchemeClientIdParameter,
                ["response_mode": "iar-post"]
            ),
            addEncryptionClientMetadataParams: false
        ) as [String : Any]

        let handler = RedirectUriPrefixAuthorizationRequestHandler(clientId: clientId,specVersion: .v1, 
            authorizationRequestParameters: params,
            walletConfig: walletConfig,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager
        )

        await XCTAssertAsyncNoThrowsError(try await handler.validateAndParseRequestFields())
    }
    
    func testValidateAndParseRequestFieldsSucceedsWithIaePostWithoutResponseUri() async {
        let params = createAuthorizationRequest(
            paramList: authRequestWithRedirectUriByValue,
            requestParams: mergeMaps(
                authorizationRequestParamsWithValue,
                redirectUriSchemeClientIdParameter,
                ["response_mode": "iae_post"]
            ),
            addEncryptionClientMetadataParams: false
        ) as [String : Any]

        let handler = RedirectUriPrefixAuthorizationRequestHandler(clientId: clientId,specVersion: .v1,
            authorizationRequestParameters: params,
            walletConfig: walletConfig,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager
        )

        await XCTAssertAsyncNoThrowsError(try await handler.validateAndParseRequestFields())
    }


    func testValidateAndParseRequestFieldsSucceedsWithIarPostJwt_WithoutResponseUri() async {
        let params = createAuthorizationRequest(
            paramList: authRequestWithRedirectUriByValue,
            requestParams: mergeMaps(
                authorizationRequestParamsWithValue,
                redirectUriSchemeClientIdParameter,
                ["response_mode": "iar-post.jwt"]
            )
        ) as [String : Any]

        let handler = RedirectUriPrefixAuthorizationRequestHandler(clientId: clientId,specVersion: .v1, 
            authorizationRequestParameters: params,
            walletConfig: walletConfig,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager
        )

        await XCTAssertAsyncNoThrowsError(try await handler.validateAndParseRequestFields())
    }

    
    func testValidateAndParseRequestFieldsSucceedsWithIaePostJwtWithoutResponseUri() async {
        let params = createAuthorizationRequest(
            paramList: authRequestWithRedirectUriByValue,
            requestParams: mergeMaps(
                authorizationRequestParamsWithValue,
                redirectUriSchemeClientIdParameter,
                ["response_mode": "iae_post.jwt"]
            )
        ) as [String : Any]

        let handler = RedirectUriPrefixAuthorizationRequestHandler(clientId: clientId,specVersion: .v1,
            authorizationRequestParameters: params,
            walletConfig: walletConfig,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager
        )

        await XCTAssertAsyncNoThrowsError(try await handler.validateAndParseRequestFields())
    }

    func testValidateAndParseRequestFieldsSucceedsWithIarPostMismatchedResponseUri() async {
        let params = createAuthorizationRequest(
            paramList: authRequestWithRedirectUriByValue,
            requestParams: mergeMaps(
                authorizationRequestParamsWithValue,
                redirectUriSchemeClientIdParameter,
                [
                    "response_mode": "iar-post",
                    "response_uri": "https://different.com/response"
                ]
            ),
            addEncryptionClientMetadataParams: false
        ) as [String : Any]

        let handler = RedirectUriPrefixAuthorizationRequestHandler(clientId: clientId,specVersion: .v1, 
            authorizationRequestParameters: params,
            walletConfig: walletConfig,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager
        )

        await XCTAssertAsyncNoThrowsError(try await handler.validateAndParseRequestFields())
    }

    
    func testValidateAndParseRequestFieldsSucceedsWithIaePostMismatchedResponseUri() async {
        let params = createAuthorizationRequest(
            paramList: authRequestWithRedirectUriByValue,
            requestParams: mergeMaps(
                authorizationRequestParamsWithValue,
                redirectUriSchemeClientIdParameter,
                [
                    "response_mode": "iae_post",
                    "response_uri": "https://different.com/response"
                ]
            ),
            addEncryptionClientMetadataParams: false
        ) as [String : Any]

        let handler = RedirectUriPrefixAuthorizationRequestHandler(clientId: clientId,specVersion: .v1,
            authorizationRequestParameters: params,
            walletConfig: walletConfig,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager
        )

        await XCTAssertAsyncNoThrowsError(try await handler.validateAndParseRequestFields())
    }

    func testValidateAndParseRequestFieldsSucceedsWithIarPostJwtMismatchedResponseUri() async {
        let params = createAuthorizationRequest(
            paramList: authRequestWithRedirectUriByValue,
            requestParams: mergeMaps(
                authorizationRequestParamsWithValue,
                redirectUriSchemeClientIdParameter,
                [
                    "response_mode": "iar-post.jwt",
                    "response_uri": "https://different.com/response"
                ]
            )
        ) as [String : Any]

        let handler = RedirectUriPrefixAuthorizationRequestHandler(clientId: clientId,specVersion: .v1, 
            authorizationRequestParameters: params,
            walletConfig: walletConfig,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager
        )

        await XCTAssertAsyncNoThrowsError(try await handler.validateAndParseRequestFields())
    }

    
    func testValidateAndParseRequestFieldsSucceedsWithIaePostJwtMismatchedResponseUri() async {
        let params = createAuthorizationRequest(
            paramList: authRequestWithRedirectUriByValue,
            requestParams: mergeMaps(
                authorizationRequestParamsWithValue,
                redirectUriSchemeClientIdParameter,
                [
                    "response_mode": "iae_post.jwt",
                    "response_uri": "https://different.com/response"
                ]
            )
        ) as [String : Any]

        let handler = RedirectUriPrefixAuthorizationRequestHandler(clientId: clientId,specVersion: .v1,
            authorizationRequestParameters: params,
            walletConfig: walletConfig,
            setResponseUri: mockSetResponseUri,
            walletNonce: "mock-nonce",
            networkManager: mockNetworkManager
        )

        await XCTAssertAsyncNoThrowsError(try await handler.validateAndParseRequestFields())
    }
}
