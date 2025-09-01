import Foundation
import XCTest
@testable import OpenID4VP

class PreRegisteredClientIdSchemeTests : XCTestCase {
    let mockNetworkManager: MockNetworkManager! = MockNetworkManager()
    let mockSetResponseUri: (String) -> Void = { value in
    }
    
    let requestUriResponse: String = createAuthorizationRequestObject(clientIdScheme: .preRegistered, authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue,[
        AuthorizationRequestFieldConstants.clientId.rawValue: "mock-client",
    ]), applicableFields: authRequestWithPreRegisteredByValueDraft23)
    let requestUri: URL = URL(string: "https://mock-verifier.com/verifier/get-auth-request-obj")!
    
    private var walletMetadata: WalletMetadata!
    
    override func setUpWithError() throws {
        walletMetadata = try createWalletMetadataV2()
    }
    
    // Validate client tests
    
    func testThrowExceptionWhenClientIdIsNotAvailableAsTrustedVerifier(){
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValueDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, [
            AuthorizationRequestFieldConstants.clientId.rawValue: "untrusted-mock-client",
        ])) as [String : Any]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(trustedVerifiers: preRegisteredVerifiers, authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil, shouldValidateClient: true, setResponseUri: mockSetResponseUri,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        XCTAssertThrowsError(try preRegistered.validateClientId()) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Verifier is not trusted by the wallet",
                expectedCode: OpenID4VPErrorCodes.invalidClient
            )
        }
    }
    
    
    func testThrowExceptionWhenTrustedVerifiersListIsEmpty(){
        let authorizationRequestParameters: [String : Any] = [AuthorizationRequestFieldConstants.clientId.rawValue: "other-mock-client","response_uri": "https://mock-verifier.com"]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(trustedVerifiers: preRegisteredVerifiers, authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil, shouldValidateClient: true, setResponseUri: mockSetResponseUri,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        XCTAssertThrowsError(try preRegistered.validateClientId()) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Verifier is not trusted by the wallet",
                expectedCode: OpenID4VPErrorCodes.invalidClient
            )
        }
    }
    
    // Support for Authorization request by reference or by value
    
    func testReturnTrueForAuthorizationRequestByReferenceSupport() {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValueDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdDraft23)) as [String : Any]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(trustedVerifiers: preRegisteredVerifiers, authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil, shouldValidateClient: true, setResponseUri: mockSetResponseUri,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        XCTAssertTrue(preRegistered.isRequestUriSupported(), "Pre-registered client id scheme should support authorization request by reference")
    }


    func testReturnTrueForAuthorizationRequestByValueSupport() {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValueDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdDraft23)) as [String : Any]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(trustedVerifiers: preRegisteredVerifiers, authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil, shouldValidateClient: true, setResponseUri: mockSetResponseUri,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        XCTAssertTrue(preRegistered.isRequestObjectSupported(), "Pre-registered client id scheme should support authorization request by value")
    }

    
    
    // Validate and parse authorization request - check if verifier is trusted
    
    func testDoesNotThrowExceptionWhenTrustedVerifierDoesNotHaveClientMetadataAndAuthorizationRequestContainsClientMetadata() async throws {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValueDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue,preRegisteredSchemeClientIdDraft23)) as [String : Any]
        let trustedVerifiersWithoutClientMetadata = [
            Verifier(clientId: "mock-client", responseUris: ["https://mock-verifier.com"])
        ]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(trustedVerifiers: trustedVerifiersWithoutClientMetadata, authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil,shouldValidateClient: true, setResponseUri: mockSetResponseUri,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        await XCTAssertAsyncNoThrowsError(try await preRegistered.validateAndParseRequestFields(), "Error should not happen when client_metadata is not known to wallet but provided in authorization request")
    }
    
    func testThrowExceptionWhenClientIdIsAvailableInTrustedVerifiersButResponseUriIsNotMatching() async{
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValueDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, [
            "client_id": "mock-client",
            "response_uri": "https://some-other-url.com"
        ])) as [String : Any]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(trustedVerifiers: preRegisteredVerifiers, authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil,shouldValidateClient: true, setResponseUri: mockSetResponseUri,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        await XCTAssertAsyncThrowsError(try await preRegistered.validateAndParseRequestFields()){ error in
            assertOpenID4VPException(error,
                                     expectedMessage: "response_uri trust cannot be established",
                                     expectedCode: OpenID4VPErrorCodes.invalidClient
            )
        }
    }
    
    func testThrowExceptionWhenClientIdIsAvailableInTrustedVerifierListWithClientMetadataButClientMetadataIsAlsoAvailableInAuthorizationRequest() async throws {
        let clientMetadataString = """
                {
                    "client_name": "Valid Client",
                    "logo_uri": "https://example.com/logo.png",
                    "authorization_encrypted_response_alg": "RSA-OAEP",
                    "authorization_encrypted_response_enc": "A256GCM",
                    "vp_formats": { "format1": { "type1": ["value1"] } },
                    "jwks": { "keys": [{ "kty": "RSA", "crv": "P-256", "use": "sig", "alg": "RS256", "kid": "1", "x": "ur76rg" }] }
                }
            """.data(using: .utf8)!
        let clientMetadata = try ClientMetadata.deserializeAndValidate(clientMetadata: clientMetadataString)
        let trustedVerifiers = [Verifier(clientId: "mock-client", responseUris: ["https://mock-verifier.com"], clientMetadata: clientMetadata)]
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValueDraft23 + [AuthorizationRequestFieldConstants.clientMetadata.rawValue], requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdDraft23)) as [String : Any]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(trustedVerifiers: trustedVerifiers, authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil, shouldValidateClient: true, setResponseUri: mockSetResponseUri,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        await XCTAssertAsyncThrowsError(try await preRegistered.validateAndParseRequestFields()) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "client_metadata provided despite pre-registered metadata already existing for the Client Identifier.",
                expectedCode: OpenID4VPErrorCodes.invalidClient
            )
        }
    }
    
    func testAutorizationRequestUpdatedWithClientMetadataForPreRegisteredVerifierWhichHasClientMetadataStored() async throws {
        let clientMetadataString = """
                {
                    "client_name": "Valid Client",
                    "logo_uri": "https://example.com/logo.png",
                    "authorization_encrypted_response_alg": "RSA-OAEP",
                    "authorization_encrypted_response_enc": "A256GCM",
                    "vp_formats": { "format1": { "type1": ["value1"] } },
                    "jwks": { "keys": [{ "kty": "RSA", "crv": "P-256", "use": "sig", "alg": "RS256", "kid": "1", "x": "ur76rg" }] }
                }
            """
        let clientMetadata = try ClientMetadata.deserializeAndValidate(clientMetadata: clientMetadataString)
        let trustedVerifiers = [Verifier(clientId: "mock-client", responseUris: ["https://mock-verifier.com"], clientMetadata: clientMetadata)]
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValueDraft23.filter {$0 != "client_metadata"}, requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdDraft23)) as [String : Any]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(trustedVerifiers: trustedVerifiers, authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil, shouldValidateClient: true, setResponseUri: mockSetResponseUri,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        try await preRegistered.validateAndParseRequestFields()
        
        let clientMetadataInAuthRequest = preRegistered.authorizationRequestParameters[AuthorizationRequestFieldConstants.clientMetadata.rawValue]
        assertJsonString(expected: clientMetadataString, actual: convertToJsonString(clientMetadataInAuthRequest as! ClientMetadata))
    }
    
    /// Fetch authorization request by value - validate authorization request object and authorization request query paramaters
    
    func testFetchAuthorizationRequestOnValidPreRegisteredSchemeAuthRequestSentByValue() async{
        let expectedAuthorizationRequestParameters: [String : Any] = [
            "response_mode": "direct_post",
            "response_type": "vp_token",
            "client_id": "mock-client",
            "nonce": "VbRRB/LTxLiXmVNZuyMO8A==",
            "state": "+mRQe1d6pBoJqF6Ab28klg==",
            "response_uri": "https://mock-verifier.com",
            "presentation_definition": [
                "input_descriptors": [[
                    "format": [
                        "ldp_vc": [
                            "proof_type": ["Ed25519Signature2018", "RsaSignature2018"]
                        ]
                    ],
                    "constraints": [
                        "fields": [[
                            "path": ["$.credentialSubject.email"],
                            "filter": [
                                "pattern": "@gmail.com",
                                "type": "string"
                            ]
                        ]]
                    ],
                    "name": "Verifiable Credential",
                    "id": "input_1",
                    "purpose": "To verify identity using Linked Data Proofs"
                ]],
                "id": "vp_presentation_definition"
            ]
        ]
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValueDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, [
            "client_id": "mock-client",
        ])) as [String : Any]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(trustedVerifiers: preRegisteredVerifiers, authorizationRequestParameters: authorizationRequestParameters, walletMetadata: nil, shouldValidateClient: true, setResponseUri: mockSetResponseUri,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
        
        try? await preRegistered.fetchAuthorizationRequest()
        
        assertDictionariesEqual(expected: expectedAuthorizationRequestParameters, actual: preRegistered.authorizationRequestParameters)
    }
    
//    func testFetchAuthorizationRequestOnValidPreRegisteredSchemeAuthRequestSentByReference() async{
//        let expectedAuthorizationRequestParameters: [String : Any] = [
//            "client_id": "mock-client",
//            "state": "+mRQe1d6pBoJqF6Ab28klg==",
//            "response_type": "vp_token",
//            "response_mode": "direct_post",
//            "response_uri": "https://mock-verifier.com",
//            "presentation_definition": [
//                "input_descriptors": [[
//                    "id": "input_1",
//                    "format": [
//                        "ldp_vc": [
//                            "proof_type": ["Ed25519Signature2018", "RsaSignature2018"]
//                        ]
//                    ],
//                    "name": "Verifiable Credential",
//                    "constraints": [
//                        "fields": [[
//                            "filter": [
//                                "type": "string",
//                                "pattern": "@gmail.com"
//                            ],
//                            "path": ["$.credentialSubject.email"]
//                        ]]
//                    ],
//                    "purpose": "To verify identity using Linked Data Proofs"
//                ]],
//                "id": "vp_presentation_definition"
//            ],
//            "nonce": "VbRRB/LTxLiXmVNZuyMO8A=="
//        ]
//        let requestUriResponse: String = createAuthorizationRequestObject(clientIdScheme: .preRegistered, authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue,preRegisteredSchemeClientIdDraft23), applicableFields: authRequestWithPreRegisteredByValueDraft23)
//        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReferenceDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdDraft23)) as [String : Any]
//        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(trustedVerifiers: preRegisteredVerifiers, authorizationRequestParameters: authorizationRequestParametersByReference, walletMetadata: nil,shouldValidateClient: true, setResponseUri: mockSetResponseUri,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
//        
//        try? await preRegistered.validateRequestUriResponse(requestUriResponse: createRequestUriResponserequestUriResponse), walletNonce: "mock-nonce", isMismatchedAcceptableType: false)
//        
//        assertDictionariesEqual(expected: expectedAuthorizationRequestParameters, actual: preRegistered.authorizationRequestParameters)
//    }
//    
//    func testFetchAuthorizationRequestThrowExceptionForValidationOfMatchingClientIdOnAuthRequestSentByReference() async{
//        let requestUriResponse: String = createAuthorizationRequestObject(clientIdScheme: .preRegistered, authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue,[
//            AuthorizationRequestFieldConstants.clientId.rawValue: "some-mock-client",
//        ]), applicableFields: authRequestWithPreRegisteredByValueDraft23)
//        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReferenceDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdDraft23)) as [String : Any]
//        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(trustedVerifiers: preRegisteredVerifiers, authorizationRequestParameters: authorizationRequestParametersByReference, walletMetadata: nil, shouldValidateClient: true, setResponseUri: mockSetResponseUri,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
//        
//        
//        await XCTAssertAsyncThrowsError(try await preRegistered.validateRequestUriResponse(requestUriResponse: createRequestUriResponserequestUriResponse),walletNonce: "mock-nonce", isMismatchedAcceptableType: false)) { error in
//            assertOpenID4VPException(error,
//                                     expectedMessage: "Client Id is mismatching in QR data and Request Uri response",
//                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
//            )
//            
//        }
//    }
//    
//    func testFetchAuthorizationRequestThrowExceptionForValidationOfMatchingClientIdSchemeOnAuthRequestSentByReferenceForDraft21() async{
//        
//        let requestUriResponse: String = createAuthorizationRequestObject(clientIdScheme: .preRegistered, authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue, [
//            AuthorizationRequestFieldConstants.clientId.rawValue: "mock-client",
//            AuthorizationRequestFieldConstants.clientIdScheme.rawValue: "did",
//        ]), applicableFields: authRequestWithPreRegisteredByValueDraft21)
//        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReferenceDraft21 , requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdDraft21)) as [String : Any]
//        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(trustedVerifiers: preRegisteredVerifiers, authorizationRequestParameters: authorizationRequestParametersByReference, walletMetadata: nil, shouldValidateClient: true, setResponseUri: mockSetResponseUri,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
//        
//        await XCTAssertAsyncThrowsError(try await preRegistered.validateRequestUriResponse(requestUriResponse: createRequestUriResponserequestUriResponse),walletNonce: "mock-nonce", isMismatchedAcceptableType: false)) { error in
//            assertOpenID4VPException(error,
//                                     expectedMessage: "Client Id scheme is mismatching in QR data and Request Uri response",
//                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
//            )
//        }
//    }
//    
//    /// Validation of authRequest params obtained via request_uri by matching with url encoded query param data
//    
//    func testFetchAuthorizationRequestThrowExceptionWhenAuthRequestObjectObtainedIsJWT() async{
//        let requestUriResponse: String = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
//        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReferenceDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdDraft23)) as [String : Any]
//        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(trustedVerifiers: preRegisteredVerifiers, authorizationRequestParameters: authorizationRequestParametersByReference, walletMetadata: nil, shouldValidateClient: true, setResponseUri: mockSetResponseUri,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
//        
//        await XCTAssertAsyncThrowsError(try await preRegistered.validateRequestUriResponse(requestUriResponse: createRequestUriResponserequestUriResponse),walletNonce: "mock-nonce",isMismatchedAcceptableType: false)) { error in
//            assertOpenID4VPException(error,
//                                     expectedMessage: "Authorization Request must not be signed for given client_id_scheme",
//                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
//            )
//        }
//    }
//    
//    func testFetchAuthorizationRequestThrowExceptionWhenAuthRequestObjectObtainedIsNotJsonContentType() async {
//        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReferenceDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdDraft23)) as [String : Any]
//        
//        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(trustedVerifiers: preRegisteredVerifiers, authorizationRequestParameters: authorizationRequestParametersByReference, walletMetadata: nil, shouldValidateClient: true, setResponseUri: mockSetResponseUri,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
//        let requestUriResponse = createRequestUriResponserequestUriResponse, httpUrlResponse: HTTPURLResponse(url: requestUri, statusCode: 200, httpVersion: "", headerFields: ["Content-Type":"application/x-www-form-urlencoded"])!)
//        
//        await XCTAssertAsyncThrowsError(try await preRegistered.validateRequestUriResponse(requestUriResponse: requestUriResponse,walletNonce: "mock-nonce", isMismatchedAcceptableType: true)) { error in
//            assertOpenID4VPException(error,
//                                     expectedMessage: "Authorization Request must not be signed for given client_id_scheme",
//                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
//            )
//        }
//    }
//    
//    func testFetchAuthorizationRequestThrowExceptionWhenAuthRequestObjectObtainedDoesNotContainContentTypeFieldInHeader() async {
//        let authorizationRequestParametersByReference: [String : Any] = createAuthorizationRequest(paramList: authRequestParamsByReferenceDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdDraft23)) as [String : Any]
//        
//        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(trustedVerifiers: preRegisteredVerifiers, authorizationRequestParameters: authorizationRequestParametersByReference, walletMetadata: walletMetadata, shouldValidateClient: true, setResponseUri: mockSetResponseUri,walletNonce: "mock-nonce", networkManager: mockNetworkManager)
//        
//        let requestUriResponse = createRequestUriResponserequestUriResponse, httpUrlResponse: HTTPURLResponse(url: requestUri, statusCode: 200, httpVersion: "", headerFields: [:])!)
//        
//        await XCTAssertAsyncThrowsError(try await preRegistered.validateRequestUriResponse(requestUriResponse: requestUriResponse,walletNonce: "mock-nonce", isMismatchedAcceptableType: true)) { error in
//            assertOpenID4VPException(error,
//                                     expectedMessage: "Authorization Request must not be signed for given client_id_scheme",
//                                     expectedCode: OpenID4VPErrorCodes.invalidRequest
//            )
//        }
//    }
    
    func testProcessingWalletMetadataSuccessfully() async{
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValueDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, [
            AuthorizationRequestFieldConstants.clientId.rawValue: "mock-client",
        ])) as [String : Any]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(trustedVerifiers: preRegisteredVerifiers, authorizationRequestParameters: authorizationRequestParameters, walletMetadata: walletMetadata, shouldValidateClient: true, setResponseUri: mockSetResponseUri,walletNonce: "mock-nonce", networkManager: mockNetworkManager!)
        
        var expectedWalletMetadata: WalletMetadata = walletMetadata
        expectedWalletMetadata.requestObjectSigningAlgValuesSupported = nil
        
        let processedMetadata = preRegistered.process(walletMetadata: walletMetadata)
        
        assertDictionariesEqual(expected: convertToDictionary(object: expectedWalletMetadata)!, actual: convertToDictionary(object: processedMetadata))
    }

    func testExtractPublicKeyThrowErrorWhenClientMetadataAvailableInAuthorizationRequestParameters() async throws {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValueDraft23 + ["client_metadata"], requestParams: authorizationRequestParamsWithValue) as [String : Any]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(trustedVerifiers: preRegisteredVerifiers, authorizationRequestParameters: authorizationRequestParameters, walletMetadata: walletMetadata, shouldValidateClient: true, setResponseUri: mockSetResponseUri,walletNonce: "mock-nonce", networkManager: mockNetworkManager!)
        
        await XCTAssertAsyncThrowsError(try await preRegistered.extractPublicKey(keyId: "ed-key2", algorithm: "ECDSA")){ error in
            assertOpenID4VPException(error, expectedMessage: "client_metadata available in Authorization Request, cannot be used to verify the signed Authorization Request", expectedCode: OpenID4VPErrorCodes.invalidRequestObject)
        }
    }
    
    func testExtractPublicKeyThrowErrorWhenPreRegisteredClientNotAvailable() async throws {
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValueDraft23, requestParams: mergeMaps(authorizationRequestParamsWithValue, ["client_id": "untrusted-client"])) as [String : Any]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(trustedVerifiers: preRegisteredVerifiers, authorizationRequestParameters: authorizationRequestParameters, walletMetadata: walletMetadata, shouldValidateClient: true, setResponseUri: mockSetResponseUri,walletNonce: "mock-nonce", networkManager: mockNetworkManager!)
        
        await XCTAssertAsyncThrowsError(try await preRegistered.extractPublicKey(keyId: "ed-key2", algorithm: "ECDSA")){ error in
            assertOpenID4VPException(error, expectedMessage: "Public key extraction failed for keyId = ed-key2, algorithm: ECDSA", expectedCode: OpenID4VPErrorCodes.invalidRequestObject)
        }
    }
    
    // clientMetadata available for trusted verifiers does not have jwks
    func testExtractPublicKeyThrowErrorWhenJwksNotAvailable() async throws {
        let trustedVerifiers = [
            Verifier(clientId: "mock-client", responseUris: ["https://mock-verifier.com"], clientMetadata: ClientMetadata(vpFormats: [
                "ldp_vp": [
                    "proof_type": [
                        "Ed25519Signature2018",
                        "Ed25519Signature2020"
                    ]
                ]
            ]))
        ]
        let authorizationRequestParameters: [String : Any] = createAuthorizationRequest(paramList: authRequestWithPreRegisteredByValueDraft23 , requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdDraft23)) as [String : Any]
        let preRegistered = PreRegisteredSchemeAuthorizationRequestHandler(trustedVerifiers: trustedVerifiers, authorizationRequestParameters: authorizationRequestParameters, walletMetadata: walletMetadata, shouldValidateClient: true, setResponseUri: mockSetResponseUri,walletNonce: "mock-nonce", networkManager: mockNetworkManager!)
        
        
        await XCTAssertAsyncThrowsError(try await preRegistered.extractPublicKey(keyId: "ed-key2", algorithm: "EdDSA")){ error in
            assertOpenID4VPException(error, expectedMessage: "jwks not available in pre-registered client_metadata to verify the signed Authorization Request", expectedCode: OpenID4VPErrorCodes.invalidRequestObject)
        }
    }
}
