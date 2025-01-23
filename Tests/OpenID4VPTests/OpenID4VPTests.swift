import XCTest
@testable import OpenID4VP

class OpenID4VPTests: XCTestCase {
    var openID4VP: OpenID4VP!
    var mockNetworkManager: MockNetworkManager!

    let authorizationRequest = AuthorizationRequest(
        clientId: "client_id",
        clientIdScheme: "123",
        presentationDefinition: "presentationDefinition" as String,
        responseType: "responseType",
        responseMode: "responseMode",
        nonce: "nonce",
        state: "state", 
        redirectUri: "1234",
        responseUri: "https://example.com",
        clientMetadata: "clientMetaData" as String
    )

    let jws = "wemcn3234ns"
    let signatureAlgoType = "RsaSignature2018"
    let publicKey = "-----BEGIN PUBLIC KEY-----\\nMIIBIjANBggvSPv73S\\nG5ToTt07NZPdKDrg9lSjetZup39oj12u0YoyRMlMhY0xYL6c8X1BexM7Wlp+c13o\\n1QIDAQAB\\n-----END PUBLIC KEY-----\\n"
    let domain = "https://example"
    let descriptorMap: [DescriptorMap] = [
        DescriptorMap(id: "bank_input", format: .ldp_vc, path: "$.verifiableCredential[0]"),
        DescriptorMap(id: "bank_input", format: .ldp_vc, path: "$.verifiableCredential[1]")
    ]
    
    let decodedPresentationDefinition = "{\"id\":\"#2345333\",\"input_descriptors\":[{\"id\":\"banking_input_1\",\"name\":\"Bank Account Information\",\"purpose\":\"We can\",\"constraints\":{\"fields\":[{\"path\":[\"$.crede\"],\"purpose\":\"We can use for  # verification purpose # for anything\",\"filter\":{\"type\":\"string\",\"pattern\":\"^$\"}},{\"path\":[\"$.vc.credential\",\"$.vc.credentialSubject.account[*].route\",\"$.account[*].route\"],\"purpose\":\"We can use for verification purpose\",\"filter\":{\"type\":\"string\",\"pattern\":\"^\"}}]}}]}"
    
    let decodedClientMetadata =
        "{\"name\":\"dummyClient\"}"

    let vpToken = VpTokenForSigning(verifiableCredential: ["VC1", "VC2"],holder: "")
    
    let didResponse = "{\"@context\":\"https://w3id.org/did-resolution/v1\",\"didDocument\":{\"assertionMethod\":[\"did:web:adityankannan-tw.github.io:openid4vp:files#key-0\"],\"service\":[],\"id\":\"did:web:adityankannan-tw.github.io:openid4vp:files\",\"verificationMethod\":[{\"publicKeyMultibase\":\"zCqghiFu9ummQzMop1b6FKWG06xfokGM36GG5uebqLk\",\"controller\":\"did:web:adityankannan-tw.github.io:openid4vp:files\",\"id\":\"did:web:adityankannan-tw.github.io:openid4vp:files#key-0\",\"type\":\"Ed25519VerificationKey2020\",\"@context\":\"https://w3id.org/security/suites/ed25519-2020/v1\"}],\"@context\":[\"https://www.w3.org/ns/did/v1\"],\"alsoKnownAs\":[],\"authentication\":[\"did:web:adityankannan-tw.github.io:openid4vp:files#key-0\"]},\"didResolutionMetadata\":{\"driverDuration\":19,\"contentType\":\"application/did+ld+json\",\"pattern\":\"^(did:web:.+)$\",\"driverUrl\":\"http://uni-resolver-driver-did-uport:8081/1.0/identifiers/\",\"duration\":19,\"did\":{\"didString\":\"did:web:adityankannan-tw.github.io:openid4vp:files\",\"methodSpecificId\":\"adityankannan-tw.github.io:openid4vp:files\",\"method\":\"web\"},\"didUrl\":{\"path\":null,\"fragment\":null,\"query\":null,\"didUrlString\":\"did:web:adityankannan-tw.github.io:openid4vp:files\",\"parameters\":null,\"did\":{\"didString\":\"did:web:adityankannan-tw.github.io:openid4vp:files\",\"methodSpecificId\":\"adityankannan-tw.github.io:openid4vp:files\",\"method\":\"web\"}}},\"didDocumentMetadata\":{}}"

    override func setUp() {
        super.setUp()
        mockNetworkManager = MockNetworkManager()
        
        openID4VP = OpenID4VP(traceabilityId: "AXESWSAW123", networkManager: mockNetworkManager)
        openID4VP.setResponseUri("https://example.com")
        openID4VP.authorizationRequest = authorizationRequest
        
        AuthorizationResponse.descriptorMap = descriptorMap
        AuthorizationResponse.vpTokenForSigning = vpToken
    }

    override func tearDown() {
        openID4VP = nil
        mockNetworkManager = nil
        super.tearDown()
    }

    let testVerifierList:  [[String: Any]]  = [
        [
            "client_id": "https://injiverify.dev2.mosip.net",
            "response_uris": [
                "https://injiverify.qa-inji.mosip.net/redirect",
                "https://injiverify.dev2.mosip.net/redirect"
            ]
        ],
        [
            "client_id": "https://injiverify.dev1.mosip.net",
            "response_uris": [
                "https://injiverify.qa-inji.mosip.net/redirect",
                "https://injiverify.dev1.mosip.net/redirect"
            ]
        ]
    ]
    
    // base64 -> client_id_scheme = redirect_uri
    let testValidBase64EncodedVpRequestWithRedirectUri = "OPENID4VP://authorize?Y2xpZW50X2lkPWh0dHBzOi8vaW5qaXZlcmlmeS5kZXYyLm1vc2lwLm5ldCZjbGllbnRfaWRfc2NoZW1lPXJlZGlyZWN0X3VyaSZyZWRpcmVjdF91cmk9aHR0cHM6Ly9pbmppdmVyaWZ5LmRldjIubW9zaXAubmV0JnByZXNlbnRhdGlvbl9kZWZpbml0aW9uPXsiaWQiOiIxMjMiLCJpbnB1dF9kZXNjcmlwdG9ycyI6W3siaWQiOiJiYW5raW5nX2lucHV0XzEiLCJmb3JtYXQiOiB7ImxkcF92YyI6IHsicHJvb2ZfdHlwZSI6IFsiRWQyNTUxOVNpZ25hdHVyZTIwMTgiXX19LCJuYW1lIjoiQmFuayBBY2NvdW50IEluZm9ybWF0aW9uIiwicHVycG9zZSI6ImhpaWlpIiwiY29uc3RyYWludHMiOnsiZmllbGRzIjpbeyJwYXRoIjpbIiQuY3JlZGUiXSwicHVycG9zZSI6IldlIGNhbiB1c2UgZm9yICAjIHZlcmlmaWNhdGlvbiBwdXJwb3NlICMgZm9yIGFueXRoaW5nIiwiZmlsdGVyIjp7InR5cGUiOiJzdHJpbmciLCJwYXR0ZXJuIjoiXlswLTldezl9fF4oW2EtekEtWl0pezR9KFthLXpBLVpdKXsyfShbMC05YS16QS1aXSl7Mn0oWzAtOWEtekEtWl17M30pPyQifX0seyJwYXRoIjpbIiQudmMuY3JlZGVudGlhbCIsIiQudmMuY3JlZGVudGlhbFN1YmplY3QuYWNjb3VudFsqXS5yb3V0ZSIsIiQuYWNjb3VudFsqXS5yb3V0ZSJdLCJwdXJwb3NlIjoiV2UgY2FuIHVzZSBmb3IgdmVyaWZpY2F0aW9uIHB1cnBvc2UiLCJmaWx0ZXIiOnsidHlwZSI6InN0cmluZyIsInBhdHRlcm4iOiJeWzAtOV17OX18XihbYS16QS1aXSl7NH0oW2EtekEtWl0pezJ9KFswLTlhLXpBLVpdKXsyfShbMC05YS16QS1aXXszfSk/JCJ9fV19fV19JnJlc3BvbnNlX3R5cGU9dnBfdG9rZW4mbm9uY2U9VmJSUkIvTFR4TGlYbVZOWnV5TU84QT09JnN0YXRlPSttUlFlMWQ2cEJvSnFGNkFiMjhrbGc9PSZjbGllbnRfbWV0YWRhdGE9eyJjbGllbnRfbmFtZSI6IkluamkgVmVyaWZ5In0="
    
    // base64 -> client_id_scheme = pre-registered
    let testValidBase64EncodedVpRequestWithResponseUri = "OPENID4VP://authorize?Y2xpZW50X2lkPWh0dHBzOi8vaW5qaXZlcmlmeS5kZXYyLm1vc2lwLm5ldCZjbGllbnRfaWRfc2NoZW1lPXByZS1yZWdpc3RlcmVkJnByZXNlbnRhdGlvbl9kZWZpbml0aW9uPXsiaWQiOiIxMjMiLCJpbnB1dF9kZXNjcmlwdG9ycyI6W3siaWQiOiJiYW5raW5nX2lucHV0XzEiLCJmb3JtYXQiOiB7ImxkcF92YyI6IHsicHJvb2ZfdHlwZSI6IFsiRWQyNTUxOVNpZ25hdHVyZTIwMTgiXX19LCJuYW1lIjoiQmFuayBBY2NvdW50IEluZm9ybWF0aW9uIiwicHVycG9zZSI6ImhpaWlpIiwiY29uc3RyYWludHMiOnsiZmllbGRzIjpbeyJwYXRoIjpbIiQuY3JlZGUiXSwicHVycG9zZSI6IldlIGNhbiB1c2UgZm9yICAjIHZlcmlmaWNhdGlvbiBwdXJwb3NlICMgZm9yIGFueXRoaW5nIiwiZmlsdGVyIjp7InR5cGUiOiJzdHJpbmciLCJwYXR0ZXJuIjoiXlswLTldezl9fF4oW2EtekEtWl0pezR9KFthLXpBLVpdKXsyfShbMC05YS16QS1aXSl7Mn0oWzAtOWEtekEtWl17M30pPyQifX0seyJwYXRoIjpbIiQudmMuY3JlZGVudGlhbCIsIiQudmMuY3JlZGVudGlhbFN1YmplY3QuYWNjb3VudFsqXS5yb3V0ZSIsIiQuYWNjb3VudFsqXS5yb3V0ZSJdLCJwdXJwb3NlIjoiV2UgY2FuIHVzZSBmb3IgdmVyaWZpY2F0aW9uIHB1cnBvc2UiLCJmaWx0ZXIiOnsidHlwZSI6InN0cmluZyIsInBhdHRlcm4iOiJeWzAtOV17OX18XihbYS16QS1aXSl7NH0oW2EtekEtWl0pezJ9KFswLTlhLXpBLVpdKXsyfShbMC05YS16QS1aXXszfSk/JCJ9fV19fV19JnJlc3BvbnNlX3R5cGU9dnBfdG9rZW4mcmVzcG9uc2VfbW9kZT1kaXJlY3RfcG9zdCZub25jZT1WYlJSQi9MVHhMaVhtVk5adXlNTzhBPT0mc3RhdGU9K21SUWUxZDZwQm9KcUY2QWIyOGtsZz09JnJlc3BvbnNlX3VyaT1odHRwczovL2luaml2ZXJpZnkuZGV2Mi5tb3NpcC5uZXQvcmVkaXJlY3QmY2xpZW50X21ldGFkYXRhPXsiY2xpZW50X25hbWUiOiJJbmppIFZlcmlmeSJ9"

    // jwt -> client_id_scheme = did
    let testValidSignedVpRequestWithDid = "OPENID4VP://authorize?eyJ0eXAiOiJvYXV0aC1hdXRoei1yZXErand0IiwiYWxnIjoiRWREU0EiLCJraWQiOiJkaWQ6d2ViOmFkaXR5YW5rYW5uYW4tdHcuZ2l0aHViLmlvOm9wZW5pZDR2cDpmaWxlcyNrZXktMCJ9.eyJjbGllbnRfaWQiOiJkaWQ6d2ViOmFkaXR5YW5rYW5uYW4tdHcuZ2l0aHViLmlvOm9wZW5pZDR2cDpmaWxlcyIsImNsaWVudF9pZF9zY2hlbWUiOiJkaWQiLCJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJyZWRpcmVjdF91cmkiOiJodHRwczovL2NsaWVudC5leGFtcGxlLm9yZy9jYWxsYmFjayIsIm5vbmNlIjoibi0wUzZfV3pBMk1qIiwic3RhdGUiOiJuZTI5MmV3d2l3aWl3aSIsInByZXNlbnRhdGlvbl9kZWZpbml0aW9uIjoie1wiaWRcIjpcIjEyM1wiLFwiaW5wdXRfZGVzY3JpcHRvcnNcIjpbe1wiaWRcIjpcImJhbmtpbmdfaW5wdXRfMVwiLFwiZm9ybWF0XCI6e1wibGRwX3ZjXCI6e1wicHJvb2ZfdHlwZVwiOltcIkVkMjU1MTlTaWduYXR1cmUyMDE4XCJdfX0sXCJuYW1lXCI6XCJCYW5rQWNjb3VudEluZm9ybWF0aW9uXCIsXCJwdXJwb3NlXCI6XCJoaWlpaVwiLFwiY29uc3RyYWludHNcIjp7XCJmaWVsZHNcIjpbe1wicGF0aFwiOltcIiQuY3JlZGVcIl0sXCJwdXJwb3NlXCI6XCJXZWNhbnVzZWZvciN2ZXJpZmljYXRpb25wdXJwb3NlI2ZvcmFueXRoaW5nXCIsXCJmaWx0ZXJcIjp7XCJ0eXBlXCI6XCJzdHJpbmdcIixcInBhdHRlcm5cIjpcIl5bMC05XXs5fXxeKFthLXpBLVpdKXs0fShbYS16QS1aXSl7Mn0oWzAtOWEtekEtWl0pezJ9KFswLTlhLXpBLVpdezN9KT8kXCJ9fSx7XCJwYXRoXCI6W1wiJC52Yy5jcmVkZW50aWFsXCIsXCIkLnZjLmNyZWRlbnRpYWxTdWJqZWN0LmFjY291bnRbKl0ucm91dGVcIixcIiQuYWNjb3VudFsqXS5yb3V0ZVwiXSxcInB1cnBvc2VcIjpcIldlY2FudXNlZm9ydmVyaWZpY2F0aW9ucHVycG9zZVwiLFwiZmlsdGVyXCI6e1widHlwZVwiOlwic3RyaW5nXCIsXCJwYXR0ZXJuXCI6XCJeWzAtOV17OX18XihbYS16QS1aXSl7NH0oW2EtekEtWl0pezJ9KFswLTlhLXpBLVpdKXsyfShbMC05YS16QS1aXXszfSk_JFwifX1dfX1dfSIsImNsaWVudF9tZXRhZGF0YSI6IntcImNsaWVudF9uYW1lXCI6XCJhZGl0eWFuXCJ9In0.l12/pXHDNaGiBDsHAJAn52DFZ1rzAuEpOsPZOt9k/0l9LBTN9SSAe0HXFKN+eoeDygo1d05kSW08Ob8SCUz6Dg=="
    
    let testInvalidPresentationDefinitionVpRequest = "OPENID4VP://authorize?Y2xpZW50X2lkPWh0dHBzOi8vaW5qaXZlcmlmeS5kZXYyLm1vc2lwLm5ldCZjbGllbnRfaWRfc2NoZW1lPXByZS1yZWdpc3RlcmVkJnByZXNlbnRhdGlvbl9kZWZpbml0aW9uPXsiaW5wdXRfZGVzY3JpcHRvcnMiOltdfSZyZXNwb25zZV90eXBlPXZwX3Rva2VuJnJlc3BvbnNlX21vZGU9ZGlyZWN0X3Bvc3Qmbm9uY2U9VmJSUkIvTFR4TGlYbVZOWnV5TU84QT09JnN0YXRlPSttUlFlMWQ2cEJvSnFGNkFiMjhrbGc9PSZyZXNwb25zZV91cmk9aHR0cHM6Ly9pbmppdmVyaWZ5LmRldjIubW9zaXAubmV0L3JlZGlyZWN0"

    let invalidVpRequest = "OPENID4VP://authorize?Y2xpZW50X2lkPWh0dHBzOi8vaW5qaXZlcmlmeS5kZXYyLm1vc2lwLm5ldCZwcmVzZW50YXRpb25fZGVmaW5pdGlvbj17ImlucHV0X2Rlc2NyaXB0b3JzIjpbXX0mcmVzcG9uc2VfdHlwZT12cF90b2tlbiZyZXNwb25zZV9tb2RlPWRpcmVjdF9wb3N0Jm5vbmNlPVZiUlJCL0xUeExpWG1WTlp1eU1POEE9PSZzdGF0ZT0rbVJRZTFkNnBCb0pxRjZBYjI4a2xnPT0mcmVzcG9uc2VfdXJpPWh0dHBzOi8vaW5qaXZlcmlmeS5kZXYyLm1vc2lwLm5ldC9yZWRpcmVjdA=="
    
    let invalidClientMetadata =
    "OPENID4VP://authorize?Y2xpZW50X2lkPWh0dHBzOi8vaW5qaXZlcmlmeS5kZXYyLm1vc2lwLm5ldCZjbGllbnRfaWRfc2NoZW1lPXByZS1yZWdpc3RlcmVkJnByZXNlbnRhdGlvbl9kZWZpbml0aW9uPXsiaWQiOiIjMjM0NTMzMyIsImlucHV0X2Rlc2NyaXB0b3JzIjpbeyJpZCI6ImJhbmtpbmdfaW5wdXRfMSIsImZvcm1hdCI6IHsibGRwX3ZjIjogeyJwcm9vZl90eXBlIjogWyJFZDI1NTE5U2lnbmF0dXJlMjAxOCJdfX0sIm5hbWUiOiJCYW5rIEFjY291bnQgSW5mb3JtYXRpb24iLCJwdXJwb3NlIjoiV2UgY2FuIG9ubHkgcmVtaXQgcGF5bWVudCB0byBhIGN1cnJlbnRseS12YWxpZCBiYW5rIGFjY291bnQgaW4gdGhlIFVTLCBGcmFuY2UsIG9yIEdlcm1hbnksIHN1Ym1pdHRlZCBhcyBhbiBBQkEgQWNjdCBvciBJQkFOLiIsImNvbnN0cmFpbnRzIjp7ImZpZWxkcyI6W3sicGF0aCI6WyIkLmNyZWRlIl0sInB1cnBvc2UiOiJXZSBjYW4gdXNlIGZvciAgIyB2ZXJpZmljYXRpb24gcHVycG9zZSAjIGZvciBhbnl0aGluZyIsImZpbHRlciI6eyJ0eXBlIjoic3RyaW5nIiwicGF0dGVybiI6Il5bMC05XXs5fXxeKFthLXpBLVpdKXs0fShbYS16QS1aXSl7Mn0oWzAtOWEtekEtWl0pezJ9KFswLTlhLXpBLVpdezN9KT8kIn19LHsicGF0aCI6WyIkLnZjLmNyZWRlbnRpYWwiLCIkLnZjLmNyZWRlbnRpYWxTdWJqZWN0LmFjY291bnRbKl0ucm91dGUiLCIkLmFjY291bnRbKl0ucm91dGUiXSwicHVycG9zZSI6IldlIGNhbiB1c2UgZm9yIHZlcmlmaWNhdGlvbiBwdXJwb3NlIiwiZmlsdGVyIjp7InR5cGUiOiJzdHJpbmciLCJwYXR0ZXJuIjoiXlswLTldezl9fF4oW2EtekEtWl0pezR9KFthLXpBLVpdKXsyfShbMC05YS16QS1aXSl7Mn0oWzAtOWEtekEtWl17M30pPyQifX1dfX1dfSZyZXNwb25zZV90eXBlPXZwX3Rva2VuJnJlc3BvbnNlX21vZGU9ZGlyZWN0X3Bvc3Qmbm9uY2U9VmJSUkIvTFR4TGlYbVZOWnV5TU84QT09JnN0YXRlPSttUlFlMWQ2cEJvSnFGNkFiMjhrbGc9PSZyZXNwb25zZV91cmk9aHR0cHM6Ly9pbmppdmVyaWZ5LmRldjIubW9zaXAubmV0L3JlZGlyZWN0JmNsaWVudF9tZXRhZGF0YT17fQ=="

    // base64 -> client_id_scheme = redirect_uri
    func testReturnDataForValidRequestWithRedirectUri() async {

        let verifiers = createVerifiers(from: testVerifierList)

        let decoded: Any?

        do {
            decoded = try await openID4VP.authenticateVerifier(encodedAuthorizationRequest: testValidBase64EncodedVpRequestWithRedirectUri, trustedVerifierJSON: verifiers, shouldValidateClient: true)
        } catch {
            decoded = nil
        }
        XCTAssertTrue(decoded is AuthorizationRequest, "decodedResponse should be an instance of AuthenticationResponse")
        XCTAssertTrue(decoded != nil, "decodedResponse should not be null")
    }
    
    // base64 -> client_id_scheme = response_uri
    func testReturnDataForValidRequestWithResponseUri() async {

        let verifiers = createVerifiers(from: testVerifierList)

        let decoded: Any?

        do {
            decoded = try await openID4VP.authenticateVerifier(encodedAuthorizationRequest: testValidBase64EncodedVpRequestWithResponseUri, trustedVerifierJSON: verifiers, shouldValidateClient: true)
        } catch {
            decoded = nil
        }
        XCTAssertTrue(decoded is AuthorizationRequest, "decodedResponse should be an instance of AuthenticationResponse")
        XCTAssertTrue(decoded != nil, "decodedResponse should not be null")
    }
    
    // jwt -> client_id_scheme = did
    func testReturnDataForValidRequestWithDid() async {

           mockNetworkManager.response = didResponse

            let verifiers = createVerifiers(from: testVerifierList)

        let decoded: Any?

        do {
            decoded = try await openID4VP.authenticateVerifier(encodedAuthorizationRequest: testValidSignedVpRequestWithDid, trustedVerifierJSON: verifiers, shouldValidateClient: true)
        } catch {
            decoded = nil
        }
        XCTAssertTrue(decoded is AuthorizationRequest, "decodedResponse should be an instance of AuthenticationResponse")
        XCTAssertTrue(decoded != nil, "decodedResponse should not be null")
    }
    
    func testReturnDataForValidRequestWhenClientValidationIsFalse() async {

        let verifiers = createVerifiers(from: testVerifierList)

        let decoded: Any?

        do {
            decoded = try await openID4VP.authenticateVerifier(encodedAuthorizationRequest: testValidBase64EncodedVpRequestWithRedirectUri, trustedVerifierJSON: verifiers, shouldValidateClient: false)
        } catch {
            decoded = nil
        }
        XCTAssertTrue(decoded is AuthorizationRequest, "decodedResponse should be an instance of AuthenticationResponse")
        XCTAssertTrue(decoded != nil, "decodedResponse should not be null")
    }

    func testMissingPresentationDefinitionFields() async {
        let verifiers = createVerifiers(from: testVerifierList)

        let error = await Task {
            try await openID4VP.authenticateVerifier(encodedAuthorizationRequest: testInvalidPresentationDefinitionVpRequest, trustedVerifierJSON: verifiers, shouldValidateClient: true)
        }.result

        switch error {
        case .failure(let thrownError):
            let expectedErrorMessage = "Missing Input: presentation_definition->id param is required"
            XCTAssertEqual(thrownError.localizedDescription,expectedErrorMessage)
        case .success: break
        }
    }

    func testMissingClientMetadataRequiredFieldsInRequest() async {

        let verifiers = createVerifiers(from: testVerifierList)
        
        let error = await Task {
            try await openID4VP.authenticateVerifier(encodedAuthorizationRequest: invalidClientMetadata, trustedVerifierJSON: verifiers, shouldValidateClient: true)
        }.result

        switch error {
        case .failure(let thrownError):
            let expectedErrorMessage = "Missing Input: client_metadata-> client_name param is required"
            XCTAssertEqual(thrownError.localizedDescription, expectedErrorMessage)
        case .success: break
        }
    }

    func testUUIDGeneration() {

        let vpToken = UUIDGenerator.generateUUID()
        let presentationSubmissionId = UUIDGenerator.generateUUID()
        let presentationSubmission = PresentationSubmission(definition_id: "", descriptor_map: AuthorizationResponse.descriptorMap!)

        XCTAssertNotNil(vpToken,presentationSubmissionId)
        XCTAssertNotNil(presentationSubmission.id)
    }

    func testShareVerifiablePresentation() async{
        let credentialsMap: [String: [String]] = ["bank_input":["VC1","VC2"]]
        let received: String?

        do {
            received = try await openID4VP.constructVerifiablePresentationToken(credentialsMap: credentialsMap)
        }catch{
            received = nil
        }
        XCTAssertNotNil(received,  "The response should not be nil for valid credentials map")
    }

    func testSendVpSuccess() async throws {
        
        do{ let presentationDefinition: PresentationDefinition = try PresentationDefinitionValidator.validate(presentatioDefinition: decodedPresentationDefinition)
            
            openID4VP.updateAuthorizationRequest(presentationDefinition, nil)
        }catch{}

        mockNetworkManager.response = "Success: Request completed successfully."
        
        let vcResponseMetaData = VPResponseMetadata(jws: jws, signatureAlgorithm: signatureAlgoType, publicKey: publicKey, domain: domain)
        
        let response = try await openID4VP.shareVerifiablePresentation(vpResponseMetadata: vcResponseMetaData)
        
        XCTAssertEqual(response, "Success: Request completed successfully.")
    }

    func testSendVpFailure() async {

        do{ let presentationDefinition: PresentationDefinition = try PresentationDefinitionValidator.validate(presentatioDefinition: decodedPresentationDefinition)
            
            openID4VP.updateAuthorizationRequest(presentationDefinition, nil)
        }catch{}
        
        let errorMessage = "Network Request failed with error"
        mockNetworkManager.error = NetworkRequestException.networkRequestFailed(message: errorMessage)

        let vcResponseMetaData = VPResponseMetadata(jws: jws, signatureAlgorithm: signatureAlgoType, publicKey: publicKey, domain: domain)


        do {
            let _ = try await openID4VP.shareVerifiablePresentation(vpResponseMetadata: vcResponseMetaData)
        } catch let error as NetworkRequestException {
            switch error {
            case .networkRequestFailed(let message):
                XCTAssertEqual(message, errorMessage, "Unexpected error message: \(message)")
            default:
                XCTFail("Expected NetworkRequestException.networkRequestFailed but got \(error)")
            }
        } catch {
        }
    }
}
