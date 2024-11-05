import XCTest
@testable import OpenID4VP

class OpenID4VPTests: XCTestCase {
    var openID4VP: OpenID4VP!
    var mockNetworkManager: MockNetworkManager!

    let authorizationRequest = AuthorizationRequest(
        clientId: "client_id",
        presentationDefinition: "presentationDefinition" as String,
        responseType: "responseType",
        responseMode: "responseMode",
        nonce: "nonce",
        state: "state",
        responseUri: "https://example.com",
        clientMetadata: "clientMetaData" as String
    )

    let jws = "wemcn3234ns"
    let signatureAlgoType = "RsaSignature2018"
    let publicKey = "MIICCgKCAgEA0IEd3E5CvLAbGvr/ysYT2TLE7WDrPBHGk8pwGqVvlrrFtZJ9wT8E"
    let domain = "https://example"
    let descriptorMap: [DescriptorMap] = [
        DescriptorMap(id: "bank_input", format: .ldp_vc, path: "$.verifiableCredential[0]"),
        DescriptorMap(id: "bank_input", format: .ldp_vc, path: "$.verifiableCredential[1]")
    ]
    
    let decodedPresentationDefinition = "{\"id\":\"#2345333\",\"input_descriptors\":[{\"id\":\"banking_input_1\",\"name\":\"Bank Account Information\",\"purpose\":\"We can\",\"constraints\":{\"fields\":[{\"path\":[\"$.crede\"],\"purpose\":\"We can use for  # verification purpose # for anything\",\"filter\":{\"type\":\"string\",\"pattern\":\"^$\"}},{\"path\":[\"$.vc.credential\",\"$.vc.credentialSubject.account[*].route\",\"$.account[*].route\"],\"purpose\":\"We can use for verification purpose\",\"filter\":{\"type\":\"string\",\"pattern\":\"^\"}}]}}]}"
    
    let decodedClientMetadata =
        "{\"name\":\"dummyClient\"}"

    let vpToken = VpTokenForSigning(verifiableCredential: ["VC1", "VC2"],holder: "")

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
    
    let testValidEncodedVpRequest = "OPENID4VP://authorize?Y2xpZW50X2lkPWh0dHBzOi8vaW5qaXZlcmlmeS5kZXYyLm1vc2lwLm5ldCZwcmVzZW50YXRpb25fZGVmaW5pdGlvbj17ImlkIjoiIzIzNDUzMzMiLCJpbnB1dF9kZXNjcmlwdG9ycyI6W3siaWQiOiJiYW5raW5nX2lucHV0XzEiLCJmb3JtYXQiOiB7ImxkcF92YyI6IHsicHJvb2ZfdHlwZSI6IFsiRWQyNTUxOVNpZ25hdHVyZTIwMTgiXX19LCJuYW1lIjoiQmFuayBBY2NvdW50IEluZm9ybWF0aW9uIiwicHVycG9zZSI6IldlIGNhbiBvbmx5IHJlbWl0IHBheW1lbnQgdG8gYSBjdXJyZW50bHktdmFsaWQgYmFuayBhY2NvdW50IGluIHRoZSBVUywgRnJhbmNlLCBvciBHZXJtYW55LCBzdWJtaXR0ZWQgYXMgYW4gQUJBIEFjY3Qgb3IgSUJBTi4iLCJjb25zdHJhaW50cyI6eyJmaWVsZHMiOlt7InBhdGgiOlsiJC5jcmVkZSJdLCJwdXJwb3NlIjoiV2UgY2FuIHVzZSBmb3IgICMgdmVyaWZpY2F0aW9uIHB1cnBvc2UgIyBmb3IgYW55dGhpbmciLCJmaWx0ZXIiOnsidHlwZSI6InN0cmluZyIsInBhdHRlcm4iOiJeWzAtOV17OX18XihbYS16QS1aXSl7NH0oW2EtekEtWl0pezJ9KFswLTlhLXpBLVpdKXsyfShbMC05YS16QS1aXXszfSk/JCJ9fSx7InBhdGgiOlsiJC52Yy5jcmVkZW50aWFsIiwiJC52Yy5jcmVkZW50aWFsU3ViamVjdC5hY2NvdW50WypdLnJvdXRlIiwiJC5hY2NvdW50WypdLnJvdXRlIl0sInB1cnBvc2UiOiJXZSBjYW4gdXNlIGZvciB2ZXJpZmljYXRpb24gcHVycG9zZSIsImZpbHRlciI6eyJ0eXBlIjoic3RyaW5nIiwicGF0dGVybiI6Il5bMC05XXs5fXxeKFthLXpBLVpdKXs0fShbYS16QS1aXSl7Mn0oWzAtOWEtekEtWl0pezJ9KFswLTlhLXpBLVpdezN9KT8kIn19XX19XX0mcmVzcG9uc2VfdHlwZT12cF90b2tlbiZyZXNwb25zZV9tb2RlPWRpcmVjdF9wb3N0Jm5vbmNlPVZiUlJCL0xUeExpWG1WTlp1eU1POEE9PSZzdGF0ZT0rbVJRZTFkNnBCb0pxRjZBYjI4a2xnPT0mcmVzcG9uc2VfdXJpPWh0dHBzOi8vaW5qaXZlcmlmeS5kZXYyLm1vc2lwLm5ldC9yZWRpcmVjdCZjbGllbnRfbWV0YWRhdGE9eyJuYW1lIjoiSW5qaSBWZXJpZnkifQ=="

    let testInvalidPresentationDefinitionVpRequest = "OPENID4VP://authorize?Y2xpZW50X2lkPWh0dHBzOi8vaW5qaXZlcmlmeS5kZXYyLm1vc2lwLm5ldCZwcmVzZW50YXRpb25fZGVmaW5pdGlvbj17ImlucHV0X2Rlc2NyaXB0b3JzIjpbXX0mcmVzcG9uc2VfdHlwZT12cF90b2tlbiZyZXNwb25zZV9tb2RlPWRpcmVjdF9wb3N0Jm5vbmNlPVZiUlJCL0xUeExpWG1WTlp1eU1POEE9PSZzdGF0ZT0rbVJRZTFkNnBCb0pxRjZBYjI4a2xnPT0mcmVzcG9uc2VfdXJpPWh0dHBzOi8vaW5qaXZlcmlmeS5kZXYyLm1vc2lwLm5ldC9yZWRpcmVjdA=="

    let invalidVpRequest = "OPENID4VP://authorize?Y2xpZW50X2lkPWh0dHBzOi8vaW5qaXZlcmlmeS5kZXYyLm1vc2lwLm5ldCZwcmVzZW50YXRpb25fZGVmaW5pdGlvbj17ImlucHV0X2Rlc2NyaXB0b3JzIjpbXX0mcmVzcG9uc2VfdHlwZT12cF90b2tlbiZyZXNwb25zZV9tb2RlPWRpcmVjdF9wb3N0Jm5vbmNlPVZiUlJCL0xUeExpWG1WTlp1eU1POEE9PSZzdGF0ZT0rbVJRZTFkNnBCb0pxRjZBYjI4a2xnPT0mcmVzcG9uc2VfdXJpPWh0dHBzOi8vaW5qaXZlcmlmeS5kZXYyLm1vc2lwLm5ldC9yZWRpcmVjdA=="

    func testReturnDataForValidRequest() async {

        let verifiers = createVerifiers(from: testVerifierList)

        let decoded: Any?

        do {
            decoded = try await openID4VP.authenticateVerifier(encodedAuthorizationRequest: testValidEncodedVpRequest, trustedVerifierJSON: verifiers)
        } catch {
            decoded = nil
        }
        XCTAssertTrue(decoded is AuthorizationRequest, "decodedResponse should be an instance of AuthenticationResponse")
        XCTAssertTrue(decoded != nil, "decodedResponse should not be null")
    }

    func testMissingPresentationDefinitionFields() async {
        let verifiers = createVerifiers(from: testVerifierList)

        let error = await Task {
            try await openID4VP.authenticateVerifier(encodedAuthorizationRequest: testInvalidPresentationDefinitionVpRequest, trustedVerifierJSON: verifiers)
        }.result

        switch error {
        case .failure(let thrownError):
            XCTAssertEqual(thrownError as? AuthorizationRequestException, AuthorizationRequestException.invalidPresentationDefinition)
        case .success: break
        }
    }

    func testMissingRequiredFieldsInRequest() async {

        let verifiers = createVerifiers(from: testVerifierList)
        
        let error = await Task {
            try await openID4VP.authenticateVerifier(encodedAuthorizationRequest: invalidVpRequest, trustedVerifierJSON: verifiers)
        }.result

        switch error {
        case .failure(let thrownError):
            XCTAssertEqual(thrownError as? AuthorizationRequestException, AuthorizationRequestException.invalidPresentationDefinition)
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

        let vcResponseMetaData = VPResponseMetadata(jws: jws, signatureAlgorithm: signatureAlgoType, publicKey: publicKey, domain: domain)
        
        let response = try await openID4VP.shareVerifiablePresentation(vpResponseMetadata: vcResponseMetaData)
        
        XCTAssertEqual(response, "Success: Request completed successfully.")
    }

    func testSendVpFailure() async {

        do{ let presentationDefinition: PresentationDefinition = try PresentationDefinitionValidator.validate(presentatioDefinition: decodedPresentationDefinition)
            
            openID4VP.updateAuthorizationRequest(presentationDefinition, nil)
        }catch{}
        
        let errorMessage = "Network Request failed with error response: response"
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
