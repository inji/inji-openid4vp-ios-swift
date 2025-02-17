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
        responseUri: "https://mock-verifier.com",
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

    override func setUp() {
        super.setUp()
        mockNetworkManager = MockNetworkManager()
        
        openID4VP = OpenID4VP(traceabilityId: "AXESWSAW123", networkManager: mockNetworkManager)
        openID4VP.setResponseUri("https://mock-verifier.com")
        openID4VP.authorizationRequest = authorizationRequest
        
        AuthorizationResponse.descriptorMap = descriptorMap
        AuthorizationResponse.vpTokenForSigning = vpToken
    }

    override func tearDown() {
        openID4VP = nil
        mockNetworkManager = nil
        super.tearDown()
    }

    // base64 -> client_id_scheme = redirect_uri
    func testReturnDataForValidRequestWithRedirectUri() async {
        do {
            let decoded = try await openID4VP.authenticateVerifier(encodedAuthorizationRequest: testValidBase64EncodedVpRequestWithRedirectUri, trustedVerifierJSON: preRegisteredVerifiers, shouldValidateClient: true)
            XCTAssertTrue(decoded is AuthorizationRequest, "decodedResponse should be an instance of AuthenticationResponse")
        } catch {
            XCTFail("Should not get error but got error - \(error)")
        }
    }
    
    // base64 -> client_id_scheme = redirect_uri, client id not equal to redirect uri
    func testVpRequestWithRedirectUriAndClientIdNotEqualtoRedirectUri() async {
        let error = await Task {
        try await openID4VP.authenticateVerifier(encodedAuthorizationRequest: testVpRequestWithRedirectUriAndClientIdNotEqual, trustedVerifierJSON: preRegisteredVerifiers, shouldValidateClient: true)
        }.result
       
        switch error {
        case .failure(let thrownError):
            let expectedErrorMessage = "An unexpected exception occurred: exception type: invalidResponseMode"
            XCTAssertEqual(thrownError.localizedDescription,expectedErrorMessage)
        case .success:
            XCTFail("Expected error - An unexpected exception occurred: exception type: invalidResponseMode but not thrown")
        }
    }
    
    // base64 -> client_id_scheme = response_uri
    func testReturnDataForValidRequestWithResponseUri() async {
        let decoded: Any?

        do {
            decoded = try await openID4VP.authenticateVerifier(encodedAuthorizationRequest: testValidBase64EncodedVpRequestWithResponseUri, trustedVerifierJSON: preRegisteredVerifiers, shouldValidateClient: true)
        } catch {
            decoded = nil
            XCTFail("Should not get error but got error - \(error)")
        }
        XCTAssertTrue(decoded is AuthorizationRequest, "decodedResponse should be an instance of AuthenticationResponse")
        XCTAssertTrue(decoded != nil, "decodedResponse should not be null")
    }
    
    // jwt -> client_id_scheme = did
    func testReturnDataForValidRequestWithDid() async {
        mockNetworkManager.setMockResponse(for: URL(string: "https://mock-verifier.com/verifier/get-auth-request-obj")!,response: validJwtResponse)
        mockNetworkManager.setMockResponse(for: URL(string: "https://resolver.identity.foundation/1.0/identifiers/did:example:123#1")!,response: didResponse)
        
        let decodedAuthorizationRequest: Any?
        do {
            decodedAuthorizationRequest = try await openID4VP.authenticateVerifier(encodedAuthorizationRequest: testValidSignedVpRequestWithDid, trustedVerifierJSON: preRegisteredVerifiers, shouldValidateClient: true)
        } catch {
            decodedAuthorizationRequest = nil
            XCTFail("Should not get error but got error - \(error)")
        }
        
        XCTAssertTrue(decodedAuthorizationRequest is AuthorizationRequest, "decodedResponse should be an instance of AuthenticationResponse")
        XCTAssertTrue(decodedAuthorizationRequest != nil, "decodedResponse should not be null")
    }
    
    // jwt -> client_id_scheme = did, Invalid did
    func testThrowErrorForInValidSignatureInRequest() async {
        mockNetworkManager.setMockResponse(for: URL(string: "https://mock-verifier.com/verifier/get-auth-request-obj")!,response: invalidJwtResponse)
        mockNetworkManager.setMockResponse(for: URL(string: "https://resolver.identity.foundation/1.0/identifiers/did:example:123#1")!,response: didResponse)
        
        let error = await Task {
        try await openID4VP.authenticateVerifier(encodedAuthorizationRequest: testValidSignedVpRequestWithDid, trustedVerifierJSON: preRegisteredVerifiers, shouldValidateClient: true)
        }.result
       
        switch error {
        case .failure(let thrownError):
            let expectedErrorMessage = "Jwt proof verification failed"
            XCTAssertEqual(thrownError.localizedDescription,expectedErrorMessage)
        case .success: 
            XCTFail("Jwt proof verification failed error should have been captured instead it succeeded")
        }
    }
    
    // jwt -> client_id_scheme = did, Mismatching clientId's in QR data and Request Uri response
    //TODO: Skipping this - fix required on JWT verification mock
    func skipped_testThrowErrorIfClientIdIsMismatchingWithQrDataAndRequest() async {
        mockNetworkManager.setMockResponse(for: URL(string: "https://mock-verifier.com/verifier/get-auth-request-obj")!,response: validJwtResponse)
        mockNetworkManager.setMockResponse(for: URL(string: "https://resolver.identity.foundation/1.0/identifiers/did:example:123#1")!,response: didResponse)
        
        let error = await Task {
        try await openID4VP.authenticateVerifier(encodedAuthorizationRequest: testInValidSignedVpRequestWithDidAndClientIdDifferent, trustedVerifierJSON: preRegisteredVerifiers, shouldValidateClient: true)
        }.result
       
        switch error {
        case .failure(let thrownError):
            let expectedErrorMessage = "Client Id is mismatching in QR data and Request Uri response"
            XCTAssertEqual(thrownError.localizedDescription,expectedErrorMessage)
        case .success: break
        }
    }
    
    // jwt -> client_id_scheme = did, Kid is empty in the JWT header
    func testThrowErrorIfKidExtractionFailedFromJwt() async {
        mockNetworkManager.setMockResponse(for: URL(string: "https://mock-verifier.com/verifier/get-auth-request-obj")!,response: invalidJwtResponseWithoutKid)
        mockNetworkManager.setMockResponse(for: URL(string: "https://resolver.identity.foundation/1.0/identifiers/did:example:123#1")!,response: didResponse)
        
        let error = await Task {
        try await openID4VP.authenticateVerifier(encodedAuthorizationRequest: testValidSignedVpRequestWithDid, trustedVerifierJSON: preRegisteredVerifiers, shouldValidateClient: true)
        }.result
       
        switch error {
        case .failure(let thrownError):
            let expectedErrorMessage = "Kid extraction from did document failed"
            XCTAssertEqual(thrownError.localizedDescription,expectedErrorMessage)
        case .success: break
        }
    }
    
    // base64 -> client_id_scheme = redirect_uri, Client id validation is false
    func testReturnDataForValidRequestWhenClientValidationIsFalse() async {
        let decoded: Any?

        do {
            decoded = try await openID4VP.authenticateVerifier(encodedAuthorizationRequest: testValidBase64EncodedVpRequestWithRedirectUri, trustedVerifierJSON: preRegisteredVerifiers, shouldValidateClient: false)
        } catch {
            decoded = nil
            XCTFail("should not get error but got error \(error)")
        }
        XCTAssertTrue(decoded is AuthorizationRequest, "decodedResponse should be an instance of AuthenticationResponse")
        XCTAssertTrue(decoded != nil, "decodedResponse should not be null")
    }

    func testMissingPresentationDefinitionFields() async {
        let error = await Task {
            try await openID4VP.authenticateVerifier(encodedAuthorizationRequest: testInvalidPresentationDefinitionVpRequest, trustedVerifierJSON: preRegisteredVerifiers, shouldValidateClient: true)
        }.result

        switch error {
        case .failure(let thrownError):
            let expectedErrorMessage = "Missing Input: presentation_definition->id param is required"
            XCTAssertEqual(thrownError.localizedDescription,expectedErrorMessage)
        case .success: break
        }
    }

    // base64 -> client_id_scheme = pre_registered, ClientMetadata mandatory values are not present
    func testMissingClientMetadataRequiredFieldsInRequest() async {
        let data = authorizationRequestParamsWithValue
        
        let error = await Task {
            try await openID4VP.authenticateVerifier(encodedAuthorizationRequest: encodedAuthorizationRequestWithInvalidClientMetadata, trustedVerifierJSON: preRegisteredVerifiers, shouldValidateClient: true)
        }.result

        switch error {
        case .failure(let thrownError):
            let expectedErrorMessage = "Invalid Input: client_metadata value cannot be empty or null"
            XCTAssertEqual(thrownError.localizedDescription, expectedErrorMessage)
        case .success: break
        }
    }

    // UUID Generation
    func testUUIDGeneration() {

        let vpToken = UUIDGenerator.generateUUID()
        let presentationSubmissionId = UUIDGenerator.generateUUID()
        let presentationSubmission = PresentationSubmission(definition_id: "", descriptor_map: AuthorizationResponse.descriptorMap!)

        XCTAssertNotNil(vpToken,presentationSubmissionId)
        XCTAssertNotNil(presentationSubmission.id)
    } 
    
    // isJWT Check
    func testJwtCheck() {
        let invalidJwt = isJWT("eeeee")
        let validJwt = isJWT("ec.exx.ef")
        XCTAssertFalse(invalidJwt)
        XCTAssertTrue(validJwt)
    }

    // Construct and return VP token for signing
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
    
    // NetworkManager Tests Success
    func testSendVpSuccess() async throws {
        mockNetworkManager.setMockResponse(for: URL(string: "https://mock-verifier.com")!, response: "Success: Request completed successfully.")
    
        let vcResponseMetaData = VPResponseMetadata(jws: jws, signatureAlgorithm: signatureAlgoType, publicKey: publicKey, domain: domain)
        
        let response = try await openID4VP.shareVerifiablePresentation(vpResponseMetadata: vcResponseMetaData)
        
        XCTAssertEqual(response, "Success: Request completed successfully.")
    }

    // NetworkManager Tests Failure
    func testSendVpFailure() async {
        let errorMessage = "Network Request failed with error response: response"
        mockNetworkManager.setMockResponse(for: URL(string: "https://mock-verifier.com")!, error: NetworkRequestException.networkRequestFailed(message: errorMessage))

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
            XCTFail("Expected NetworkRequestException.networkRequestFailed but got \(error)")
        }
    }
}
