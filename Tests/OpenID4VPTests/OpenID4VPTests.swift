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
    
    let didResponse = "{\"@context\":\"https://w3id.org/did-resolution/v1\",\"didDocument\":{\"assertionMethod\":[\"did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs#key-0\"],\"service\":[],\"id\":\"did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs\",\"verificationMethod\":[{\"publicKey\":\"IKXhA7W1HD1sAl+OfG59VKAqciWrrOL1Rw5F+PGLhi4=\",\"controller\":\"did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs\",\"id\":\"did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs#key-0\",\"type\":\"Ed25519VerificationKey2020\",\"@context\":\"https://w3id.org/security/suites/ed25519-2020/v1\"}],\"@context\":[\"https://www.w3.org/ns/did/v1\"],\"alsoKnownAs\":[],\"authentication\":[\"did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs#key-0\"]},\"didResolutionMetadata\":{\"driverDuration\":19,\"contentType\":\"application/did+ld+json\",\"pattern\":\"^(did:web:.+)$\",\"driverUrl\":\"http://uni-resolver-driver-did-uport:8081/1.0/identifiers/\",\"duration\":19,\"did\":{\"didString\":\"did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs\",\"methodSpecificId\":\"mosip.github.io:inji-mock-services:openid4vp-service:docs\",\"method\":\"web\"},\"didUrl\":{\"path\":null,\"fragment\":null,\"query\":null,\"didUrlString\":\"did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs\",\"parameters\":null,\"did\":{\"didString\":\"did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs\",\"methodSpecificId\":\"mosip.github.io:inji-mock-services:openid4vp-service:docs\",\"method\":\"web\"}}},\"didDocumentMetadata\":{}}"

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
        mockNetworkManager.setMockResponse(for: URL(string: "https://7af8-2401-4900-71c2-f74a-8d88-aa5b-2f16-294b.ngrok-free.app/verifier/get-auth-request-obj")!,response: validJwtResponse)
        mockNetworkManager.setMockResponse(for: URL(string: "https://resolver.identity.foundation/1.0/identifiers/did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs")!,response: didResponse)
        let verifiers = createVerifiers(from: testVerifierList)
        
        let decodedAuthorizationRequest: Any?
        do {
            decodedAuthorizationRequest = try await openID4VP.authenticateVerifier(encodedAuthorizationRequest: testValidSignedVpRequestWithDid, trustedVerifierJSON: verifiers, shouldValidateClient: true)
        } catch {
            decodedAuthorizationRequest = nil
        }
        
        XCTAssertTrue(decodedAuthorizationRequest is AuthorizationRequest, "decodedResponse should be an instance of AuthenticationResponse")
        XCTAssertTrue(decodedAuthorizationRequest != nil, "decodedResponse should not be null")
    }
    
    // jwt -> client_id_scheme = did, Invalid did
    func testThrowErrorForInValidSignatureInRequest() async {
        mockNetworkManager.setMockResponse(for: URL(string: "https://7af8-2401-4900-71c2-f74a-8d88-aa5b-2f16-294b.ngrok-free.app/verifier/get-auth-request-obj")!,response: invalidJwtResponse)
        mockNetworkManager.setMockResponse(for: URL(string: "https://resolver.identity.foundation/1.0/identifiers/did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs")!,response: didResponse)
        let verifiers = createVerifiers(from: testVerifierList)
        
        let error = await Task {
        try await openID4VP.authenticateVerifier(encodedAuthorizationRequest: testValidSignedVpRequestWithDid, trustedVerifierJSON: verifiers, shouldValidateClient: true)
        }.result
       
        switch error {
        case .failure(let thrownError):
            let expectedErrorMessage = "Jwt proof verification failed"
            XCTAssertEqual(thrownError.localizedDescription,expectedErrorMessage)
        case .success: break
        }
    }
    
    // jwt -> client_id_scheme = did, Mismatching clientId's in QR data and Request Uri response
    func testThrowErrorIfClientIdIsMismatchingWithQrDataAndRequest() async {
        mockNetworkManager.setMockResponse(for: URL(string: "https://7af8-2401-4900-71c2-f74a-8d88-aa5b-2f16-294b.ngrok-free.app/verifier/get-auth-request-obj")!,response: validJwtResponse)
        mockNetworkManager.setMockResponse(for: URL(string: "https://resolver.identity.foundation/1.0/identifiers/did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs")!,response: didResponse)
        let verifiers = createVerifiers(from: testVerifierList)
        
        let error = await Task {
        try await openID4VP.authenticateVerifier(encodedAuthorizationRequest: testInValidSignedVpRequestWithDidAndClientIdDifferent, trustedVerifierJSON: verifiers, shouldValidateClient: true)
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
        mockNetworkManager.setMockResponse(for: URL(string: "https://7af8-2401-4900-71c2-f74a-8d88-aa5b-2f16-294b.ngrok-free.app/verifier/get-auth-request-obj")!,response: invalidJwtResponseWithoutKid)
        mockNetworkManager.setMockResponse(for: URL(string: "https://resolver.identity.foundation/1.0/identifiers/did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs")!,response: didResponse)
        let verifiers = createVerifiers(from: testVerifierList)
        
        let error = await Task {
        try await openID4VP.authenticateVerifier(encodedAuthorizationRequest: testValidSignedVpRequestWithDid, trustedVerifierJSON: verifiers, shouldValidateClient: true)
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

    // base64 -> client_id_scheme = pre_registered, ClientMetadata mandatory values are not present
    func testMissingClientMetadataRequiredFieldsInRequest() async {

        let verifiers = createVerifiers(from: testVerifierList)
        
        let error = await Task {
            try await openID4VP.authenticateVerifier(encodedAuthorizationRequest: invalidClientMetadata, trustedVerifierJSON: verifiers, shouldValidateClient: true)
        }.result

        switch error {
        case .failure(let thrownError):
            let expectedErrorMessage = "Invalid Input: client_metadata value cannot be empty or null"
            XCTAssertEqual(thrownError.localizedDescription, expectedErrorMessage)
        case .success: break
        }
    }
    
    //
    func testValidateVerifierForAGivenVerifierListAndRequestObject() async {

        let verifiers = createVerifiers(from: testVerifierList)

        let decoded: AuthorizationRequest?

        do {
            decoded = try await openID4VP.authenticateVerifier(encodedAuthorizationRequest: testValidBase64EncodedVpRequestWithRedirectUri, trustedVerifierJSON: verifiers, shouldValidateClient: true)
        } catch {
            decoded = nil
        }
        
        let error = await Task {
            try validateVerifier(verifierList: verifiers, authorizationRequest: decoded!, shouldValidateClient: true)
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
        mockNetworkManager.setMockResponse(for: URL(string: "https://example.com")!, response: "Success: Request completed successfully.")
        do{ let presentationDefinition: PresentationDefinition = try PresentationDefinitionValidator.validate(presentatioDefinition: decodedPresentationDefinition)
            
            openID4VP.updateAuthorizationRequest(presentationDefinition, nil)
        }catch{}
        
        let vcResponseMetaData = VPResponseMetadata(jws: jws, signatureAlgorithm: signatureAlgoType, publicKey: publicKey, domain: domain)
        
        let response = try await openID4VP.shareVerifiablePresentation(vpResponseMetadata: vcResponseMetaData)
        
        XCTAssertEqual(response, "Success: Request completed successfully.")
    }

    // NetworkManager Tests Failure
    func testSendVpFailure() async {

        do{ let presentationDefinition: PresentationDefinition = try PresentationDefinitionValidator.validate(presentatioDefinition: decodedPresentationDefinition)
            
            openID4VP.updateAuthorizationRequest(presentationDefinition, nil)
        }catch{}
        
        let errorMessage = "Network Request failed with error response: response"
        mockNetworkManager.setMockResponse(for: URL(string: "https://example.com")!, error: NetworkRequestException.networkRequestFailed(message: errorMessage))

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
