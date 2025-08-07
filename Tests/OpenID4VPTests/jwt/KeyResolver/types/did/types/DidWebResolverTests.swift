import XCTest
@testable import OpenID4VP

final class DidWebResolverTests: XCTestCase {
    
    let mockNetworkManager = MockNetworkManager()
    let did = "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs"
    let didDocumentUrl = "https://mosip.github.io/inji-mock-services/openid4vp-service/docs/did.json"
    
    let didResponse = """
    {
      "@context": ["https://www.w3.org/ns/did/v1"],
      "id": "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs",
      "alsoKnownAs": [],
      "authentication": [
        "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs#key-0"
      ],
      "assertionMethod": [
        "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs#key-0"
      ],
      "service": [],
      "verificationMethod": [
        {
          "@context": "https://w3id.org/security/suites/ed25519-2020/v1",
          "id": "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs#key-0",
          "type": "Ed25519VerificationKey2020",
          "controller": "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs",
          "publicKeyMultibase": "z6MkwAm9tLpXZNfeEAqj9jcccFhjdiTwxVD32GhcjyeqGYSo"
        }
      ]
    }
    """
    
    let didResponseWithPublicKeyJwk = """
    {
      "@context": ["https://www.w3.org/ns/did/v1"],
      "id": "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs",
      "alsoKnownAs": [],
      "authentication": [
        "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs#key-0"
      ],
      "assertionMethod": [
        "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs#key-0"
      ],
      "service": [],
      "verificationMethod": [
        {
          "@context": "https://w3id.org/security/suites/ed25519-2020/v1",
          "id": "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs#key-0",
          "type": "Ed25519VerificationKey2020",
          "controller": "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs",
          "publicKeyJwk": {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "5Gkh7kcvir1nKUxZSbZIfa-CMJ-7K4F8NGamMhRr8B4",
            "alg": "EdDSA",
            "key_ops": [
              "sign",
              "verify"
            ],
            "use": "sig"
          }
        }
      ]
    }
    """

    
    func testSuccessfulResolvingWithPublicKeyMultibase() async throws {
        // Setup mock response with publicKeyMultibase
        let didDocJSON = """
        {
            "id": "did:web:example.com",
            "verificationMethod": [{
                "id": "did:web:example.com#key1",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:web:example.com",
                "publicKeyMultibase": "z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
            }]
        }
        """
        mockNetworkManager.setMockResponse(
            for: "https://example.com/.well-known/did.json",
            responseBody: didDocJSON
        )
        
        // Create the resolver with a parsed DID
        let parsedDid = ParsedDID(
            did: "did:web:example.com",
            method: .web,
            id: "example.com",
            didUrl: "did:web:example.com#key1"
        )
        let resolver = DidWebResolver(networkManager: mockNetworkManager, parsedDID: parsedDid)
        
        // Resolve the verification method
        let key = try await resolver.resolve(verificationaMethodUri: "did:web:example.com#key1")
        
        // Verify the result is a valid key
        switch key {
        case .ed25519:
            // If we got an Ed25519 key, the test passes
            break
        default:
            XCTFail("Expected Ed25519 key type, but got \(key)")
        }
    }
    
    func testSuccessfulResolvingWithJWK() async throws {
        // Setup mock response with publicKeyJwk
        let didDocJSON = """
        {
            "id": "did:web:example.com",
            "verificationMethod": [{
                "id": "did:web:example.com#key1",
                "type": "JsonWebKey2020",
                "controller": "did:web:example.com",
                "publicKeyJwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "8g9d_MB0iU2nmgb_9P4Df0TRQm5RJTmaiEk2HkZy5pE",
                    "alg": "EdDSA",
                    "use": "sig"
                }
            }]
        }
        """
        mockNetworkManager.setMockResponse(
            for: "https://example.com/.well-known/did.json",
            responseBody: didDocJSON
        )
        
        let parsedDid = ParsedDID(
            did: "did:web:example.com",
            method: .web,
            id: "example.com",
            didUrl: "did:web:example.com#key1"
        )
        let resolver = DidWebResolver(networkManager: mockNetworkManager, parsedDID: parsedDid)
        
        let key = try await resolver.resolve(verificationaMethodUri: "did:web:example.com#key1")
        
        switch key {
        case .ed25519:
            // Test passes if we get an Ed25519 key
            break
        default:
            XCTFail("Expected Ed25519 key type, but got \(key)")
        }
    }
    
    func testSuccessfulResolvingWithPEM() async throws {
        // Setup mock response with publicKeyPem
        let didDocJSON = """
        {
            "id": "did:web:example.com",
            "verificationMethod": [{
                "id": "did:web:example.com#key1",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:web:example.com",
                "publicKeyPem": "-----BEGIN PUBLIC KEY-----\\nMCowBQYDK2VwAyEA8g9d/MB0iU2nmgb/9P4Df0TRQm5RJTmaiEk2HkZy5pE=\\n-----END PUBLIC KEY-----"
            }]
        }
        """
        mockNetworkManager.setMockResponse(
            for: "https://example.com/.well-known/did.json",
            responseBody: didDocJSON
        )
        
        let parsedDid = ParsedDID(
            did: "did:web:example.com",
            method: .web,
            id: "example.com",
            didUrl: "did:web:example.com#key1"
        )
        let resolver = DidWebResolver(networkManager: mockNetworkManager, parsedDID: parsedDid)
        
        let key = try await resolver.resolve(verificationaMethodUri: "did:web:example.com#key1")
        
        switch key {
        case .ed25519:
            break
        default:
            XCTFail("Expected ed25519 type, but got \(key)")
        }
    }
    
    func testSuccessfulResolvingWithHex() async throws {
        // Setup mock response with publicKeyHex
        let didDocJSON = """
        {
            "id": "did:web:example.com",
            "verificationMethod": [{
                "id": "did:web:example.com#key1",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:web:example.com",
                "publicKeyHex": "f20f5dfcc074894da79a06fff4fe037f44d1426e5125399a8849361e4672e691"
            }]
        }
        """
        mockNetworkManager.setMockResponse(
            for: "https://example.com/.well-known/did.json",
            responseBody: didDocJSON
        )
        
        let parsedDid = ParsedDID(
            did: "did:web:example.com",
            method: .web,
            id: "example.com",
            didUrl: "did:web:example.com#key1"
        )
        let resolver = DidWebResolver(networkManager: mockNetworkManager, parsedDID: parsedDid)
        
        let key = try await resolver.resolve(verificationaMethodUri: "did:web:example.com#key1")
        
        XCTAssertNotNil(key)
    }
    
    func testSubdomainInDID() async throws {
        let didDocJSON = """
        {
            "id": "did:web:sub.example.com",
            "verificationMethod": [{
                "id": "did:web:sub.example.com#key1",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:web:sub.example.com",
                "publicKeyMultibase": "z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
            }]
        }
        """
        mockNetworkManager.setMockResponse(
            for: "https://sub.example.com/.well-known/did.json",
            responseBody: didDocJSON
        )
        
        let parsedDid = ParsedDID(
            did: "did:web:sub.example.com",
            method: .web,
            id: "sub.example.com",
            didUrl: "did:web:sub.example.com#key1"
        )
        let resolver = DidWebResolver(networkManager: mockNetworkManager, parsedDID: parsedDid)
        
        // This should construct the URL with the subdomain correctly
        let key = try await resolver.resolve(verificationaMethodUri: "did:web:sub.example.com#key1")
        
        // Verify the URL was constructed correctly
        XCTAssertTrue(mockNetworkManager.recordedRequests.keys.contains("https://sub.example.com/.well-known/did.json"))
        XCTAssertNotNil(key)
    }
    
    func testValidPublicKeyResolutionWithPublicKeyJwk() async {
        mockNetworkManager.setMockResponse(for: didDocumentUrl, responseBody: didResponseWithPublicKeyJwk)
        let didKeyResolver = DidPublicKeyResolver(didUrl: did, networkManager: mockNetworkManager)
        
        await assertAsyncNoThrowsErrorAndVerify(try await didKeyResolver.resolveKey(header: [
            "typ": "oauth-authz-req+jwt",
            "alg": "EdDSA",
            "kid": "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs#key-0"
        ])){ result in
            switch result {
            case .ed25519(let publicKey):
                XCTAssertEqual("e46921ee472f8abd67294c5949b6487daf82309fbb2b817c3466a632146bf01e", publicKey.rawRepresentation.toHexString())
            default:
                XCTFail("Unexpected public key type returned")
            }
        }

    }

    
    func testPathBasedDID() async throws {
        let didDocJSON = """
        {
            "id": "did:web:example.com:path:to:identity",
            "verificationMethod": [{
                "id": "did:web:example.com:path:to:identity#key1",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:web:example.com:path:to:identity",
                "publicKeyMultibase": "z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
            }]
        }
        """
        mockNetworkManager.setMockResponse(
            for: "https://example.com/path/to/identity/did.json",
            responseBody: didDocJSON
        )
        
        let parsedDid = ParsedDID(
            did: "did:web:example.com:path:to:identity",
            method: .web,
            id: "example.com:path:to:identity",
            didUrl: "did:web:example.com:path:to:identity#key1"
        )
        let resolver = DidWebResolver(networkManager: mockNetworkManager, parsedDID: parsedDid)
        
        let key = try await resolver.resolve(verificationaMethodUri: "did:web:example.com:path:to:identity#key1")
        
        // Verify the URL was constructed correctly
        XCTAssertTrue(mockNetworkManager.recordedRequests.keys.contains("https://example.com/path/to/identity/did.json"))
        XCTAssertNotNil(key)
    }
    
    func testNetworkFailure() async {
        mockNetworkManager.setMockResponse(
            for: "https://example.com/.well-known/did.json",
            error: NetworkRequestException.networkRequestFailed(message: "Not Found")
        )
        
        let parsedDid = ParsedDID(
            did: "did:web:example.com",
            method: .web,
            id: "example.com",
            didUrl: "did:web:example.com#key1"
        )
        let resolver = DidWebResolver(networkManager: mockNetworkManager, parsedDID: parsedDid)
        
        await assertAsyncThrowsError(try await resolver.resolve(verificationaMethodUri: "did:web:example.com#key1")) { error in
            assertOpenID4VPException(error, expectedMessage: "Network request failed with error response - Not Found", expectedCode: "invalid_request")
        }
    }
    
    func testInvalidDidDocument() async {
        // Setup mock response with invalid JSON
        mockNetworkManager.setMockResponse(
            for: "https://example.com/.well-known/did.json",
            responseBody: "Invalid JSON"
        )
        
        let parsedDid = ParsedDID(
            did: "did:web:example.com",
            method: .web,
            id: "example.com",
            didUrl: "did:web:example.com#key1"
        )
        let resolver = DidWebResolver(networkManager: mockNetworkManager, parsedDID: parsedDid)
        
        await assertAsyncThrowsError(try await resolver.resolve(verificationaMethodUri: "did:web:example.com#key1")) { error in
            assertOpenID4VPException(error, expectedMessage: "The data couldn’t be read because it isn’t in the correct format.", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }
    
    func testMissingVerificationMethod() async {
        // Setup mock response with no matching verification method
        let didDocJSON = """
        {
            "id": "did:web:example.com",
            "verificationMethod": [{
                "id": "did:web:example.com#different-key",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:web:example.com",
                "publicKeyMultibase": "z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
            }]
        }
        """
        mockNetworkManager.setMockResponse(
            for: "https://example.com/.well-known/did.json",
            responseBody: didDocJSON
        )
        
        let parsedDid = ParsedDID(
            did: "did:web:example.com",
            method: .web,
            id: "example.com",
            didUrl: "did:web:example.com#key1"
        )
        let resolver = DidWebResolver(networkManager: mockNetworkManager, parsedDID: parsedDid)
        
        await assertAsyncThrowsError(try await resolver.resolve(verificationaMethodUri: "did:web:example.com#key1")) { error in
            assertOpenID4VPException(error, expectedMessage: "Public key extraction failed for kid: did:web:example.com#key1", expectedCode: "invalid_request")
        }
    }
    
    func testEmptyPublicKeyMultibase() async {
        // Setup mock response with empty publicKeyMultibase
        let didDocJSON = """
        {
            "id": "did:web:example.com",
            "verificationMethod": [{
                "id": "did:web:example.com#key1",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:web:example.com",
                "publicKeyMultibase": ""
            }]
        }
        """
        mockNetworkManager.setMockResponse(
            for: "https://example.com/.well-known/did.json",
            responseBody: didDocJSON
        )
        
        let parsedDid = ParsedDID(
            did: "did:web:example.com",
            method: .web,
            id: "example.com",
            didUrl: "did:web:example.com#key1"
        )
        let resolver = DidWebResolver(networkManager: mockNetworkManager, parsedDID: parsedDid)
        
        await assertAsyncThrowsError(try await resolver.resolve(verificationaMethodUri: "did:web:example.com#key1")) { error in
            assertOpenID4VPException(error, expectedMessage: "publicKeyMultibase cannot be null or empty", expectedCode: "invalid_request")
        }
    }
    
    func testNoSupportedKeyType() async {
        // Setup mock response with no supported key types
        let didDocJSON = """
        {
            "id": "did:web:example.com",
            "verificationMethod": [{
                "id": "did:web:example.com#key1",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:web:example.com",
                "unsupportedKeyType": "value"
            }]
        }
        """
        mockNetworkManager.setMockResponse(
            for: "https://example.com/.well-known/did.json",
            responseBody: didDocJSON
        )
        
        let parsedDid = ParsedDID(
            did: "did:web:example.com",
            method: .web,
            id: "example.com",
            didUrl: "did:web:example.com#key1"
        )
        let resolver = DidWebResolver(networkManager: mockNetworkManager, parsedDID: parsedDid)
        await assertAsyncThrowsError(try await resolver.resolve(verificationaMethodUri: "did:web:example.com#key1")) { error in
            assertOpenID4VPException(error, expectedMessage: "Unsupported Public Key type. Supported: publicKeyMultibase, publicKeyJwk, publicKeyHex, publicKeyPem", expectedCode: "invalid_request")
        }
    }
    
    func testUnsupportedPublicKeyTypesThrowError() async {
        let unsupportedKeys = [
            "publicKeyBase58"
        ]

        for key in unsupportedKeys {
            let kid = "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs#key-unsupported-\(key)"
            let didDocumentWithUnsupportedKey = """
            {
              "verificationMethod": [
                {
                  "id": "\(kid)",
                  "\(key)": "dummy-value"
                }
              ]
            }
            """
            mockNetworkManager.setMockResponse(for: didDocumentUrl, responseBody: didDocumentWithUnsupportedKey)

            let resolver = DidPublicKeyResolver(didUrl: did, networkManager: mockNetworkManager)

            await assertAsyncThrowsError(
                        try await resolver.resolveKey(header: ["kid": kid])
                    ) { error in
                    assertOpenID4VPException(
                        error,
                        expectedMessage: "Unsupported Public Key type. Supported: publicKeyMultibase, publicKeyJwk, publicKeyHex, publicKeyPem",
                        expectedCode: OpenID4VPErrorCodes.invalidRequest
                    )
                }
        }
    }
    
    func testThrowsErrorWhenPublicKeyMultibaseIsNil() async {
        let kid = "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs#key-0"

        let didDoc = """
        {
          "verificationMethod": [
            {
              "id": "\(kid)",
              "publicKeyMultibase": null
            }
          ]
        }
        """

        mockNetworkManager.setMockResponse(for: didDocumentUrl, responseBody: didDoc)
        let resolver = DidPublicKeyResolver(didUrl: did, networkManager: mockNetworkManager)

        await assertAsyncThrowsError(
            try await resolver.resolveKey(header: ["kid": kid])
        ) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "publicKeyMultibase cannot be null or empty",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }


    
    func testThrowsErrorWhenPublicKeyMultibaseIsEmpty() async {
        let kid = "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs#key-0"

        let didDoc = """
        {
          "verificationMethod": [
            {
              "id": "\(kid)",
              "publicKeyMultibase": ""
            }
          ]
        }
        """

        mockNetworkManager.setMockResponse(for: didDocumentUrl, responseBody: didDoc)
        let resolver = DidPublicKeyResolver(didUrl: did, networkManager: mockNetworkManager)

        await assertAsyncThrowsError(
            try await resolver.resolveKey(header: ["kid": kid])
        ) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "publicKeyMultibase cannot be null or empty",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
}
