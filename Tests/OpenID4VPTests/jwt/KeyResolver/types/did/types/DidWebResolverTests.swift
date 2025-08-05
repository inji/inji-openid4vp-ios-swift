import XCTest
@testable import OpenID4VP

final class DidWebResolverTests: XCTestCase {
    
    let mockNetworkManager = MockNetworkManager()
    
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
        
        // The exact type will depend on the implementation of publicKeyFromHex
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
}
