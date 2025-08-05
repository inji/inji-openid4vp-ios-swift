import XCTest
import CryptoKit
import Base58Swift
@testable import OpenID4VP

final class DidKeyResolverTests: XCTestCase {
    
    let mockNetworkManager = MockNetworkManager()
    
    func testResolveValidEd25519DidKey() async throws {
        let validDidKey = "did:key:z6MkpiJgQdNWUzyojaFuCzQ1MWvSSaxUfL1tvbcRfqWFoJRK"
        let parsedDid = ParsedDID(did: validDidKey, method: .key, id: "z6MkkXReNrZa6qLkqnQcffhNPEK1SJvJoK1cRezKEWnJ8PuS", didUrl: validDidKey)
        
        let resolver = DidKeyResolver(networkManager: mockNetworkManager, parsedDID: parsedDid)
                
        await XCTAssertNoThrowAndVerifyAsync(try await resolver.resolve(verificationaMethodUri: validDidKey)){ key in
            switch key {
            case .ed25519(let publicKey):
                XCTAssertNotNil(publicKey, "Public key should not be nil")
                XCTAssertEqual(publicKey.rawRepresentation.count, 32, "Ed25519 public key should be 32 bytes")
            default:
                XCTFail("Expected Ed25519 key type, but got \(key)")
            }
        }
    }
    
    func testInvalidBase58EncodedKey() async {
        // Invalid base58 encoded key
        let invalidBase58DidKey = "did:key:z1nval1dBase58String"
        let parsedDid = ParsedDID(did: invalidBase58DidKey, method: .key, id: "z1nval1dBase58String", didUrl: invalidBase58DidKey)
        
        let resolver = DidKeyResolver(networkManager: mockNetworkManager, parsedDID: parsedDid)
        
        await assertAsyncThrowsError(try await resolver.resolve(verificationaMethodUri: invalidBase58DidKey)) { error in
            assertOpenID4VPException(error, expectedMessage: "DID public key decoding failed", expectedCode: "invalid_request")
        }
    }
    
    func testUnsupportedKeyType() async {
        // Create a valid base58 string but with incorrect multicodec prefix
        // This simulates a key that's not an Ed25519 key (first bytes not 0xed, 0x01)
        let keyBytes = [UInt8](repeating: 0, count: 32)
        let prefixedKeyBytes = [0x12, 0x20] + keyBytes // Using different prefix (e.g., secp256k1)
        let base58Key = Base58.base58Encode(prefixedKeyBytes)
        
        let invalidTypeDidKey = "did:key:z\(base58Key)"
        let parsedDid = ParsedDID(did: invalidTypeDidKey, method: .key, id: "z\(base58Key)", didUrl: invalidTypeDidKey)
        
        let resolver = DidKeyResolver(networkManager: mockNetworkManager, parsedDID: parsedDid)
        
        await assertAsyncThrowsError(try await resolver.resolve(verificationaMethodUri: invalidTypeDidKey)) { error in
            assertOpenID4VPException(error, expectedMessage: "unsupportedKeyType", expectedCode: "invalid_request")
        }
    }
    
    func testInvalidKeyData() async {
        // The key bytes are too short to be a valid Ed25519 key
        let invalidKeyBytes = [UInt8](repeating: 0, count: 16)
        let prefixedKeyBytes = [0xed, 0x01] + invalidKeyBytes
        let invalidBase58 = Base58.base58Encode(prefixedKeyBytes)
        
        let invalidDataDidKey = "did:key:z\(invalidBase58)"
        let parsedDid = ParsedDID(did: invalidDataDidKey, method: .key, id: "z\(invalidBase58)", didUrl: invalidDataDidKey)
        
        let resolver = DidKeyResolver(networkManager: mockNetworkManager, parsedDID: parsedDid)
        
        await assertAsyncThrowsError(try await resolver.resolve(verificationaMethodUri: invalidDataDidKey)) { error in
            assertOpenID4VPException(error, expectedMessage: "unsupportedKeyType", expectedCode: "invalid_request")
        }
    }
    
    func testValidEd25519KeyWithFragment() async throws {
        let validDidKey = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#key-1"
        let parsedDid = ParsedDID(did: validDidKey, method: .key, id: "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", didUrl: validDidKey, fragment: "key-1")
        
        let resolver = DidKeyResolver(networkManager: mockNetworkManager, parsedDID: parsedDid)
        
        let key = try await resolver.resolve(verificationaMethodUri: validDidKey)
        
        switch key {
        case .ed25519(let publicKey):
            XCTAssertNotNil(publicKey)
            XCTAssertEqual(publicKey.rawRepresentation.count, 32)
        default:
            XCTFail("Expected Ed25519 key type, but got \(key)")
        }
    }
}
