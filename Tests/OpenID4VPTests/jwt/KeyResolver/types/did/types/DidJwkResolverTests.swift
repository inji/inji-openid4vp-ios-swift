import Foundation
@testable import OpenID4VP

import XCTest
final class DidJwkResolverTests: XCTestCase {
    
    let mockNetworkManager = MockNetworkManager()
    
    func testDidJwkSuccessfulResolving() async throws {
        let did = "did:jwk:eyJrdHkiOiAiT0tQIiwgImNydiI6ICJFZDI1NTE5IiwgIngiOiAiOGc5ZF9NQjBpVTJubWdiXzlQNERmMFRSUW01UkpUbWFpRWsySGtaeTVwRSIsICJhbGciOiAiRWREU0EiLCAia2V5X29wcyI6IFsidmVyaWZ5Il0sICJ1c2UiOiAic2lnIn0"
        let parsedDid = ParsedDID(did: did, method: .jwk, id: "eyJrdHkiOiAiT0tQIiwgImNydiI6ICJFZDI1NTE5IiwgIngiOiAiOGc5ZF9NQjBpVTJubWdiXzlQNERmMFRSUW01UkpUbWFpRWsySGtaeTVwRSIsICJhbGciOiAiRWREU0EiLCAia2V5X29wcyI6IFsidmVyaWZ5Il0sICJ1c2UiOiAic2lnIn0", didUrl: did)
        let resolver = DidJwkResolver(networkManager: mockNetworkManager, parsedDID: parsedDid)
        
        let key = try await resolver.resolve(verificationaMethodUri: did)
        
        switch key {
        case .ed25519(let edKey):
            XCTAssertEqual("f20f5dfcc074894da79a06fff4fe037f44d1426e5125399a8849361e4672e691", edKey.jwkRepresentation.x?.toHexString())
        default:
            XCTFail("Expected Ed25519 key type, but got \(key)")
        }
    }
    
    func testInvalidBase64URL() async {
        // Invalid base64url string that cannot be decoded
        let invalidDid = "did:jwk:not@valid%base64"
        let parsedDid = ParsedDID(did: invalidDid, method: .jwk, id: "not@valid%base64", didUrl: invalidDid)
        let resolver = DidJwkResolver(networkManager: mockNetworkManager, parsedDID: parsedDid)
        
        await assertAsyncThrowsError(try await resolver.resolve(verificationaMethodUri: invalidDid)) { error in
            assertOpenID4VPException(error,
                expectedMessage: "Invalid base64url encoding for public key data",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testInvalidJSONInJWK() async {
        let invalidJsonDid = "did:jwk:\(encodeBase64Url("not valid json".data(using: .utf8)!))"
        let parsedDid = ParsedDID(did: invalidJsonDid, method: .jwk, id: "", didUrl: invalidJsonDid)
        let resolver = DidJwkResolver(networkManager: mockNetworkManager, parsedDID: parsedDid)
        
        await assertAsyncThrowsError(try await resolver.resolve(verificationaMethodUri: invalidJsonDid)) { error in
            XCTAssertTrue(error is DecodingError, "Expected DecodingError but got \(type(of: error)) : \(error)")
        }
    }
    
    func testUnsupportedCurve() async {
        let jwk = """
            {
                "kty": "OKP",
                "crv": "P-256",
                "alg": "ES256",
                "use":"sig",
                "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
                "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"
            }
            """
        let jwkBase64 = encodeBase64Url(jwk.data(using: .utf8)!)
        let unsupportedCurveDid = "did:jwk:\(jwkBase64)"
        let parsedDid =  ParsedDID(did: unsupportedCurveDid, method: .jwk, id: jwkBase64, didUrl: unsupportedCurveDid)
        let resolver = DidJwkResolver(networkManager: mockNetworkManager, parsedDID: parsedDid)
        
        await assertAsyncThrowsError(try await resolver.resolve(verificationaMethodUri: unsupportedCurveDid)) { error in
            assertOpenID4VPException(error,
                expectedMessage: "Curve - P-256 is not supported. Supported: Ed25519",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testUnsupportedKeyType() async {
        let jwk = """
            {
                "kty": "EC",
                "crv": "P-256",
                "alg": "ES256",
                "use":"sig",
                "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
                "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"
            }
            """
        let jwkBase64 = encodeBase64Url(jwk.data(using: .utf8)!)
        let unsupportedCurveDid = "did:jwk:\(jwkBase64)"
        let parsedDid =  ParsedDID(did: unsupportedCurveDid, method: .jwk, id: jwkBase64, didUrl: unsupportedCurveDid)
        let resolver = DidJwkResolver(networkManager: mockNetworkManager, parsedDID: parsedDid)
        
        await assertAsyncThrowsError(try await resolver.resolve(verificationaMethodUri: unsupportedCurveDid)) { error in
            assertOpenID4VPException(error,
                expectedMessage: "KeyType - EC is not supported. Supported: OKP",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testMissingXCoordinate() async {
        let jwk = """
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "alg": "EdDSA"
            }
            """
        let jwkBase64 = encodeBase64Url(jwk.data(using: .utf8)!)
        let missingXDid = "did:jwk:\(jwkBase64)"
        let parsedDid = ParsedDID(did: missingXDid, method: .jwk, id: jwkBase64, didUrl: missingXDid)
        let resolver = DidJwkResolver(networkManager: mockNetworkManager, parsedDID: parsedDid)
        
        await assertAsyncThrowsError(try await resolver.resolve(verificationaMethodUri: missingXDid)) { error in
            XCTAssertTrue(error is DeserializationFailure, "Expected DeserializationFailure but got \(type(of: error))")
        }
    }
    
    func testInvalidXCoordinateBase64() async {
        let jwk = """
            {
                "kty": "OKP",
                "use": "sig",
                "crv": "Ed25519",
                "x": "invalid@base64",
                "alg": "EdDSA"
            }
            """
        let jwkBase64 = encodeBase64Url(jwk.data(using: .utf8)!)
        let invalidXBase64Did = "did:jwk:\(jwkBase64)"
        let parsedDid = ParsedDID(did: invalidXBase64Did, method: .jwk, id: jwkBase64, didUrl: invalidXBase64Did)
        let resolver = DidJwkResolver(networkManager: mockNetworkManager, parsedDID: parsedDid)
        
        await assertAsyncThrowsError(try await resolver.resolve(verificationaMethodUri: invalidXBase64Did)) { error in
            assertOpenID4VPException(error,
                expectedMessage: "Invalid base64url encoding for public key data",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testInvalidPublicKeyData() async {
        // JWK with valid base64 in x coordinate but data is not a valid Ed25519 key
        let jwk = """
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "aW52YWxpZCBrZXkgZGF0YQ==",
                "alg": "EdDSA",
                "use": "sig"
            }
            """
        let jwkBase64 = encodeBase64Url(jwk.data(using: .utf8)!)
        let invalidKeyDataDid = "did:jwk:\(jwkBase64)"
        let parsedDid = ParsedDID(did: invalidKeyDataDid, method: .jwk, id: jwkBase64, didUrl: invalidKeyDataDid)
        let resolver = DidJwkResolver(networkManager: mockNetworkManager, parsedDID: parsedDid)
        
        await assertAsyncThrowsError(try await resolver.resolve(verificationaMethodUri: invalidKeyDataDid)) { error in
           assertOpenID4VPException(error,
                expectedMessage: "Public key resolution failed. Error: incorrectKeySize",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    private func encodeBase64Url(_ data: Data) -> String {
        return data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

