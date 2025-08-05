import XCTest
import CryptoKit
@testable import OpenID4VP

class DidPublicKeyResolverTests: XCTestCase {
    let mockNetworkManager: MockNetworkManager! = MockNetworkManager()
    
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

    func testValidPublicKeyResolution() async {
        mockNetworkManager.setMockResponse(for: didDocumentUrl, responseBody: didResponse)
        let didKeyResolver = DidPublicKeyResolver(didUrl: did, networkManager: mockNetworkManager)

        await assertAsyncNoThrowsErrorAndVerify(try await didKeyResolver.resolveKey(header: [
            "typ": "oauth-authz-req+jwt",
            "alg": "EdDSA",
            "kid": "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs#key-0"
        ])){ result in
            // assert if returned result is of type publick key type ed22519 case
            switch result {
            case .ed25519(let publicKey):
                XCTAssertTrue(publicKey is Curve25519.Signing.PublicKey)
            default:
                XCTFail("Unexpected public key type returned")
            }
        }
    }
    
    func testValidPublicKeyResolutionWithPublicKeyJwk() async {
        mockNetworkManager.setMockResponse(for: didDocumentUrl, responseBody: didResponseWithPublicKeyJwk)
        let didKeyResolver = DidPublicKeyResolver(didUrl: did, networkManager: mockNetworkManager)
        
        await assertAsyncNoThrowsErrorAndVerify(try await didKeyResolver.resolveKey(header: [
            "typ": "oauth-authz-req+jwt",
            "alg": "EdDSA",
            "kid": "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs#key-0"
        ])){ result in
            // assert if returned result is of type publick key type ed22519 case
            switch result {
            case .ed25519(let publicKey):
                XCTAssertTrue(publicKey is Curve25519.Signing.PublicKey)
            default:
                XCTFail("Unexpected public key type returned")
            }
        }

    }

    func testThrowErrorWhenKeyIdIsNotMatchingAnyOfTheKeysInDidDocumentResponse() async {
        let testCases: [TestCase] = [
            TestCase(input: ""),
            TestCase(input: "did:example:123#2"),
        ]

        for testCase in testCases {
            mockNetworkManager.setMockResponse(for: didDocumentUrl, responseBody: didResponse)
            let didKeyResolver = DidPublicKeyResolver(didUrl: did, networkManager: mockNetworkManager)

            await assertAsyncThrowsError(
                        try await didKeyResolver.resolveKey(header: [
                            "typ": "oauth-authz-req+jwt",
                            "alg": "EdDSA",
                            "kid": testCase.input
                        ])
                    ) { error in
                    assertOpenID4VPException(
                        error,
                        expectedMessage: "Public key extraction failed for kid: \(testCase.input)",
                        expectedCode: OpenID4VPErrorCodes.invalidRequest
                    )
                }
        }
    }

    func testThrowErrorWhenPublicKeyResolutionFailed() async {
        let invalidDid = "did:peer:xyz"
        let didKeyResolver = DidPublicKeyResolver(didUrl: invalidDid, networkManager: mockNetworkManager)

        await assertAsyncThrowsError(
                try await didKeyResolver.resolveKey(header: [
                    "typ": "oauth-authz-req+jwt",
                    "alg": "EdDSA",
                    "kid": "did:example:123#2"
                ])
            ) { error in
                assertOpenID4VPException(
                    error,
                    expectedMessage: "Given did url is not supported",
                    expectedCode: OpenID4VPErrorCodes.invalidRequest
                )
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
