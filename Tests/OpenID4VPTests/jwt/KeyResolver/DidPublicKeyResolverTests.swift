import XCTest
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

    func testValidPublicKeyResolution() async {
        mockNetworkManager.setMockResponse(for: didDocumentUrl, responseBody: didResponse)
        let didKeyResolver = DidPublicKeyResolver(didUrl: did, networkManager: mockNetworkManager)
        
        do {
            let result = try await didKeyResolver.resolveKey(header: [
                "typ": "oauth-authz-req+jwt",
                "alg": "EdDSA",
                "kid": "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs#key-0"
            ])
            XCTAssertEqual(result, "z6MkwAm9tLpXZNfeEAqj9jcccFhjdiTwxVD32GhcjyeqGYSo")
        } catch {
            XCTFail("Expected success but got error: \(error)")
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
        let invalidDid = "did:jwk:xyz"
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
            "publicKey",
            "publicKeyJwk",
            "publicKeyPem",
            "publicKeyHex"
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
                        expectedMessage: "Unsupported Public Key type. Supported: publicKeyMultibase",
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
