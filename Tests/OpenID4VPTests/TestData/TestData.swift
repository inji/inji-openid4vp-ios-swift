import OpenID4VP
import Foundation

let clientMetadataString = """
        {
            "client_name": "Valid Client",
            "logo_uri": "https://example.com/logo.png",
            "authorization_encrypted_response_alg": "RSA-OAEP",
            "authorization_encrypted_response_enc": "A256GCM",
            "vp_formats": { "format1": { "type1": ["value1"] } },
            "jwks": { "keys": [{ "kty": "RSA", "crv": "curve", "use": "sig", "alg": "RS256", "kid": "1", "x": "ur76ru" }] }
        }
    """.data(using: .utf8)!
//let clientMetadata = clientMetadataString.toInstance(as: ClientMetadata.self)

private let testVerifierList:  [[String: Any]]  = [
    [
        "client_id": "https://mock-verifier.com",
        "response_uris": [
            "https://mock-verifier.com/response",
        ]
    ],
    [
        "client_id": "mock-client",
        "response_uris": [
            "https://mock-verifier.com",
        ]
    ]
]

let didUrl = "did:web:inji-ovp:inji-mock-services:openid4vp-service:docs"

let preRegisteredVerifiers = createVerifiers(from: testVerifierList)

let verifiableCredentialsList : [String : [FormatType : [AnyCodable]]] = ["input_descriptor1": [FormatType.ldp_vc : [AnyCodable(ldpVC())]]]

let didDocumentUrl = "https://inji-ovp/inji-mock-services/openid4vp-service/docs/did.json"
let httpUrlResponseForJWS: HTTPURLResponse = HTTPURLResponse(url: URL(string: didDocumentUrl)!, statusCode: 200, httpVersion: "", headerFields: ["Content-Type": "application/oauth-authz-req+jwt"])!
let didResponse = convertToJsonString([
    "assertionMethod": [
        "did:web:inji-ovp:inji-mock-services:openid4vp-service:docs#key-0"
    ],
    "service": [],
    "id": "did:web:inji-ovp:inji-mock-services:openid4vp-service:docs",
    "verificationMethod": [
        [
            "publicKeyMultibase": "z6MkwAm9tLpXZNfeEAqj9jcccFhjdiTwxVD32GhcjyeqGYSo",
            "controller": "did:web:inji-ovp:inji-mock-services:openid4vp-service:docs",
            "id": "did:web:inji-ovp:inji-mock-services:openid4vp-service:docs#key-0",
            "type": "Ed25519VerificationKey2020",
            "@context": "https://w3id.org/security/suites/ed25519-2020/v1"
        ]
    ],
    "@context": [
        "https://www.w3.org/ns/did/v1"
    ],
    "alsoKnownAs": [],
    "authentication": [
        "did:web:inji-ovp:inji-mock-services:openid4vp-service:docs#key-0"
    ]
])

let authorizationRequestParamsWithValue: [String: Any] = [
    "redirect_uri": "https://mock-verifier.com",
    "response_uri": "https://mock-verifier.com",
    "request_uri": "https://mock-verifier.com/verifier/get-auth-request-obj",
    "request_uri_method": "get",
    "presentation_definition": (presentationDefinition),
    "response_type": "vp_token",
    "response_mode": "direct_post",
    "nonce": "VbRRB/LTxLiXmVNZuyMO8A==",
    "state": "+mRQe1d6pBoJqF6Ab28klg==",
    "client_metadata": (clientMetadata),
    "presentation_definition_uri": "https://mock-verifier.com/presentation-definition"
]

let redirectUriSchemeClientIdDraft23: [String: String] = [
    "client_id": "redirect_uri:https://mock-verifier.com",
]

let DidSchemeClientIdDraft23: [String: String] = [
    "client_id": "did:web:inji-ovp:inji-mock-services:openid4vp-service:docs",
]

let preRegisteredSchemeClientIdDraft23: [String: String] = [
    "client_id": "mock-client",
]

let redirectUriSchemeClientIdDraft21: [String: String] = [
    "client_id": "https://mock-verifier.com",
    "client_id_scheme": "redirect_uri",
]

let DidSchemeClientIdDraft21: [String: String] = [
    "client_id": "did:web:inji-ovp:inji-mock-services:openid4vp-service:docs",
    "client_id_scheme": "did",
]

let preRegisteredSchemeClientIdDraft21: [String: String] = [
    "client_id": "mock-client",
    "client_id_scheme": "pre-registered",
]

let authRequestParamsByReferenceDraft23 : [String] = [
    "client_id",
    "request_uri",
    "request_uri_method"
]

let authRequestParamsByReferenceDraft21 : [String] = [
    "client_id",
    "client_id_scheme",
    "request_uri",
    "request_uri_method"
]

let authRequestWithRedirectUriByValue : [String] = [
    "client_id",
    "response_uri",
    "presentation_definition",
    "response_type",
    "response_mode",
    "nonce",
    "state",
    "client_metadata"
]

let authRequestWithRedirectUriWithPresentationDefinitionUri : [String] = [
    "client_id",
    "response_uri",
    "presentation_definition_uri",
    "response_type",
    "response_mode",
    "nonce",
    "state",
    "client_metadata"
]

let authRequestWithPreRegisteredByValueDraft23 : [String] = [
    "client_id",
    "response_mode",
    "response_uri",
    "presentation_definition",
    "response_type",
    "nonce",
    "state",
    "client_metadata"
]

let authRequestWithPreRegisteredByValueDraft21 : [String] = [
    "client_id",
    "client_id_scheme",
    "response_mode",
    "response_uri",
    "presentation_definition",
    "response_type",
    "nonce",
    "state",
    "client_metadata"
]

let authRequestWithDidByValue : [String] = [
    "client_id",
    "response_mode",
    "response_uri",
    "presentation_definition",
    "response_type",
    "nonce",
    "state",
    "client_metadata"
]


let authRequestClientIdSchemeMap : [ClientIdScheme: [String]] = [
    ClientIdScheme.preRegistered : authRequestWithDidByValue,
    ClientIdScheme.redirectUri : authRequestWithRedirectUriByValue,
    ClientIdScheme.did : authRequestWithPreRegisteredByValueDraft23
]

let presentationDefinition: [String: Any] = [
    "id": "vp_presentation_definition",
    "input_descriptors": [
        [
            "id": "input_1",
            "name": "Verifiable Credential",
            "purpose": "To verify identity using Linked Data Proofs",
            "format": [
                "ldp_vc": [
                    "proof_type": ["Ed25519Signature2018", "RsaSignature2018"]
                ]
            ],
            "constraints": [
                "fields": [
                    [
                        "path": ["$.credentialSubject.email"],
                        "filter": [
                            "type": "string",
                            "pattern": "@gmail.com"
                        ]
                    ]
                ]
            ]
        ]
    ]
]

let mockPresentationDefinitionObject = createInstance(presentationDefinition, as: PresentationDefinition.self)

let vpFormatsMap: [String: VPFormatSupported] = [
    "ldp_vc": VPFormatSupported(algValuesSupported: ["Ed25519Signature2018", "Ed25519Signature2020"])
]

public let clientMetadata: [String: Any] = [
    "client_name": "Requester name",
    "logo_uri": "https://mock-verifier.com/logo",
    "authorization_encrypted_response_alg": "ECDH-ES",
    "authorization_encrypted_response_enc": "A256GCM",
    "jwks": [
        "keys": [[
            "kty": "OKP",
            "crv": "X25519",
            "use": "enc",
            "x": "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
            "alg": "ECDH-ES",
            "kid": "ed-key1"
        ]]
    ],
    "vp_formats": [
        "ldp_vp": [
            "proof_type": [
                "Ed25519Signature2018",
                "Ed25519Signature2020"
            ]
        ]
    ]
]

let mockClientMetadataObject = createInstance(clientMetadata, as: ClientMetadata.self)

let ldpVPTokenSigningResult = LdpVPTokenSigningResult(
    jws: "validJWS", proofValue: "hdjbhdsjdshjv",
    signatureAlgorithm: "JsonWebSignature2020"
)

let mdocSigningResult = MdocVPTokenSigningResult(
    docTypeToDeviceAuthentication: ["docType": DeviceAuthentication(signature: "signature", algorithm: "ES256")]
)

//  client_id_scheme = redirect_uri
let authorizationRequestParamsWithRedirectUri: [String: Any] = [
    "client_id": "redirect_uri:https://mock-verifier.com",
    "redirect_uri":"https://mock-verifier.com",
    "presentation_definition": presentationDefinition,
    "response_type": "vp_token",
    "response_mode": "direct_post",
    "nonce":"VbRRB/LTxLiXmVNZuyMO8A==",
    "state":"+mRQe1d6pBoJqF6Ab28klg==",
    "client_metadata": clientMetadata
]

let urlEncodedAuthRequestWithPresentationDefinitionUri = createUrlEncodedAuthorizationRequest(
    requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdDraft23),
    clientIdScheme: .preRegistered,
    applicableFields: authRequestWithPreRegisteredByValueDraft23.map {
        $0 == AuthorizationRequestFieldConstants.presentationDefinition.rawValue ? AuthorizationRequestFieldConstants.presentationDefinitionUri.rawValue : $0
    }
)

// client_id_scheme = redirect_uri
let testValidUrlEncodedVPRequestWithRedirectUri = createUrlEncodedAuthorizationRequest(
    requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdDraft23),
    clientIdScheme: .redirectUri,
    applicableFields: authRequestWithRedirectUriByValue.map { $0 == AuthorizationRequestFieldConstants.redirectUri.rawValue ? AuthorizationRequestFieldConstants.responseUri.rawValue : $0 }
)

//  client_id_scheme = redirect_uri, with response uri and response mode
let testVPRequestWithRedirectUriAndResponseUriResponseMode = createUrlEncodedAuthorizationRequest(requestParams: mergeMaps( redirectUriSchemeClientIdDraft23,  authorizationRequestParamsWithValue), clientIdScheme: .redirectUri, applicableFields: authRequestClientIdSchemeMap[.redirectUri]! + ["response_uri","response_mode"])

//  client_id_scheme = redirect_uri, and not equal to client id
let testVPRequestWithRedirectUriAndClientIdNotEqual = createUrlEncodedAuthorizationRequest(requestParams: mergeMaps(authorizationRequestParamsWithValue, ["client_id": "redirect_uri:https://mock-verifier-party.com", "redirect_uri": "https://mock-verifier.com", "response_mode": "fragment"]), clientIdScheme: .redirectUri)

//client_id_scheme = pre-registered
let testValidUrlEncodedVPRequestWithResponseUri = createUrlEncodedAuthorizationRequest(requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdDraft23), clientIdScheme: .preRegistered)

let testUrlEncodedAuthRequestOfUntrustedVerifier = createUrlEncodedAuthorizationRequest(requestParams: mergeMaps(authorizationRequestParamsWithValue, ["client_id": "untrusted_client"]), clientIdScheme: .preRegistered)

// client_id_scheme = pre-registered draft 21
let testValidUrlEncodedVPRequestWithResponseUriDraft21 = createUrlEncodedAuthorizationRequest(requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdDraft21), clientIdScheme: .preRegistered, draftVersion: 21)

// jwt -> client_id_scheme = did
let testValidSignedVPRequestWithDid = createUrlEncodedAuthorizationRequest(requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdDraft23), verifierSentAuthRequestByReference : true, clientIdScheme: .did)

let testInValidSignedVPRequestWithDidAndClientIdDifferent = createUrlEncodedAuthorizationRequest(requestParams: mergeMaps(authorizationRequestParamsWithValue, [
    "client_id": "did:web:inji-ovp:inji-mock-services:openid4vp-service:docs#key-21",
]), verifierSentAuthRequestByReference : true, clientIdScheme: .did)


let testInvalidPresentationDefinitionVPRequest = createUrlEncodedAuthorizationRequest(requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdDraft23, ["presentation_definition": convertToJsonString(["input_descriptor":[]])]), clientIdScheme: .preRegistered)

let urlEncodedAuthorizationRequestWithInvalidClientMetadata = createUrlEncodedAuthorizationRequest(requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientIdDraft23, ["client_metadata": "{}"]),clientIdScheme: .preRegistered)

let validJwtResponse = createAuthorizationRequestObject(clientIdScheme: .did, authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdDraft23))

let invalidJwtResponse = createAuthorizationRequestObject(clientIdScheme: .did, authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdDraft23), addValidSignature: false)

let invalidJwtResponseWithoutKid = createAuthorizationRequestObject(clientIdScheme: .did, authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientIdDraft23), jwsHeaderData: [
    "typ": "oauth-authz-req+jwt",
    "alg": "EdDSA"
])

let resquestUriResponseData: [String: Any] = createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientIdDraft23)) as [String : Any]

let mockUrlEncodedVPRequestWithDirectPostJwt = createUrlEncodedAuthorizationRequest(
    requestParams: mergeMaps(authorizationRequestParamsWithValue.merging(["response_mode": "direct_post.jwt"]) { _, new in new },preRegisteredSchemeClientIdDraft23),clientIdScheme: .preRegistered
)

let mockAuthorizationRequestObjectWithDirectPostResponseMode = getMockAuthorizationRequest()

let mockAuthorizationRequestObjectWithDirectPostJwtResponseMode = getMockAuthorizationRequest(responseMode: .directPostJwt)

let mockSetResponseUri: (String) -> Void = { value in
}

let credentialsMap: [String: [String: Array<Any>]] = [
    "bank_input":
        ["ldp_vc": ["VC1"]],
]

let sampleMdoc = "omdkb2NUeXBldW9yZy5pc28uMTgwMTMuNS4xLm1ETGxpc3N1ZXJTaWduZWSiamlzc3VlckF1dGiEQ6EBJqEYIVkCADCCAfwwggGjAhQF2zbegdWq1XHLmdrVZZIORS_efDAKBggqhkjOPQQDAjCBgDELMAkGA1UEBhMCSU4xCzAJBgNVBAgMAktBMRIwEAYDVQQHDAlCQU5HQUxPUkUxDjAMBgNVBAoMBUlJSVRCMQwwCgYDVQQLDANEQ1MxEDAOBgNVBAMMB0NFUlRJRlkxIDAeBgkqhkiG9w0BCQEWEW1vc2lwcWFAZ21haWwuY29tMB4XDTI1MDIxMjEyMzE1N1oXDTI2MDIxMjEyMzE1N1owgYAxCzAJBgNVBAYTAklOMQswCQYDVQQIDAJLQTESMBAGA1UEBwwJQkFOR0FMT1JFMQ4wDAYDVQQKDAVJSUlUQjEMMAoGA1UECwwDRENTMRAwDgYDVQQDDAdDRVJUSUZZMSAwHgYJKoZIhvcNAQkBFhFtb3NpcHFhQGdtYWlsLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABAcZXrsgNSABzg9o_dNKu6S2pXuJ3hgYlX162Ex56IUGDJZP_IlRCrEQPHZSSl53DwlpL4iHisASqFaRQiXAtqkwCgYIKoZIzj0EAwIDRwAwRAIgGI6B63QccJQ4B84hRjRGlRURJ5SSNTuf74w-nE8zqRACIA3diiD3VCA5G6joGeTSX-Xx79shhDrCmUHuj3Lk5uL1WQJR2BhZAkymZ3ZlcnNpb25jMS4wb2RpZ2VzdEFsZ29yaXRobWdTSEEtMjU2Z2RvY1R5cGV1b3JnLmlzby4xODAxMy41LjEubURMbHZhbHVlRGlnZXN0c6Fxb3JnLmlzby4xODAxMy41LjGoAlggoYW5sb6ESFos65JdcrGlpW4Dzbyye02GzxYpdb14lT4GWCBOKmbymvZx9mlX-zq7fKPzM3BPBp5e8KLD_G4k1GsMSwNYIFlKVBXtrEPyDHpCp-E_MT2RTCduZ6Yvo84kjAj9-F79AVggeYDGTfx8w7Sz2hIQvkZ1QhtrXskhDjZkS_cgN6HP18oEWCBeZlkW29iqUBLxAFlOfHrz5qXioXKKaoyEEYI96YyKvwBYIIlDF4uT1D3MLGPsLL-kVBP0SHyxAYcAVf9SLYLUJUUgB1ggFuI0cmV1WwSJGv5VxI5a7Dsm6fIqr2MeIDBmYjIlZ0oFWCA88kOo8KNGtCpl2XH5CXMcgoE6D_fag9xjmPoLUcpgpG1kZXZpY2VLZXlJbmZvoWlkZXZpY2VLZXmkAQIgASFYICT1yy5zwUTPWESS8KRgFLrkMFnWMbOkNP9vZnRlGppvIlggBl7qoNLfjtf_r6M543nalRUGAt-PNi8u5QvhOf3MQKxsdmFsaWRpdHlJbmZvo2ZzaWduZWTAdDIwMjUtMDQtMTRUMDc6MjE6MjdaaXZhbGlkRnJvbcB0MjAyNS0wNC0xNFQwNzoyMToyN1pqdmFsaWRVbnRpbMB0MjAyNy0wNC0xNFQwNzoyMToyN1pYQMq2sYS6gOyooh4wfLlSN6aAMwTz5ij-gl3whMwvW285Ueasc1qNmsFUnE5-yAphM1xF8F2cMMPWI0CkbiRIGFBqbmFtZVNwYWNlc6Fxb3JnLmlzby4xODAxMy41LjGI2BhYWKRoZGlnZXN0SUQCZnJhbmRvbVBthSy1vmphqpoMYRe9Z0PncWVsZW1lbnRJZGVudGlmaWVyamlzc3VlX2RhdGVsZWxlbWVudFZhbHVlajIwMjUtMDQtMTTYGFhZpGhkaWdlc3RJRAZmcmFuZG9tUNyXhXOZjmheiFyzYfhsl0ZxZWxlbWVudElkZW50aWZpZXJrZXhwaXJ5X2RhdGVsZWxlbWVudFZhbHVlajIwMzAtMDQtMTTYGFifpGhkaWdlc3RJRANmcmFuZG9tUCC-v7ARALJ2VFcYww9AbMhxZWxlbWVudElkZW50aWZpZXJyZHJpdmluZ19wcml2aWxlZ2VzbGVsZW1lbnRWYWx1ZXhIe2lzc3VlX2RhdGU9MjAyNS0wNC0xNCwgdmVoaWNsZV9jYXRlZ29yeV9jb2RlPUEsIGV4cGlyeV9kYXRlPTIwMzAtMDQtMTR92BhYXaRoZGlnZXN0SUQBZnJhbmRvbVDjoYj_8RBZ62-85iZV371vcWVsZW1lbnRJZGVudGlmaWVyb2RvY3VtZW50X251bWJlcmxlbGVtZW50VmFsdWVqOTI2MTQ4MTAyNNgYWFWkaGRpZ2VzdElEBGZyYW5kb21Qg7iWcNbZ-b9S2D3u3Av2YnFlbGVtZW50SWRlbnRpZmllcm9pc3N1aW5nX2NvdW50cnlsZWxlbWVudFZhbHVlYklO2BhYWKRoZGlnZXN0SUQAZnJhbmRvbVAFg1zMFq1oLYxHiib0UCeYcWVsZW1lbnRJZGVudGlmaWVyamJpcnRoX2RhdGVsZWxlbWVudFZhbHVlajE5OTQtMTEtMDbYGFhUpGhkaWdlc3RJRAdmcmFuZG9tUElZm1bdU7M1GlcrQPJ_ctNxZWxlbWVudElkZW50aWZpZXJqZ2l2ZW5fbmFtZWxlbGVtZW50VmFsdWVmSm9zZXBo2BhYVaRoZGlnZXN0SUQFZnJhbmRvbVB_NHtdmXkWLPqVnSgypGGWcWVsZW1lbnRJZGVudGlmaWVya2ZhbWlseV9uYW1lbGVsZW1lbnRWYWx1ZWZBZ2F0aGE="
