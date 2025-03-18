import OpenID4VP
import Foundation

public struct MockEncodable: Codable, Equatable {
    let name: String
    let age: Int
}

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

let preRegisteredVerifiers = createVerifiers(from: testVerifierList)

let verifiableCredentialsList : [String : [FormatType : Array<Any>]] = ["input_descriptor1": [FormatType.ldp_vc : ["VC1"]]]

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
            "publicKey": "IKXhA7W1HD1sAl+OfG59VKAqciWrrOL1Rw5F+PGLhi4=",
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

let redirectUriSchemeClientId: [String: String] = [
    "client_id": "redirect_uri:https://mock-verifier.com",
]

let DidSchemeClientId: [String: String] = [
    "client_id": "did:web:inji-ovp:inji-mock-services:openid4vp-service:docs",
]

let preRegisteredSchemeClientId: [String: String] = [
    "client_id": "mock-client",
]

let authRequestParamsByReference : [String] = [
    "client_id",
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

let authRequestWithPreRegisteredByValue : [String] = [
    "client_id",
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
    ClientIdScheme.did : authRequestWithPreRegisteredByValue
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
        "mso_mdoc": [
            "alg": [
                "ES256",
                "EdDSA"
            ]
        ],
        "ldp_vp": [
            "proof_type": [
                "Ed25519Signature2018",
                "Ed25519Signature2020",
                "RsaSignature2018"
            ]
        ]
    ]
]

let mockClientMetadataObject = createInstance(clientMetadata, as: ClientMetadata.self)

var vpResponseMetadata = LdpVPResponseMetadata(
    jws: "validJWS",
    signatureAlgorithm: "RSA",
    publicKey: "validPublicKey",
    domain: "validDomain"
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
    requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientId),
    clientIdScheme: .preRegistered,
    applicableFields: authRequestWithPreRegisteredByValue.map {
        $0 == AuthorizationRequestFieldConstants.presentationDefinition.rawValue ? AuthorizationRequestFieldConstants.presentationDefinitionUri.rawValue : $0
    }
)

// client_id_scheme = redirect_uri
let testValidUrlEncodedVpRequestWithRedirectUri = createUrlEncodedAuthorizationRequest(
    requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientId),
    clientIdScheme: .redirectUri,
    applicableFields: authRequestWithRedirectUriByValue.map { $0 == AuthorizationRequestFieldConstants.redirectUri.rawValue ? AuthorizationRequestFieldConstants.responseUri.rawValue : $0 }
)

//  client_id_scheme = redirect_uri, with response uri and response mode
let testVpRequestWithRedirectUriAndResponseUriResponseMode = createUrlEncodedAuthorizationRequest(requestParams: mergeMaps( redirectUriSchemeClientId,  authorizationRequestParamsWithValue), clientIdScheme: .redirectUri, applicableFields: authRequestClientIdSchemeMap[.redirectUri]! + ["response_uri","response_mode"])

//  client_id_scheme = redirect_uri, and not equal to client id
let testVpRequestWithRedirectUriAndClientIdNotEqual = createUrlEncodedAuthorizationRequest(requestParams: mergeMaps(authorizationRequestParamsWithValue, ["client_id": "redirect_uri:https://mock-verifier-party.com", "redirect_uri": "https://mock-verifier.com", "response_mode": "fragment"]), clientIdScheme: .redirectUri)

//client_id_scheme = pre-registered
let testValidUrlEncodedVpRequestWithResponseUri = createUrlEncodedAuthorizationRequest(requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientId), clientIdScheme: .preRegistered)

// jwt -> client_id_scheme = did
let testValidSignedVpRequestWithDid = createUrlEncodedAuthorizationRequest(requestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientId), verifierSentAuthRequestByReference : true, clientIdScheme: .did)

let testInValidSignedVpRequestWithDidAndClientIdDifferent = createUrlEncodedAuthorizationRequest(requestParams: mergeMaps(authorizationRequestParamsWithValue, [
    "client_id": "did:web:inji-ovp:inji-mock-services:openid4vp-service:docs#key-21",
]), verifierSentAuthRequestByReference : true, clientIdScheme: .did)


let testInvalidPresentationDefinitionVpRequest = createUrlEncodedAuthorizationRequest(requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientId, ["presentation_definition": convertToJsonString(["input_descriptor":[]])]), clientIdScheme: .preRegistered)

let urlEncodedAuthorizationRequestWithInvalidClientMetadata = createUrlEncodedAuthorizationRequest(requestParams: mergeMaps(authorizationRequestParamsWithValue, preRegisteredSchemeClientId, ["client_metadata": "{}"]),clientIdScheme: .preRegistered)

let validJwtResponse = createAuthorizationRequestObject(clientIdScheme: .did, authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientId))

let invalidJwtResponse = createAuthorizationRequestObject(clientIdScheme: .did, authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientId), addValidSignature: false)

let invalidJwtResponseWithoutKid = createAuthorizationRequestObject(clientIdScheme: .did, authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue, DidSchemeClientId), jwsHeaderData: [
    "typ": "oauth-authz-req+jwt",
    "alg": "EdDSA"
])

let resquestUriResponseData: [String: Any] = createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, redirectUriSchemeClientId)) as [String : Any]

let mockUrlEncodedVpRequestWithDirectPostJwt = createUrlEncodedAuthorizationRequest(
    requestParams: mergeMaps(authorizationRequestParamsWithValue.merging(["response_mode": "direct_post.jwt"]) { _, new in new },preRegisteredSchemeClientId),clientIdScheme: .preRegistered
)

let mockAuthorizationRequestObjectWithDirectPostResponseMode = getMockAuthorizationRequest()

let mockAuthorizationRequestObjectWithDirectPostJwtResponseMode = getMockAuthorizationRequest(responseMode: .directPostJwt)

let mockSetResponseUri: (String) -> Void = { value in
}

let credentialsMap: [String: [String: Array<Any>]] = [
    "bank_input":
        ["ldp_vc": ["VC1"]],
]
