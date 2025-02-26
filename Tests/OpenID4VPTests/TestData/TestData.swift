import OpenID4VP
import Foundation

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

let didDocumentUrl = URL(string: "https://inji-ovp/inji-mock-services/openid4vp-service/docs/did.json")!
let httpUrlResponseForJWT: HTTPURLResponse = HTTPURLResponse(url: didDocumentUrl, statusCode: 200, httpVersion: "", headerFields: ["Content-Type": "application/oauth-authz-req+jwt"])!
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

let clientIdAndSchemeOfRedirectUri: [String: String] = [
    "client_id": "https://mock-verifier.com",
    "client_id_scheme": ClientIdScheme.redirectUri.rawValue,
]

let clientIdAndSchemeOfDid: [String: String] = [
    "client_id": "did:web:inji-ovp:inji-mock-services:openid4vp-service:docs",
    "client_id_scheme": ClientIdScheme.did.rawValue,
]

let clientIdAndSchemeOfPreRegistered: [String: String] = [
    "client_id": "mock-client",
    "client_id_scheme": ClientIdScheme.preRegistered.rawValue,
]

let authRequestParamsByReference : [String] = [
    "client_id",
    "client_id_scheme",
    "request_uri",
    "request_uri_method"
]

let authRequestWithRedirectUriByValue : [String] = [
    "client_id",
    "client_id_scheme",
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
    "client_id_scheme",
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

let clientMetadata: [String: Any] = [
    "client_name": "Requester name",
    "logo_uri": "https://mock-verifier.com/logo",
    "authorization_encrypted_response_alg": "ECDH-ES",
    "authorization_encrypted_response_enc": "A256GCM",
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
    requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfPreRegistered),
    clientIdScheme: .preRegistered,
    applicableFields: authRequestWithPreRegisteredByValue.map {
        $0 == AuthorizationRequestFieldConstants.presentationDefinition.rawValue ? AuthorizationRequestFieldConstants.presentationDefinitionUri.rawValue : $0
    }
)

// client_id_scheme = redirect_uri
let testValidUrlEncodedVpRequestWithRedirectUri = createUrlEncodedAuthorizationRequest(
    requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfRedirectUri),
    clientIdScheme: .redirectUri,
    applicableFields: authRequestWithRedirectUriByValue.map { $0 == AuthorizationRequestFieldConstants.redirectUri.rawValue ? AuthorizationRequestFieldConstants.responseUri.rawValue : $0 }
)

//  client_id_scheme = redirect_uri, with response uri and response mode
let testVpRequestWithRedirectUriAndResponseUriResponseMode = createUrlEncodedAuthorizationRequest(requestParams: mergeMaps( clientIdAndSchemeOfRedirectUri,  authorizationRequestParamsWithValue), clientIdScheme: .redirectUri, applicableFields: authRequestClientIdSchemeMap[.redirectUri]! + ["response_uri","response_mode"])

//  client_id_scheme = redirect_uri, and not equal to client id
let testVpRequestWithRedirectUriAndClientIdNotEqual = createUrlEncodedAuthorizationRequest(requestParams: mergeMaps(authorizationRequestParamsWithValue, ["client_id": "https://mock-verifier-party.com","client_id_scheme": "redirect_uri", "redirect_uri": "https://mock-verifier.com", "response_mode": "fragment"]), clientIdScheme: .redirectUri)

//client_id_scheme = pre-registered
let testValidUrlEncodedVpRequestWithResponseUri = createUrlEncodedAuthorizationRequest(requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfPreRegistered), clientIdScheme: .preRegistered)

// jwt -> client_id_scheme = did
let testValidSignedVpRequestWithDid = createUrlEncodedAuthorizationRequest(requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfDid), verifierSentAuthRequestByReference : true, clientIdScheme: .did)

let testInValidSignedVpRequestWithDidAndClientIdDifferent = createUrlEncodedAuthorizationRequest(requestParams: mergeMaps(authorizationRequestParamsWithValue, [
    "client_id": "did:web:inji-ovp:inji-mock-services:openid4vp-service:docs#key-21",
    "client_id_scheme": ClientIdScheme.did.rawValue,
]), verifierSentAuthRequestByReference : true, clientIdScheme: .did)


let testInvalidPresentationDefinitionVpRequest = createUrlEncodedAuthorizationRequest(requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfPreRegistered, ["presentation_definition": convertToJsonString(["input_descriptor":[]])]), clientIdScheme: .preRegistered)

let urlEncodedAuthorizationRequestWithInvalidClientMetadata = createUrlEncodedAuthorizationRequest(requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfPreRegistered, ["client_metadata": "{}"]),clientIdScheme: .preRegistered)

let validJwtResponse = createAuthorizationRequestObject(clientIdScheme: .did, authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfDid))

let invalidJwtResponse = createAuthorizationRequestObject(clientIdScheme: .did, authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfDid), addValidSignature: false)

let invalidJwtResponseWithoutKid = createAuthorizationRequestObject(clientIdScheme: .did, authorizationRequestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfDid), jwtHeaderData: [
    "typ": "oauth-authz-req+jwt",
    "alg": "EdDSA"
])

let resquestUriResponseData: [String: Any] = createAuthorizationRequest(paramList: authRequestWithRedirectUriByValue , requestParams: mergeMaps(authorizationRequestParamsWithValue, clientIdAndSchemeOfRedirectUri)) as [String : Any]

