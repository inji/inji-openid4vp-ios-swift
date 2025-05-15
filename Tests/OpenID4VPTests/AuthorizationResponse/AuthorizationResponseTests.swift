import XCTest
@testable import OpenID4VP

final class AuthorizationResponseTests: XCTestCase {
    let mdocVPToken = MdocVPToken(value: "mdoc")
    let ldpVPToken = LdpVPToken(context: ["context"], type: ["typ1"], verifiableCredential: [ldpVC().mapValues { AnyCodable($0) }], id: "identifier", holder: "holder", proof: Proof(type: "Ed25519Signature2018", created: "2021-03-19T15:30:15Z", challenge: "n-0S6_WzA2Mj", domain: "https://client.example.org/cb", jws: "eyJhbG...IAoDA", proofPurpose: .vpProofPurpose, verificationMethod: "did:example:holder#key-1"))
    
    let presentationSubmissionWithMdoc = PresentationSubmission(definitionId: "client-identifier", descriptorMap: [DescriptorMap(id: "input_1", format: .ldp_vp, path: "$", pathNested:nil)])
    let presentationSubmissionWithLdpVPAndMdoc = PresentationSubmission(
        definitionId: "client-identifier",
        descriptorMap: [
            DescriptorMap(id: "input_1", format: .ldp_vp, path: "$[0]", pathNested: PathNested(id: "input_1", format: .ldp_vc, path: "$.verifiableCredential[0]")),
            DescriptorMap(id: "input_2", format: .mso_mdoc, path: "$[1]", pathNested: nil)
        ])
    
    
    func testToJsonEncodedMapWithSingleToken() throws {
        let expectedPresentationSubmission : [String: Any] = [
            "descriptor_map": [
                [
                    "path": "$",
                    "id": "input_1",
                    "format": "ldp_vp"
                ]
                
            ],
            "definition_id": "client-identifier"
        ]
        let authorizationResponse = AuthorizationResponse(
            vpToken: .vpTokenElement(mdocVPToken),
            presentationSubmission: presentationSubmissionWithMdoc,
            state: "test-state"
        )
        
        let result = try authorizationResponse.toJsonEncodedMap()
        
        XCTAssertEqual(result["state"] as? String, "test-state")
        assertDictionariesEqual(expected: expectedPresentationSubmission, actual: result["presentation_submission"] as? [String: Any], strict: false)
        XCTAssertEqual("mdoc", result["vp_token"] as? String)
    }
    
    
    func testToJsonEncodedMapWithTokenArray() throws {
        let expectedVPToken : [Any] = [
            "mdoc",
            [
                "type": [
                    "typ1"
                ],
                "proof":     [
                    "proofPurpose": "authentication",
                    "type": "Ed25519Signature2018",
                    "domain": "https://client.example.org/cb",
                    "verificationMethod": "did:example:holder#key-1",
                    "created": "2021-03-19T15:30:15Z",
                    "jws": "eyJhbG...IAoDA",
                    "challenge": "n-0S6_WzA2Mj"
                ]
                ,
                "id": "identifier",
                "verifiableCredential": [
                    [
                        "type": [
                            "VerifiableCredential",
                            "IDCardCredential"
                        ],
                        "proof":         [
                            "jws": "eyJhb...JQdBw",
                            "type": "Ed25519Signature2018",
                            "created": "2021-03-19T15:30:15Z",
                            "proofPurpose": "assertionMethod",
                            "verificationMethod": "did:example:issuer#keys-1"
                        ]
                        ,
                        "credentialSubject":         [
                            "family_name": "Mockister",
                            "given_name": "MockUser",
                            "birthdate": "1949-01-22"
                        ]
                        ,
                        "id": "https://example.com/credentials/1872",
                        "issuer":         [
                            "id": "did:example:issuer"
                        ]
                        ,
                        "@context": [
                            "https://www.w3.org/2018/credentials/v1",
                            "https://www.w3.org/2018/credentials/examples/v1",
                            [
                                "sec": "https://w3id.org/security#"
                            ]
                            
                        ],
                        "issuanceDate": "2010-01-01T19:23:24Z"
                    ]
                    
                ],
                "holder": "holder",
                "@context": [
                    "context"
                ]
            ]
            
        ]
        let authorizationResponse = AuthorizationResponse(
            vpToken: .vpTokenArray([mdocVPToken, ldpVPToken]),
            presentationSubmission: presentationSubmissionWithLdpVPAndMdoc,
            state: "test-state"
        )
        
        let result = try authorizationResponse.toJsonEncodedMap()
        
        XCTAssertEqual(result["state"] as? String, "test-state")
        assertDictionariesEqual(expected: [
            "descriptor_map": [
                [
                    "format": "ldp_vp",
                    "id": "input_1",
                    "path_nested":       [
                        "path": "$.verifiableCredential[0]",
                        "id": "input_1",
                        "format": "ldp_vc",
                    ],
                    "path": "$[0]"
                ]
                ,
                [
                    "path": "$[1]",
                    "id": "input_2",
                    "format": "mso_mdoc",
                ]
            ],
            "definition_id": "client-identifier"
        ], actual: result["presentation_submission"] as? [String: Any], strict: false)
        assertJsonString(expected: convertToJsonString(expectedVPToken), actual: convertToJsonString(result["vp_token"] as? [Any] ?? []))
    }
    
    func testToJsonEncodedMapWithoutState() throws {
        let expectedPresentationSubmission : [String: Any] = [
            "descriptor_map": [
                [
                    "path": "$",
                    "id": "input_1",
                    "format": "ldp_vp"
                ]
                
            ],
            "definition_id": "client-identifier"
        ]
        let authorizationResponse = AuthorizationResponse(
            vpToken: .vpTokenElement(mdocVPToken),
            presentationSubmission: presentationSubmissionWithMdoc,
            state: nil
        )
        
        let result = try authorizationResponse.toJsonEncodedMap()
        
        XCTAssertNil(result["state"])
        assertDictionariesEqual(expected: expectedPresentationSubmission, actual: result["presentation_submission"] as? [String: Any], strict: false)
        XCTAssertEqual("mdoc", result["vp_token"] as? String)
    }
}
