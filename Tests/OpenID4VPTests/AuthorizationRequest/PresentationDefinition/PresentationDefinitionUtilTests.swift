import XCTest
@testable import OpenID4VP

final class PresentationDefinitionUtilTests: XCTestCase {
    private let isPresentationDefinitionUriSupported = true
    private let networkManager = MockNetworkManager()

    // in case of presentation definition with format having mso_mdoc, response_mode should not be any other than direct_post.jwt
    func testParseAndValidatePresentationDefinitionWithMdocFormatAndInvalidResponseMode() async throws {
        let testCases = [
            TestCase(input: [
                "presentation_definition": [
                    "id": "id card credential",
                    "input_descriptors": [
                        [
                            "id": "input descriptor id",
                            "format": [
                                "mso_mdoc": [
                                    "alg": ["ES256"]
                                ]
                            ],
                            "constraints": [
                                "fields": [
                                    [
                                        "path": ["$['org.iso.18013.5.1:mosip']['document_number']"],
                                        "intent_to_retain": true
                                    ]
                                ]
                            ]
                        ]
                    ],
                    "format": [
                        "mso_mdoc": [
                            "alg": ["ES256"]
                        ]
                    ]
                ],
                "response_mode": "direct_post"
            ]
                    ),
            TestCase(input:
                        [
                            "presentation_definition": [
                                "id": "id card credential",
                                "input_descriptors": [
                                    [
                                        "id": "input descriptor id",
                                        "constraints": [
                                            "fields": [
                                                [
                                                    "path": ["$['org.iso.18013.5.1:mosip']['document_number']"],
                                                    "intent_to_retain": true
                                                ]
                                            ]
                                        ]
                                    ]
                                ],
                                "format": [
                                    "mso_mdoc": [
                                        "alg": ["ES256"]
                                    ]
                                ]
                            ],
                            "response_mode": "direct_post"
                        ]
                    ),
            TestCase(input: [
                "presentation_definition": [
                    "id": "id card credential",
                    "input_descriptors": [
                        [
                            "id": "input descriptor id",
                            "format": [
                                "mso_mdoc": [
                                    "alg": ["ES256"]
                                ]
                            ],
                            "constraints": [
                                "fields": [
                                    [
                                        "path": ["$['org.iso.18013.5.1:mosip']['document_number']"],
                                        "intent_to_retain": true
                                    ]
                                ]
                            ]
                        ]
                    ]
                ],
                "response_mode": "direct_post"
            ])
        ]

        for testCase in testCases {
            await assertAsyncThrowsError(try await parseAndValidatePresentationDefinition(testCase.input, isPresentationDefinitionUriSupported, networkManager)) { error in
                assertOpenID4VPException(error,
                    expectedMessage: "When mso_mdoc format is present in presentation definition, response_mode must be direct_post.jwt",
                    expectedCode: OpenID4VPErrorCodes.invalidRequest
                )
            }

        }
    }
}
