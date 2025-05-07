//
//  PresentationDefinitionUtilTests.swift
//  OpenID4VP
//
//  Created by Kiruthika Jeyashankar on 06/05/25.
//

import XCTest
@testable import OpenID4VP

final class PresentationDefinitionUtilTests: XCTestCase {
    // in case of presentation definition with format having mso_mdoc, response_mode should not be any other than direct_post.jwt
    func testThrowErrorWhenResponseModeIsNotDirectPostJwtButRequstConatainsMdocRequest() {
        _ = """
        {
            "presentation_definition": {
                "id": "id card credential",
                "input_descriptors": [
                    {
                        "id": "input descriptor id",
                        "format": {
                            "mso_mdoc": {
                                "alg": ["ES256"],
                            }
                        },
                        "constraints": {
                            "fields": [
                                {
                                    "path": ["$['org.iso.18013.5.1:mosip']['document_number']"],
                                    "intent_to_retain": true,
                                 }
                            ],
                        }                                  
                    }
                ],
                "format": {
                    "mso_mdoc": {
                        "alg": ["ES256"],
                    }
                }
            },  
            "response_mode": "direct_post"
        }
    """
    }
    
    func testParseAndValidatePresentationDefinitionWithMdocFormatAndInvalidResponseMode() async throws {
        // Arrange
        let input: [String: Any] = [
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
            "response_mode": "invalid_response_mode"
        ]
        let isPresentationDefinitionUriSupported = true
        let networkManager = MockNetworkManager() // Replace with a mock implementation of `NetworkManaging`

        await assertAsyncThrowsError(try await parseAndValidatePresentationDefinition(input, isPresentationDefinitionUriSupported, networkManager)) { error in
//            XCTAssertEqual(error.exceptionType, "InvalidData")
            XCTAssertEqual(error.localizedDescription, "When mso_mdoc format is present in presentation definition, response_mode must be direct_post.jwt")
        }
    }
}
