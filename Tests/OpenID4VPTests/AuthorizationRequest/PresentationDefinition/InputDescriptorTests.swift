//
//  InputDescriptorTests.swift
//  
//
//  Created by Kiruthika Jeyashankar on 21/03/25.
//

import XCTest
@testable import OpenID4VP

final class InputDescriptorTests: XCTestCase {
    func testNoThrowErrorForValidInputDescriptot() {
        let jsonData = """
        {
          "id": "id card credential",
          "format": {
            "ldp_vc": {
              "proof_type": [
                "Ed25519Signature2018"
              ]
            }
          },
          "constraints": {
            "fields": [
              {
                "path": [
                  "$.type"
                ],
                "filter": {
                  "type": "string",
                  "pattern": "IDCardCredential"
                }
              }
            ]
          }
        }
        """.data(using: .utf8)!
        
        XCTAssertNoThrow(try JSONDecoder().decode(InputDescriptor.self, from: jsonData))
    }
    
    func testThrowErrorWhenInputDescriptorIdIsEmpty() {
        let inputDescriptorWithInvalidId = """
        {
          "id": "",
          "format": {
            "ldp_vc": {
              "proof_type": [
                "Ed25519Signature2018"
              ]
            }
          },
          "constraints": {
            "fields": [
              {
                "path": [
                  "$.type"
                ],
                "filter": {
                  "type": "string",
                  "pattern": "IDCardCredential"
                }
              }
            ]
          }
        }
        """.data(using: .utf8)!
        
        XCTAssertThrowsError(try JSONDecoder().decode(InputDescriptor.self, from: inputDescriptorWithInvalidId)) { error in
            XCTAssertEqual("Invalid Input: input_descriptor->id value cannot be empty or null", error.localizedDescription)
        }
    }
    
    func testThrowErrorWhenInputDescriptorNameIsEmpty() {
        let inputDescriptorWithInvalidName = """
        {
          "id": "id card credenital",
          "name": "",
          "format": {
            "ldp_vc": {
              "proof_type": [
                "Ed25519Signature2018"
              ]
            }
          },
          "constraints": {
            "fields": [
              {
                "path": [
                  "$.type"
                ],
                "filter": {
                  "type": "string",
                  "pattern": "IDCardCredential"
                }
              }
            ]
          }
        }
        """.data(using: .utf8)!
        
        XCTAssertThrowsError(try JSONDecoder().decode(InputDescriptor.self, from: inputDescriptorWithInvalidName)) { error in
            XCTAssertEqual("Invalid Input: input_descriptor->name value cannot be empty or null", error.localizedDescription)
        }
    }
    
    func testThrowErrorWhenInputDescriptorPurposeIsEmpty() {
        let inputDescriptorWithInvalidPurpose = """
        {
          "id": "id card credenital",
          "name": "ID card details",
          "purpose": "",
          "format": {
            "ldp_vc": {
              "proof_type": [
                "Ed25519Signature2018"
              ]
            }
          },
          "constraints": {
            "fields": [
              {
                "path": [
                  "$.type"
                ],
                "filter": {
                  "type": "string",
                  "pattern": "IDCardCredential"
                }
              }
            ]
          }
        }
        """.data(using: .utf8)!
        
        XCTAssertThrowsError(try JSONDecoder().decode(InputDescriptor.self, from: inputDescriptorWithInvalidPurpose)) { error in
            XCTAssertEqual("Invalid Input: input_descriptor->purpose value cannot be empty or null", error.localizedDescription)
        }
    }
    
    func testThrowErrorWhenInputDescriptorFormatHasEntryWithEmptyProofType() {
        let inputDescriptorWithInvalidFormatField = """
        {
          "id": "id card credenital",
          "name": "ID card details",
          "purpose": "We can only allow people with valid ID for registration of event",
          "format": {
            "ldp_vc": {
              "proof_type": []
            }
          },
          "constraints": {
            "fields": [
              {
                "path": [
                  "$.type"
                ],
                "filter": {
                  "type": "string",
                  "pattern": "IDCardCredential"
                }
              }
            ]
          }
        }
        """.data(using: .utf8)!
        
        XCTAssertThrowsError(try JSONDecoder().decode(InputDescriptor.self, from: inputDescriptorWithInvalidFormatField)) { error in
            XCTAssertEqual("Invalid Input: ldpFormat->proof_type value cannot be empty or null", error.localizedDescription)
        }
    }
}
