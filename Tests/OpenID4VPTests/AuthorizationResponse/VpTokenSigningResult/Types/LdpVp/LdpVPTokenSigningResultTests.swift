import XCTest
@testable import OpenID4VP

final class LdpVPTokenSigningResultTests: XCTestCase {
    
    func testValidateSuccess() throws {
        let validMetadata = ldpVPTokenSigningResult
        
        XCTAssertNoThrow(try validMetadata.validate())
    }
    
    func testValidateFailureEmptyString() {
        let invalidMetadata = LdpVPTokenSigningResult(
            jws: "", proofValue: "valid-proof",
            signatureAlgorithm: ldpVPTokenSigningResult.signatureAlgorithm
        )
        
        XCTAssertThrowsError(try invalidMetadata.validate()) { error in
            XCTAssertEqual(error.localizedDescription, "Invalid Input: LdpVPTokenSigningResult->jws value cannot be empty or null")
        }
    }
    
    func testValidateFailureNullValue() {
        let invalidMetadata = LdpVPTokenSigningResult(
            jws: nil, proofValue: "test",
            signatureAlgorithm: ldpVPTokenSigningResult.signatureAlgorithm
        )
        
        XCTAssertThrowsError(try invalidMetadata.validate()) { error in
            XCTAssertEqual(error.localizedDescription, "Invalid Input: LdpVPTokenSigningResult->jws value cannot be empty or null")
        }
    }
}

