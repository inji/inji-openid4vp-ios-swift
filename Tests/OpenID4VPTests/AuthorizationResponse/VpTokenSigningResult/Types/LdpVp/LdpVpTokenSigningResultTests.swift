import XCTest
@testable import OpenID4VP

final class LdpVpTokenSigningResultTests: XCTestCase {
    
    func testValidateSuccess() throws {
        let validMetadata = vpTokenSigningResult
        
        XCTAssertNoThrow(try validMetadata.validate())
    }
    
    func testValidateFailureEmptyString() {
        let invalidMetadata = LdpVpTokenSigningResult(
            jws: "",
            signatureAlgorithm: vpTokenSigningResult.signatureAlgorithm,
            publicKey: vpTokenSigningResult.publicKey,
            domain: vpTokenSigningResult.domain
        )
        
        XCTAssertThrowsError(try invalidMetadata.validate()) { error in
            XCTAssertEqual(error.localizedDescription, "Invalid Input: vp response metadata-> value cannot be empty or null")
        }
    }
    
    func testValidateFailureNullValue() {
        let invalidMetadata = LdpVpTokenSigningResult(
            jws: "null",
            signatureAlgorithm: vpTokenSigningResult.signatureAlgorithm,
            publicKey: vpTokenSigningResult.publicKey,
            domain: vpTokenSigningResult.domain
        )
        
        XCTAssertThrowsError(try invalidMetadata.validate()) { error in
            XCTAssertEqual(error.localizedDescription, "Invalid Input: vp response metadata->null value cannot be empty or null")
        }
    }
}

