import XCTest
@testable import OpenID4VP

final class LdpVPTokenSigningResultTests: XCTestCase {
    
    func testValidateSuccess() throws {
        let validMetadata = ldpVPTokenSigningResult
        
        XCTAssertNoThrow(try validMetadata.validate())
    }
    
    func testValidateFailureEmptyString() {
        let invalidMetadata = LdpVPTokenSigningResult(
            jws: "",
            signatureAlgorithm: ldpVPTokenSigningResult.signatureAlgorithm,
            publicKey: ldpVPTokenSigningResult.publicKey,
            domain: ldpVPTokenSigningResult.domain
        )
        
        XCTAssertThrowsError(try invalidMetadata.validate()) { error in
            XCTAssertEqual(error.localizedDescription, "Invalid Input: vp response metadata-> value cannot be empty or null")
        }
    }
    
    func testValidateFailureNullValue() {
        let invalidMetadata = LdpVPTokenSigningResult(
            jws: "null",
            signatureAlgorithm: ldpVPTokenSigningResult.signatureAlgorithm,
            publicKey: ldpVPTokenSigningResult.publicKey,
            domain: ldpVPTokenSigningResult.domain
        )
        
        XCTAssertThrowsError(try invalidMetadata.validate()) { error in
            XCTAssertEqual(error.localizedDescription, "Invalid Input: vp response metadata->null value cannot be empty or null")
        }
    }
}

