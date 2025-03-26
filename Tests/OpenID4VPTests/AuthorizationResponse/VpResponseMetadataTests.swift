import XCTest
@testable import OpenID4VP

final class VpResponseMetadataTests: XCTestCase {
    
    func testValidateSuccess() throws {
    
        let validMetadata = vpResponseMetadata
        
        XCTAssertNoThrow(try validMetadata.validate())
    }
    
    func testValidateFailureEmptyString() {
        let invalidMetadata = LdpVPResponseMetadata(
            jws: "",
            signatureAlgorithm: vpResponseMetadata.signatureAlgorithm,
            publicKey: vpResponseMetadata.publicKey,
            domain: vpResponseMetadata.domain
        )
        
        XCTAssertThrowsError(try invalidMetadata.validate()) { error in
            XCTAssertEqual(error.localizedDescription, "Invalid Input: vp response metadata-> value cannot be empty or null")
        }
    }
    
    func testValidateFailureNullValue() {
        let invalidMetadata = LdpVPResponseMetadata(
            jws: "null",
            signatureAlgorithm: vpResponseMetadata.signatureAlgorithm,
            publicKey: vpResponseMetadata.publicKey,
            domain: vpResponseMetadata.domain
        )
        
        XCTAssertThrowsError(try invalidMetadata.validate()) { error in
            XCTAssertEqual(error.localizedDescription, "Invalid Input: vp response metadata->null value cannot be empty or null")
        }
    }
}

