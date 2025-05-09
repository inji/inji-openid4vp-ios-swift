import XCTest
@testable import OpenID4VP

final class MdocVPTokenSigningResultTests: XCTestCase {
    func testMdocVPTokenSigningResultSuccess() {
        let validDeviceAuth = DeviceAuthentication(
            signature: "validSignature",
            algorithm: "ES256"
        )
        
        let deviceAuthMap = ["org.iso.18013.5.1.mosip": validDeviceAuth]
        let validMetadata = MdocVPTokenSigningResult(deviceAuthenticationBytesSigned: deviceAuthMap)
        
        XCTAssertNoThrow(try validMetadata.validate())
    }
    
    func testMdocVPTokenSigningResultWitInvalidDeviceAuthentication() {
        let invalidDeviceAuth = DeviceAuthentication(
            signature: "",
            algorithm: "ES256"
        )
        
        let invalidMetadata = MdocVPTokenSigningResult(
            deviceAuthenticationBytesSigned: ["org.iso.18013.5.1.mosip": invalidDeviceAuth]
        )
        
        XCTAssertThrowsError(try invalidMetadata.validate()) { error in
            XCTAssertEqual(error.localizedDescription, "Invalid Input: DeviceAuthentication->signature value cannot be empty or null")
        }
    }
    
    func testMdocVPTokenSigningResultWithEmptyInputPassed() {
        let invalidMetadata = MdocVPTokenSigningResult(
            deviceAuthenticationBytesSigned: [:]
        )
        
        XCTAssertThrowsError(try invalidMetadata.validate()) { error in
            XCTAssertEqual(error.localizedDescription, "Invalid Input: MdocVPTokenSigningResult->deviceAuthenticationBytesSigned value cannot be empty or null")
        }
    }
}
