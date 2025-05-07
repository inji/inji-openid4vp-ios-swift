import XCTest
@testable import OpenID4VP

final class MdocVpTokenSigningResultTests: XCTestCase {

    func testMdocVpTokenSigningResultSuccess() {
        let validDeviceAuth = DeviceAuthentication(
            signature: "validSignature",
            algorithm: "ES256"
        )
        
        let deviceAuthMap = ["org.iso.18013.5.1.mosip": validDeviceAuth]
        let validMetadata = MdocVpTokenSigningResult(deviceAuthenticationBytesSigned: deviceAuthMap)
        
        XCTAssertNoThrow(try validMetadata.validate())
    }
    
    func testMdocVpTokenSigningResultWitInvalidDeviceAuthentication() {
        let invalidDeviceAuth = DeviceAuthentication(
            signature: "",
            algorithm: "ES256"
        )
        
        let invalidMetadata = MdocVpTokenSigningResult(
            deviceAuthenticationBytesSigned: ["org.iso.18013.5.1.mosip": invalidDeviceAuth]
        )
        
        XCTAssertThrowsError(try invalidMetadata.validate()) { error in
            XCTAssertEqual(error.localizedDescription, "Invalid Input: DeviceAuthentication->signature value cannot be empty or null")
        }
    }
    
    func testMdocVpTokenSigningResultWithEmptyInputPassed() {
        let invalidMetadata = MdocVpTokenSigningResult(
            deviceAuthenticationBytesSigned: [:]
        )
        
        XCTAssertThrowsError(try invalidMetadata.validate()) { error in
            XCTAssertEqual(error.localizedDescription, "Invalid Input: MdocVpTokenSigningResult->deviceAuthenticationBytesSigned value cannot be empty or null")
        }
    }
}
