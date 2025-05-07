import XCTest
@testable import OpenID4VP

final class MdocVPResponseMetadataTests: XCTestCase {

    func testMdocVPResponseMetadataSuccess() {
        let validDeviceAuth = DeviceAuthentication(
            signature: "validSignature",
            algorithm: "ES256"
        )
        
        let deviceAuthMap = ["org.iso.18013.5.1.mosip": validDeviceAuth]
        let validMetadata = MdocVPResponseMetadata(deviceAuthenticationBytesSigned: deviceAuthMap)
        
        XCTAssertNoThrow(try validMetadata.validate())
    }
    
    func testMdocVPResponseMetadataWitInvalidDeviceAuthentication() {
        let invalidDeviceAuth = DeviceAuthentication(
            signature: "",
            algorithm: "ES256"
        )
        
        let invalidMetadata = MdocVPResponseMetadata(
            deviceAuthenticationBytesSigned: ["org.iso.18013.5.1.mosip": invalidDeviceAuth]
        )
        
        XCTAssertThrowsError(try invalidMetadata.validate()) { error in
            XCTAssertEqual(error.localizedDescription, "Invalid Input: DeviceAuthentication->signature value cannot be empty or null")
        }
    }
    
    func testMdocVPResponseMetadataWithEmptyInputPassed() {
        let invalidMetadata = MdocVPResponseMetadata(
            deviceAuthenticationBytesSigned: [:]
        )
        
        XCTAssertThrowsError(try invalidMetadata.validate()) { error in
            XCTAssertEqual(error.localizedDescription, "Invalid Input: MdocVPResponseMetadata->deviceAuthenticationBytesSigned value cannot be empty or null")
        }
    }
}
