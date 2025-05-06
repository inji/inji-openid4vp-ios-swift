import XCTest
@testable import OpenID4VP

final class MdocVPTokenBuilderTests: XCTestCase {
    let unsignedToken = UnsignedMdocVPToken(deviceAuthenticationBytes: ["org.iso.18013.5.1.mosip": "bytes"])
    
    func testBuildsVPTokenSuccessfullyWithValidInput() {
        let metadata = MdocVPResponseMetadata(deviceAuthenticationBytesSigned: ["docType1": DeviceAuthentication(signature: "validSignature", algorithm: "RS256")])
        let authorizationRequest = getMockAuthorizationRequest()
        let credentials = [
            """
            {
                "docType": "docType1"
            }
            """
        ]
        let builder = MdocVPTokenBuilder(mdocVPResponeMetadata: metadata, unsignedMdocVPToken: unsignedToken, nonce: authorizationRequest.nonce, credentials: credentials)
        
        XCTAssertNoThrow(try builder.build())
    }
    
    func testThrowsErrorWhenCredentialIsInvalidCBOR() {
        let metadata = MdocVPResponseMetadata(deviceAuthenticationBytesSigned: ["docType1": DeviceAuthentication(signature: "validSignature", algorithm: "RS256")])
        let authorizationRequest = getMockAuthorizationRequest()
        let credentials = ["invalidCBOR"]
        let builder = MdocVPTokenBuilder(mdocVPResponeMetadata: metadata, unsignedMdocVPToken: unsignedToken, nonce: authorizationRequest.nonce, credentials: credentials)
        
        XCTAssertThrowsError(try builder.build()) { error in
            XCTAssertEqual((error as NSError).domain, "Invalid Verifiable Credential")
            XCTAssertEqual((error as NSError).code, 1001)
        }
    }
    
    func testThrowsErrorWhenDocTypeIsMissingInCredential() {
        let metadata = MdocVPResponseMetadata(deviceAuthenticationBytesSigned: ["docType1": DeviceAuthentication(signature: "validSignature", algorithm: "RS256")])
        let authorizationRequest = getMockAuthorizationRequest()
        let credentials = [
            """
            {
                "invalidKey": "value"
            }
            """
        ]
        let builder = MdocVPTokenBuilder(mdocVPResponeMetadata: metadata, unsignedMdocVPToken: unsignedToken, nonce: authorizationRequest.nonce, credentials: credentials)
        
        XCTAssertThrowsError(try builder.build()) { error in
            XCTAssertEqual((error as NSError).domain, "Invalid Verifiable Credential")
            XCTAssertEqual((error as NSError).code, 1002)
        }
    }
    
    func testThrowsErrorWhenDeviceAuthenticationBytesAreMissing() {
        let metadata = MdocVPResponseMetadata(deviceAuthenticationBytesSigned: ["docType1": DeviceAuthentication(signature: "validSignature", algorithm: "RS256")])
        let authorizationRequest = getMockAuthorizationRequest()
        let credentials = [
            """
            {
                "docType": "docType1"
            }
            """
        ]
        let builder = MdocVPTokenBuilder(mdocVPResponeMetadata: metadata, unsignedMdocVPToken: unsignedToken, nonce: authorizationRequest.nonce, credentials: credentials)
        
        XCTAssertThrowsError(try builder.build()) { error in
            XCTAssertEqual((error as NSError).domain, "Invalid Verifiable Credential")
            XCTAssertEqual((error as NSError).code, 1003)
        }
    }
    
    func testThrowsErrorWhenMetadataValidationFails() {
        let metadata = MdocVPResponseMetadata(deviceAuthenticationBytesSigned: [:]) // Invalid metadata
        let authorizationRequest = getMockAuthorizationRequest()
        let credentials = [
            """
            {
                "docType": "docType1"
            }
            """
        ]
        let builder = MdocVPTokenBuilder(mdocVPResponeMetadata: metadata, unsignedMdocVPToken: unsignedToken, nonce: authorizationRequest.nonce, credentials: credentials)
        
        XCTAssertThrowsError(try builder.build())
    }
}
