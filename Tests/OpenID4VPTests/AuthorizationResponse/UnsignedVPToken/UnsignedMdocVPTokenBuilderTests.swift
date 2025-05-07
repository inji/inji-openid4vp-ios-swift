import XCTest
@testable import OpenID4VP

final class UnsignedMdocVPTokenBuilderTests: XCTestCase {
    func testCreationOfUnsignedMdocVPToken() throws {
        let unsignedMdocVPToken : UnsignedMdocVPToken = try UnsignedMdocVPTokenBuilder(mdocCredentials: [sampleMdoc], clientId: "client-id", responseUri: "response-uri", verifierNonce: "verifier-nonce", mdocGeneratedNonce: "wallet-nonce").build() as! UnsignedMdocVPToken
        
        assertDictionariesEqual(expected: ["org.iso.18013.5.1.mDL": "d8185885847444657669636541757468656e7469636174696f6e83f6f683582025f063606ff45acabf6cf500710f3a749d8e12d8c29e517f7575d48fedf5dc295820afde2e4ec03639ec57e705210b665a26d24c9766d0b6a346a96e590d2a56f6bb6c77616c6c65742d6e6f6e6365756f72672e69736f2e31383031332e352e312e6d444cd81841a0"], actual: unsignedMdocVPToken.deviceAuthenticationBytes)
    }
    
    func testThrowErrorWhenUnableToDecodeCredential() throws {
        let unsignedMdocVPTokenBuilder : UnsignedMdocVPTokenBuilder =  UnsignedMdocVPTokenBuilder(mdocCredentials: ["invalidCBOR"], clientId: "client-id", responseUri: "response-uri", verifierNonce: "verifier-nonce", mdocGeneratedNonce: "wallet-nonce")
        
        XCTAssertThrowsError(try unsignedMdocVPTokenBuilder.build()) { error in
            XCTAssertEqual(error.localizedDescription, "Invalid Verifiable Credential: Error while decoding credential")
        }
    }
}
