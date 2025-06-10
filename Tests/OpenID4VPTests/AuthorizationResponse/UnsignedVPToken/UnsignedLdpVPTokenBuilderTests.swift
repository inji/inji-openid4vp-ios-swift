//import XCTest
//@testable import OpenID4VP
//
//final class UnsignedLdpVPTokenBuilderTests: XCTestCase {
//    func testCreationOfUnsignedLdpVPToken() throws {
//        let unsignedLdpVPToken : UnsignedLdpVPToken = try UnsignedLdpVPTokenBuilder(verifiableCredential: [ldpVC()], id: "ebc6f1c2", holder: "did:example:wallet").build() as! UnsignedLdpVPToken
//        
//        XCTAssertEqual(unsignedLdpVPToken.context, ["https://www.w3.org/2018/credentials/v1"])
//        XCTAssertEqual(unsignedLdpVPToken.type, ["VerifiablePresentation"])
//        XCTAssertEqual(unsignedLdpVPToken.id, "ebc6f1c2")
//        XCTAssertEqual(unsignedLdpVPToken.holder, "did:example:wallet")
//        XCTAssertTrue(unsignedLdpVPToken.verifiableCredential.count == 1)
//    }
//}
