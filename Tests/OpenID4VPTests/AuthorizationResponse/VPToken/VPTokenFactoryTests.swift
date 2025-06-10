//import XCTest
//@testable import OpenID4VP
//
//final class VPTokenFactoryTests: XCTestCase {
//    
//    ///Test credential format - ldp_vc
//    
//    func testGetVPTokenBuilder_WithLdpVcFormat() throws {
//        let unsignedToken = UnsignedLdpVPToken(
//            context: ["https://www.w3.org/2018/credentials/v1"],
//            type: ["VerifiablePresentation"],
//            verifiableCredential: [],
//            id: "test-vp-id", holder: "did:example:123"
//        )
//        let nonce = "nonce123"
//        let groupedVcs: [FormatType: [Any]] = [.ldp_vc: ["vc1", "vc2"]]
//        let factory = VPTokenFactory(
//            vpTokenSigningResult: ldpVPTokenSigningResult,
//            unsignedVPToken: unsignedToken,
//            nonce: nonce,
//            groupedVcs: groupedVcs
//        )
//        
//        let builder = try factory.getVPTokenBuilder(credentialFormat: .ldp_vc)
//        
//        XCTAssertTrue(builder is LdpVPTokenBuilder)
//    }
//    
//    ///Test credential format - mso_mdoc
//    func testGetVPTokenBuilder_WithMdocFormat() throws {
//        let unsignedToken = UnsignedMdocVPToken(
//            docTypeToDeviceAuthenticationBytes: ["org.iso.18013.5.1.mDL": "bytes"]
//        )
//        
//        let nonce = "nonce123"
//        let credentials = ["mdoc1", "mdoc2"]
//        let groupedVcs: [FormatType: [Any]] = [.mso_mdoc: credentials]
//        let factory = VPTokenFactory(
//            vpTokenSigningResult: mdocSigningResult,
//            unsignedVPToken: unsignedToken,
//            nonce: nonce,
//            groupedVcs: groupedVcs
//        )
//        
//        let builder = try factory.getVPTokenBuilder(credentialFormat: FormatType.mso_mdoc)
//        
//        XCTAssertTrue(builder is MdocVPTokenBuilder)
//    }
//}
