
@testable import OpenID4VP
import XCTest

final class VPTokenFactoryTests: XCTestCase {
    /// Test credential format - ldp_vc

    func testGetVPTokenBuilder_WithLdpVcFormat() throws {
        let nonce = "nonce123"

        let factory = VPTokenFactory(
            nonce: nonce
        )

        let builder = try factory.getVPTokenBuilder(credentialFormat: .ldp_vc)

        XCTAssertTrue(builder is LdpVPTokenBuilder)
    }

    /// Test credential format - mso_mdoc
    func testGetVPTokenBuilder_WithMdocFormat() throws {
        let nonce = "nonce123"

        let factory = VPTokenFactory(
            nonce: nonce
        )

        let builder = try factory.getVPTokenBuilder(credentialFormat: FormatType.mso_mdoc)

        XCTAssertTrue(builder is MdocVPTokenBuilder)
    }
}
