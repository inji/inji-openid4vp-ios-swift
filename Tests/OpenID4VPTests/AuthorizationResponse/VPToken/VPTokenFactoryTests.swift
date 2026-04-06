
@testable import OpenID4VP
import XCTest

final class VPTokenFactoryTests: XCTestCase {
    func testGetVPTokenBuilder_WithLdpVcFormat() throws {
        let builder = try VPTokenFactory.getVPTokenBuilder(credentialFormat: .ldp_vc, specVersion: .draft23)
        XCTAssertTrue(builder is LdpVPTokenBuilder)
        XCTAssertEqual(builder.specVersion, .draft23)
    }

    func testGetVPTokenBuilder_WithMdocFormat() throws {
        let builder = try VPTokenFactory.getVPTokenBuilder(credentialFormat: FormatType.mso_mdoc, specVersion: .v1)
        XCTAssertTrue(builder is MdocVPTokenBuilder)
        XCTAssertEqual(builder.specVersion, .v1)
    }

    func testGetVPTokenBuilder_WithSdJwtFormat() throws {
        let vcSdJwtBuilder = try VPTokenFactory.getVPTokenBuilder(credentialFormat: FormatType.vc_sd_jwt, specVersion: .draft23)
        XCTAssertTrue(vcSdJwtBuilder is SdJwtVPTokenBuilder)
        XCTAssertEqual(vcSdJwtBuilder.specVersion, .draft23)

        let dcSdJwtBuilder = try VPTokenFactory.getVPTokenBuilder(credentialFormat: FormatType.dc_sd_jwt, specVersion: .v1)
        XCTAssertTrue(dcSdJwtBuilder is SdJwtVPTokenBuilder)
        XCTAssertEqual(dcSdJwtBuilder.specVersion, .v1)
    }
}
