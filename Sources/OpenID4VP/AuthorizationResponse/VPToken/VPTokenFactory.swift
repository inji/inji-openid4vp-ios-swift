import Foundation

class VPTokenFactory {
    static let className = String(describing: VPTokenFactory.self)
    
    static func getVPTokenBuilder(credentialFormat: FormatType, specVersion: SpecVersion) throws -> VPTokenBuilder {
        switch credentialFormat {
        case .ldp_vc:
            return LdpVPTokenBuilder(specVersion: specVersion)

        case .mso_mdoc:
            return MdocVPTokenBuilder(specVersion: specVersion)

        case .dc_sd_jwt, .vc_sd_jwt:
            return SdJwtVPTokenBuilder(specVersion: specVersion)
        }
    }
}

