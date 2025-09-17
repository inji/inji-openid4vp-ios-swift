import Foundation

class VPTokenFactory {
    private let nonce: String
    static let className = String(describing: VPTokenFactory.self)
    
    init(nonce: String) {
        self.nonce = nonce
    }
    
    func getVPTokenBuilder(credentialFormat: FormatType) throws -> VPTokenBuilder {
        switch credentialFormat {
        case .ldp_vc:
            return LdpVPTokenBuilder(nonce: nonce)
            
        case .mso_mdoc:
            return MdocVPTokenBuilder()
            
        case .dc_sd_jwt, .vc_sd_jwt:
            return SdJwtVPTokenBuilder()
            
        default:
            throw UnsupportedOperationException(
                message: "Unsupported credential format: \(credentialFormat.rawValue)",
                className: VPTokenFactory.className,
                code: "UNSUPPORTED_CREDENTIAL_FORMAT"
            )
        }
    }
}

