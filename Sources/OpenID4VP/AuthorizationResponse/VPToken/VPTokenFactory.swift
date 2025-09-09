import Foundation

class VPTokenFactory {
    private let vpTokenSigningResult: VPTokenSigningResult
    private let vpTokenSigningPayload: Any
    private let nonce: String
    private let uuid: String?
    private let unsignedVpTokens: Any?
    static let className = String(describing: VPTokenFactory.self)

    init(
        vpTokenSigningResult: VPTokenSigningResult,
        vpTokenSigningPayload: Any,
//        TOOD: unsignedVPTokens should not be nil, it has to be value, fix test and remove tbis
        unsignedVPTokens: Any? = nil,
        nonce: String,
        uuid: String? = nil
    ) {
        self.vpTokenSigningResult = vpTokenSigningResult
        self.vpTokenSigningPayload = vpTokenSigningPayload
        self.nonce = nonce
        self.unsignedVpTokens = unsignedVPTokens
        self.uuid = uuid
    }

    func getVPTokenBuilder(credentialFormat: FormatType) throws -> VPTokenBuilder {
        switch credentialFormat {
        case .ldp_vc:
            guard let ldpToken = vpTokenSigningPayload as? LdpVPToken,
                  let ldpResult = vpTokenSigningResult as? LdpVPTokenSigningResult else {
                throw InvalidType(
                    message: "Invalid LDP token or signing result type",
                    className: VPTokenFactory.className
                )
            }
            return LdpVPTokenBuilder(
                ldpVPTokenSigningResult: ldpResult,
                unsignedLdpVPToken: ldpToken,
                nonce: nonce
            )

        case .mso_mdoc:
            guard let credentialList = vpTokenSigningPayload as? [String],
                  let mdocResult = vpTokenSigningResult as? MdocVPTokenSigningResult else {
                throw InvalidType(
                    message: "Invalid MSO-MDOC token or signing result type",
                    className: VPTokenFactory.className
                )
            }

            return MdocVPTokenBuilder(
                mdocVPTokenSigningResult: mdocResult,
                credentials: credentialList
            )
        
        case .dc_sd_jwt, .vc_sd_jwt:
            guard let uuid = self.uuid else {
                throw MissingInput(
                    fieldPath: ["uuid"],
                    message: "UUID is required for SD-JWT VP Token",
                    className: VPTokenFactory.className
                )
            }
            guard let sdJwtVpTokenSigningResult = vpTokenSigningResult as? SdJwtVpTokenSigningResult else {
                throw InvalidType(message: "Invalid SD-JWT signing result type", className: VPTokenFactory.className)
            }
            guard let sdJwtCredentials = vpTokenSigningPayload as? [String: String] else {
                throw InvalidData(message: "sd jwt credential payload must be a dictionary", className: Self.className)
            }
            guard let unsignedSdJwtVpTokens = unsignedVpTokens as? UnsignedSdJWTVPToken else {
                throw InvalidData(message: "unsignedVpTokens must be of type UnsignedSdJWTVPToken", className: Self.className)
            }
            return SdJwtVPTokenBuilder(vpTokenSigningResult: sdJwtVpTokenSigningResult, credentials: sdJwtCredentials , unsignedVpTokens: unsignedSdJwtVpTokens, uuid: uuid)
        
            
        default:
            throw UnsupportedOperationException(
                message: "Unsupported credential format: \(credentialFormat.rawValue)",
                className: VPTokenFactory.className,
                code: "UNSUPPORTED_CREDENTIAL_FORMAT"
            )
        }
    }
}

