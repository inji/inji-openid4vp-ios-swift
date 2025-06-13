import Foundation

class VPTokenFactory {
    private let vpTokenSigningResult: VPTokenSigningResult
    private let vpTokenSigningPayload: Any
    private let nonce: String
    static let className = String(describing: VPTokenFactory.self)

    init(
        vpTokenSigningResult: VPTokenSigningResult,
        vpTokenSigningPayload: Any,
        nonce: String
    ) {
        self.vpTokenSigningResult = vpTokenSigningResult
        self.vpTokenSigningPayload = vpTokenSigningPayload
        self.nonce = nonce
    }

    func getVPTokenBuilder(credentialFormat: FormatType) throws -> VPTokenBuilder {
        switch credentialFormat {
        case .ldp_vc:
            guard let ldpToken = vpTokenSigningPayload as? LdpVPToken,
                  let ldpResult = vpTokenSigningResult as? LdpVPTokenSigningResult else {
                throw Logger.handleException(
                    exceptionType: "InvalidType",
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
                throw Logger.handleException(
                    exceptionType: "InvalidType",
                    message: "Invalid MSO-MDOC token or signing result type",
                    className: VPTokenFactory.className
                )
            }

            return MdocVPTokenBuilder(
                mdocVPTokenSigningResult: mdocResult,
                credentials: credentialList
            )
        }
    }
}

