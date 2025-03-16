import Foundation

class VPTokenFactory {
    private let vpResponseMetadata:  VPResponseMetadata
    private let vpTokenForSigning:  VPTokenForSigning
    private let nonce: String
    static let className = String(describing: VPTokenFactory.self)

    init(vpResponseMetadata:  VPResponseMetadata,vpTokenForSigning:  VPTokenForSigning, nonce: String) {
        self.vpResponseMetadata = vpResponseMetadata
        self.vpTokenForSigning = vpTokenForSigning
        self.nonce = nonce
    }

    func getVPTokenBuilder(credentialFormat: FormatType) throws -> VpTokenBuilder {
        if(credentialFormat == .ldp_vc){
            return LdpVpTokenBuilder(ldpVPResponseMetadata: self.vpResponseMetadata as! LdpVPResponseMetadata, ldpVPTokenForSigning: self.vpTokenForSigning as! LdpVPTokenForSigning, nonce: nonce)
        } else {
            throw Logger.handleException(exceptionType: "InvalidData", className: VPTokenFactory.className)
        }
    }
}
