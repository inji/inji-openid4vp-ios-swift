import Foundation

class VPTokenFactory {
    private let vpResponseMetadata:  VPResponseMetadata
    private let unsignedVPToken:  UnsignedVPToken
    private let nonce: String
    static let className = String(describing: VPTokenFactory.self)

    init(vpResponseMetadata:  VPResponseMetadata,unsignedVPToken:  UnsignedVPToken, nonce: String) {
        self.vpResponseMetadata = vpResponseMetadata
        self.unsignedVPToken = unsignedVPToken
        self.nonce = nonce
    }

    func getVPTokenBuilder(credentialFormat: FormatType) throws -> VpTokenBuilder {
        if(credentialFormat == .ldp_vc){
            return LdpVpTokenBuilder(ldpVPResponseMetadata: self.vpResponseMetadata as! LdpVPResponseMetadata, unsignedLdpVPToken: self.unsignedVPToken as! UnsignedLdpVPToken, nonce: nonce)
        } else {
            throw Logger.handleException(exceptionType: "InvalidData", className: VPTokenFactory.className)
        }
    }
}
