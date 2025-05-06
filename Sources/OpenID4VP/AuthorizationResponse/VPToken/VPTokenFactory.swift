import Foundation

class VPTokenFactory {
    private let vpResponseMetadata:  VPResponseMetadata
    private let unsignedVPToken:  UnsignedVPToken
    private let nonce: String
    private let groupedVcs: [FormatType: [Any]]
    static let className = String(describing: VPTokenFactory.self)

    init(vpResponseMetadata:  VPResponseMetadata,unsignedVPToken:  UnsignedVPToken, nonce: String, groupedVcs: [FormatType: [Any]]) {
        self.vpResponseMetadata = vpResponseMetadata
        self.unsignedVPToken = unsignedVPToken
        self.nonce = nonce
        self.groupedVcs = groupedVcs
    }

    func getVPTokenBuilder(credentialFormat: FormatType) throws -> VpTokenBuilder {
        if(credentialFormat == .ldp_vc){
            return LdpVpTokenBuilder(ldpVPResponseMetadata: self.vpResponseMetadata as! LdpVPResponseMetadata, unsignedLdpVPToken: self.unsignedVPToken as! UnsignedLdpVPToken, nonce: nonce)
        } else if (credentialFormat == .mso_mdoc){
            return MdocVPTokenBuilder(mdocVPResponeMetadata: self.vpResponseMetadata as! MdocVPResponseMetadata, unsignedMdocVPToken: self.unsignedVPToken as! UnsignedMdocVPToken, nonce: nonce, credentials: groupedVcs[credentialFormat] as! [String])
        }else {
            throw Logger.handleException(exceptionType: "InvalidData", className: VPTokenFactory.className)
        }
    }
}
