import Foundation

class VPTokenFactory {
    private let vpTokenSigningResult:  VpTokenSigningResult
    private let unsignedVPToken:  UnsignedVPToken
    private let nonce: String
    private let groupedVcs: [FormatType: [Any]]
    static let className = String(describing: VPTokenFactory.self)
    
    init(vpTokenSigningResult:  VpTokenSigningResult,unsignedVPToken:  UnsignedVPToken, nonce: String, groupedVcs: [FormatType: [Any]]) {
        self.vpTokenSigningResult = vpTokenSigningResult
        self.unsignedVPToken = unsignedVPToken
        self.nonce = nonce
        self.groupedVcs = groupedVcs
    }
    
    func getVPTokenBuilder(credentialFormat: FormatType) throws -> VpTokenBuilder {
        switch credentialFormat {
        case .ldp_vc:
            return LdpVpTokenBuilder(ldpVpTokenSigningResult: self.vpTokenSigningResult as! LdpVpTokenSigningResult, unsignedLdpVPToken: self.unsignedVPToken as! UnsignedLdpVPToken, nonce: nonce)
        case .mso_mdoc:
            return MdocVPTokenBuilder(mdocVPResponeMetadata: self.vpTokenSigningResult as! MdocVpTokenSigningResult, unsignedMdocVPToken: self.unsignedVPToken as! UnsignedMdocVPToken, credentials: groupedVcs[credentialFormat] as! [String])
        }
    }
}
