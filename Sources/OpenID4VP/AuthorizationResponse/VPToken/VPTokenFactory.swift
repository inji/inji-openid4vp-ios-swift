import Foundation

class VPTokenFactory {
    private let vpTokenSigningResult:  VPTokenSigningResult
    private let unsignedVPToken:  UnsignedVPToken
    private let nonce: String
    private let groupedVcs: [FormatType: [Any]]
    static let className = String(describing: VPTokenFactory.self)
    
    init(vpTokenSigningResult:  VPTokenSigningResult,unsignedVPToken:  UnsignedVPToken, nonce: String, groupedVcs: [FormatType: [Any]]) {
        self.vpTokenSigningResult = vpTokenSigningResult
        self.unsignedVPToken = unsignedVPToken
        self.nonce = nonce
        self.groupedVcs = groupedVcs
    }
    
    func getVPTokenBuilder(credentialFormat: FormatType) throws -> VPTokenBuilder {
        switch credentialFormat {
        case .ldp_vc:
            return LdpVPTokenBuilder(ldpVPTokenSigningResult: self.vpTokenSigningResult as! LdpVPTokenSigningResult, unsignedLdpVPToken: self.unsignedVPToken as! UnsignedLdpVPToken, nonce: nonce)
        case .mso_mdoc:
            return MdocVPTokenBuilder(mdocVPTokenSigningResult: self.vpTokenSigningResult as! MdocVPTokenSigningResult, unsignedMdocVPToken: self.unsignedVPToken as! UnsignedMdocVPToken, credentials: groupedVcs[credentialFormat] as! [String])
        }
    }
}
