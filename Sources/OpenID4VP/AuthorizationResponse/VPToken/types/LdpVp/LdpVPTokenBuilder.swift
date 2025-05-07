import Foundation

class LdpVpTokenBuilder : VpTokenBuilder {
    private(set) var ldpVpTokenSigningResult:  LdpVpTokenSigningResult
    private(set) var unsignedLdpVPToken:  UnsignedLdpVPToken
    private(set) var nonce: String
    
    init(ldpVpTokenSigningResult:  LdpVpTokenSigningResult,unsignedLdpVPToken:  UnsignedLdpVPToken, nonce: String) {
        self.ldpVpTokenSigningResult = ldpVpTokenSigningResult
        self.unsignedLdpVPToken = unsignedLdpVPToken
        self.nonce = nonce
    }
    
    func build() throws -> VPToken {
        try ldpVpTokenSigningResult.validate()
        let proof = Proof.construct(from: ldpVpTokenSigningResult, challenge: self.nonce)
        return LdpVpToken(
            context: unsignedLdpVPToken.context,
            type: unsignedLdpVPToken.type,
            verifiableCredential: unsignedLdpVPToken.verifiableCredential,
            id: unsignedLdpVPToken.id,
            holder: unsignedLdpVPToken.holder,
            proof: proof
        )
    }
}
