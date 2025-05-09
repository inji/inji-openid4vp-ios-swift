import Foundation

class LdpVPTokenBuilder : VPTokenBuilder {
    private(set) var ldpVPTokenSigningResult:  LdpVPTokenSigningResult
    private(set) var unsignedLdpVPToken:  UnsignedLdpVPToken
    private(set) var nonce: String
    
    init(ldpVPTokenSigningResult:  LdpVPTokenSigningResult,unsignedLdpVPToken:  UnsignedLdpVPToken, nonce: String) {
        self.ldpVPTokenSigningResult = ldpVPTokenSigningResult
        self.unsignedLdpVPToken = unsignedLdpVPToken
        self.nonce = nonce
    }
    
    func build() throws -> VPToken {
        try ldpVPTokenSigningResult.validate()
        let proof = Proof.construct(from: ldpVPTokenSigningResult, challenge: self.nonce)
        return LdpVPToken(
            context: unsignedLdpVPToken.context,
            type: unsignedLdpVPToken.type,
            verifiableCredential: unsignedLdpVPToken.verifiableCredential,
            id: unsignedLdpVPToken.id,
            holder: unsignedLdpVPToken.holder,
            proof: proof
        )
    }
}
