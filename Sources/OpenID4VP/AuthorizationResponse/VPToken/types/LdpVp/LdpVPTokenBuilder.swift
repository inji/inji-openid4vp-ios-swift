import Foundation

class LdpVpTokenBuilder : VpTokenBuilder {
    private(set) var ldpVPResponseMetadata:  LdpVPResponseMetadata
    private(set) var ldpVPTokenForSigning:  LdpVPTokenForSigning
    private(set) var nonce: String
    
    init(ldpVPResponseMetadata:  LdpVPResponseMetadata,ldpVPTokenForSigning:  LdpVPTokenForSigning, nonce: String) {
        self.ldpVPResponseMetadata = ldpVPResponseMetadata
        self.ldpVPTokenForSigning = ldpVPTokenForSigning
        self.nonce = nonce
    }
    
    func build() throws -> VPToken {
        try ldpVPResponseMetadata.validate()
        let proof = Proof.construct(from: ldpVPResponseMetadata, challenge: self.nonce)
        return LdpVpToken(
            context: ldpVPTokenForSigning.context,
            type: ldpVPTokenForSigning.type,
            verifiableCredential: ldpVPTokenForSigning.verifiableCredential,
            id: ldpVPTokenForSigning.id,
            holder: ldpVPTokenForSigning.holder,
            proof: proof
        )
    }
}
