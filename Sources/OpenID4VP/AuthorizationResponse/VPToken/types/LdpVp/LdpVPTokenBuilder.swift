import Foundation

class LdpVpTokenBuilder : VpTokenBuilder {
    private(set) var ldpVPResponseMetadata:  LdpVPResponseMetadata
    private(set) var unsignedLdpVPToken:  UnsignedLdpVPToken
    private(set) var nonce: String
    
    init(ldpVPResponseMetadata:  LdpVPResponseMetadata,unsignedLdpVPToken:  UnsignedLdpVPToken, nonce: String) {
        self.ldpVPResponseMetadata = ldpVPResponseMetadata
        self.unsignedLdpVPToken = unsignedLdpVPToken
        self.nonce = nonce
    }
    
    func build() throws -> VPToken {
        try ldpVPResponseMetadata.validate()
        let proof = Proof.construct(from: ldpVPResponseMetadata, challenge: self.nonce)
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
