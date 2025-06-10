import Foundation

class LdpVPTokenBuilder: VPTokenBuilder {
    private let ldpVPTokenSigningResult: LdpVPTokenSigningResult
    private let unsignedLdpVPToken: LdpVPToken
    private let nonce: String

    init(ldpVPTokenSigningResult: LdpVPTokenSigningResult,
         unsignedLdpVPToken: LdpVPToken,
         nonce: String) {
        self.ldpVPTokenSigningResult = ldpVPTokenSigningResult
        self.unsignedLdpVPToken = unsignedLdpVPToken
        self.nonce = nonce
    }

    func build() throws -> VPToken {
        try ldpVPTokenSigningResult.validate()

        var signedProof = unsignedLdpVPToken.proof
        signedProof?.jws = ldpVPTokenSigningResult.jws
        signedProof?.proofValue = ldpVPTokenSigningResult.proofValue

        return LdpVPToken(
            context: unsignedLdpVPToken.context,
            type: unsignedLdpVPToken.type,
            verifiableCredential: unsignedLdpVPToken.verifiableCredential,
            id: unsignedLdpVPToken.id,
            holder: unsignedLdpVPToken.holder,
            proof: signedProof!
        )
    }
}
