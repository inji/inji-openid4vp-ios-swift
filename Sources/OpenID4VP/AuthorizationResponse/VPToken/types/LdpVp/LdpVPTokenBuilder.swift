import Foundation

class LdpVPTokenBuilder: VPTokenBuilder {
    private let ldpVPTokenSigningResult: LdpVPTokenSigningResult
    private let unsignedLdpVPToken: LdpVPToken
    private let nonce: String
    private let className = "LdpVPTokenBuilder"

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

    func build(
        credentialInputDescriptorMappings: [CredentialInputDescriptorMapping],
        unsignedVPTokenResult: (payload: Any?, unsignedVPToken: UnsignedVPToken),
        vpTokenSigningResult: VPTokenSigningResult,
        rootIndex: Int
    ) throws -> (vpTokens: [VPToken], DescriptorMaps: [DescriptorMap], nextIndex: Int) {
        guard let ldpVPTokenSigningResult = vpTokenSigningResult as? LdpVPTokenSigningResult else {
            throw InvalidData(message: "vpTokenSigningResult is not LdpVPTokenSigningResult", className: className)
        }
        try ldpVPTokenSigningResult.validate()
        guard let unsignedLdpVPToken = unsignedVPTokenResult.payload as? LdpVPToken else {
            throw InvalidData(message: "payload is not LdpVPToken", className: className)
        }
        var proof = unsignedLdpVPToken.proof
        proof?.proofValue = ldpVPTokenSigningResult.proofValue
        proof?.jws = ldpVPTokenSigningResult.jws
        let ldpVPToken = LdpVPToken(
            context: unsignedLdpVPToken.context,
            type: unsignedLdpVPToken.type,
            verifiableCredential: unsignedLdpVPToken.verifiableCredential,
            id: unsignedLdpVPToken.id,
            holder: unsignedLdpVPToken.holder,
            proof: proof!
        )
        let descriptorMaps = credentialInputDescriptorMappings.map { mapping in
            DescriptorMap(
                id: mapping.inputDescriptorId,
                format: .ldp_vp,
                path: createDescriptorMapPath(rootIndex),
                pathNested: createNestedPath(
                    id: mapping.inputDescriptorId,
                    nestedPath: mapping.nestedPath,
                    format: .ldp_vc
                )
            )
        }
        return ([ldpVPToken], descriptorMaps, rootIndex + 1)
    }
}
