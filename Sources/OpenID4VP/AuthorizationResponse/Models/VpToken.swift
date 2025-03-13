public struct VPToken: Encodable {
    let context: [String]
    let type: [String]
    let verifiableCredential: [String]
    let id: String
    let holder: String
    let proof: Proof
    
    enum CodingKeys: String, CodingKey {
        case context = "@context"
        case type
        case verifiableCredential
        case id
        case holder
        case proof
    }
    
    static func construct(signingVPToken: VpTokenForSigning, proof: Proof) -> Self {
        return VPToken(
            context: signingVPToken.context,
            type: signingVPToken.type,
            verifiableCredential: signingVPToken.verifiableCredential,
            id: signingVPToken.id,
            holder: signingVPToken.holder,
            proof: proof
        )
    }
}
