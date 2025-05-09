struct LdpVPToken: Encodable, VPToken {
    let context: [String]
    let type: [String]
    let verifiableCredential: [String]
    let id: String
    let holder: String
    let proof: Proof
    
    static let internalPath : String = "verifiableCredential"
    
    public enum CodingKeys: String, CodingKey {
        case context = "@context"
        case type
        case verifiableCredential
        case id
        case holder
        case proof
    }
}
