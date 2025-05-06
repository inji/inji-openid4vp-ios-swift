public struct UnsignedLdpVPToken: Codable, UnsignedVPToken {
    let context: [String]
    let type: [String]
    let verifiableCredential: [String]
    let id: String
    let holder: String

    enum CodingKeys: String, CodingKey {
        case context = "@context"
        case type
        case verifiableCredential
        case id
        case holder
    }
}

