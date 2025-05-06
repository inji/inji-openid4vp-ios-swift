public struct UnsignedLdpVPToken: Codable, UnsignedVPToken {
    //TODO: Move default params to build method
    let context = ["https://www.w3.org/2018/credentials/v1"]
    let type = ["VerifiablePresentation"]
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

