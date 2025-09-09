struct MdocVPToken: Encodable, VPToken {
    // TODO: Base64EncodedDeviceResponse change
    let value: String
    
    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(value)
    }
}
