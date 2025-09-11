struct MdocVPToken: Encodable, VPToken {
    // TODO: Base64EncodedDeviceResponse change
    let base64EncodedDeviceResponse: String
    
    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(base64EncodedDeviceResponse)
    }
}
