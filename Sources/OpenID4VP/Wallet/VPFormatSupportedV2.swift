public protocol VPFormatSupportedV2: Codable {}

public struct LdpVcFormatSupported: VPFormatSupportedV2, Codable {
    let proofTypeValues: [SignatureAlgorithm]
    let cryptoSuiteValues: [String]?
    
    enum CodingKeys: String, CodingKey {
        case proofTypeValues = "proof_types_values"
        case cryptoSuiteValues = "cryptosuite_values"
    }
    
    init(proofTypeValues: [SignatureAlgorithm] = [.ed25519Signature2020, .jsonWebSignature2020], cryptoSuiteValues: [String]? = nil) {
        self.proofTypeValues = proofTypeValues
        self.cryptoSuiteValues = cryptoSuiteValues
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(proofTypeValues, forKey: .proofTypeValues)
        try container.encodeIfPresent(cryptoSuiteValues, forKey: .cryptoSuiteValues)
    }
}

public struct MsoMdocVcFormatSupported: VPFormatSupportedV2, Codable {
    let issuerAuthAlgValues: [String]?
    let deviceAuthAlgValues: [String]?
    
    enum CodingKeys: String, CodingKey {
        case issuerAuthAlgValues = "issuerauth_alg_values"
        case deviceAuthAlgValues = "deviceauth_alg_values"
    }
    
    init(issuerAuthAlgValues: [String]? = nil, deviceAuthAlgValues: [String]? = nil) {
        self.issuerAuthAlgValues = issuerAuthAlgValues
        self.deviceAuthAlgValues = deviceAuthAlgValues
    }
}


public struct SdJwtVcFormatSupported: VPFormatSupportedV2, Codable {
    let sdJwtAlgValues: [String]?
    let kbJwtAlgValues: [String]?
    
    enum CodingKeys: String, CodingKey {
        case sdJwtAlgValues = "sd-jwt_alg_values"
        case kbJwtAlgValues = "kb-jwt_alg_values"
    }
    
    init(sdJwtAlgValues: [String]? = nil, kbJwtAlgValues: [String]? = nil) {
        self.sdJwtAlgValues = sdJwtAlgValues
        self.kbJwtAlgValues = kbJwtAlgValues
    }
}
