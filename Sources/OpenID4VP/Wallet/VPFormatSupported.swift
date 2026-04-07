public protocol VPFormatSupported: Codable {}

public struct LdpVcFormatSupported: VPFormatSupported, Codable {
    //TODO: Expose a separate enum for ProofType or accept as string
    let proofTypeValues: [SignatureAlgorithm]?
    let cryptoSuiteValues: [String]?
    
    enum CodingKeys: String, CodingKey {
        case proofTypeValues = "proof_type_values"
        case cryptoSuiteValues = "cryptosuite_values"
    }
    
    public init(proofTypeValues: [SignatureAlgorithm] = [.ed25519Signature2020, .jsonWebSignature2020], cryptoSuiteValues: [String]? = nil) {
        self.proofTypeValues = proofTypeValues
        self.cryptoSuiteValues = cryptoSuiteValues
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        
        if container.contains(.proofTypeValues) {
            var proofTypesArray = try container.nestedUnkeyedContainer(forKey: .proofTypeValues)
            var validProofTypes: [SignatureAlgorithm] = []
            
            while !proofTypesArray.isAtEnd {
                let rawValue = try proofTypesArray.decode(String.self)
                if let signatureAlgorithm = SignatureAlgorithm(rawValue: rawValue) {
                    validProofTypes.append(signatureAlgorithm)
                }
            }
            
            self.proofTypeValues = validProofTypes.isEmpty ? nil : validProofTypes
        } else {
            self.proofTypeValues = nil
        }
        
        self.cryptoSuiteValues = try container.decodeIfPresent([String].self, forKey: .cryptoSuiteValues)
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(proofTypeValues, forKey: .proofTypeValues)
        try container.encodeIfPresent(cryptoSuiteValues, forKey: .cryptoSuiteValues)
    }
}

public struct MsoMdocVcFormatSupported: VPFormatSupported, Codable {
    let issuerAuthAlgValues: [Int]?
    let deviceAuthAlgValues: [Int]?
    
    enum CodingKeys: String, CodingKey {
        case issuerAuthAlgValues = "issuerauth_alg_values"
        case deviceAuthAlgValues = "deviceauth_alg_values"
    }
    
    public init(issuerAuthAlgValues: [Int]? = nil, deviceAuthAlgValues: [Int]? = nil) {
        self.issuerAuthAlgValues = issuerAuthAlgValues
        self.deviceAuthAlgValues = deviceAuthAlgValues
    }
}


public struct SdJwtVcFormatSupported: VPFormatSupported, Codable {
    let sdJwtAlgValues: [String]?
    let kbJwtAlgValues: [String]?
    
    enum CodingKeys: String, CodingKey {
        case sdJwtAlgValues = "sd-jwt_alg_values"
        case kbJwtAlgValues = "kb-jwt_alg_values"
    }
    
    public init(sdJwtAlgValues: [String]? = nil, kbJwtAlgValues: [String]? = nil) {
        self.sdJwtAlgValues = sdJwtAlgValues
        self.kbJwtAlgValues = kbJwtAlgValues
    }
}
