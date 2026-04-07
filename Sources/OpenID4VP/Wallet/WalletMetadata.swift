import Foundation

public struct WalletMetadata: Codable {
    let vpFormatsSupported: [VPFormatType: VPFormatSupported]
    let clientIdPrefixesSupported: [ClientIdPrefix]
    var requestObjectSigningAlgValuesSupported: [RequestSigningAlgorithm]?
    let authorizationEncryptionAlgValuesSupported: [KeyManagementAlgorithm]?
    let authorizationEncryptionEncValuesSupported: [ContentEncryptionAlgorithm]?
    let responseTypesSupported: [ResponseType]
    static let className = String(describing: WalletMetadata.self)
    
    enum CodingKeys: String, CodingKey {
        case vpFormatsSupported = "vp_formats_supported"
        case clientIdPrefixesSupported = "client_id_prefixes_supported"
        case requestObjectSigningAlgValuesSupported = "request_object_signing_alg_values_supported"
        case authorizationEncryptionAlgValuesSupported = "authorization_encryption_alg_values_supported"
        case authorizationEncryptionEncValuesSupported = "authorization_encryption_enc_values_supported"
        case responseTypesSupported = "response_types_supported"
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let vpFormatsContainer = try container.nestedContainer(keyedBy: VPFormatType.self, forKey: .vpFormatsSupported)
        var decodedFormats: [VPFormatType: VPFormatSupported] = [:]
        for key in vpFormatsContainer.allKeys {
            switch key {
            case .ldp_vc, .ldp_vp:
                let value = try vpFormatsContainer.decode(LdpVcFormatSupported.self, forKey: key)
                decodedFormats[key] = value
            case .mso_mdoc:
                let value = try vpFormatsContainer.decode(MsoMdocVcFormatSupported.self, forKey: key)
                decodedFormats[key] = value
            case .dc_sd_jwt, .vc_sd_jwt:
                let value = try vpFormatsContainer.decode(SdJwtVcFormatSupported.self, forKey: key)
                decodedFormats[key] = value
            }
        }
        self.vpFormatsSupported = decodedFormats
        self.clientIdPrefixesSupported = try container.decode([ClientIdPrefix].self, forKey: .clientIdPrefixesSupported)
        self.requestObjectSigningAlgValuesSupported = try container.decodeIfPresent([RequestSigningAlgorithm].self, forKey: .requestObjectSigningAlgValuesSupported)
        self.authorizationEncryptionAlgValuesSupported = try container.decodeIfPresent([KeyManagementAlgorithm].self, forKey: .authorizationEncryptionAlgValuesSupported)
        self.authorizationEncryptionEncValuesSupported = try container.decodeIfPresent([ContentEncryptionAlgorithm].self, forKey: .authorizationEncryptionEncValuesSupported)
        self.responseTypesSupported = try container.decode([ResponseType].self, forKey: .responseTypesSupported)
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        var vpFormatsContainer = container.nestedContainer(keyedBy: VPFormatType.self, forKey: .vpFormatsSupported)
        for (key, value) in vpFormatsSupported {
            switch key {
            case .ldp_vc, .ldp_vp:
                try vpFormatsContainer.encode(try cast(value, to: LdpVcFormatSupported.self), forKey: key)
            case .mso_mdoc:
                try vpFormatsContainer.encode(try cast(value, to: MsoMdocVcFormatSupported.self), forKey: key)
            case .dc_sd_jwt, .vc_sd_jwt:
                try vpFormatsContainer.encode(try cast(value, to: SdJwtVcFormatSupported.self), forKey: key)
            }
        }
        try container.encode(clientIdPrefixesSupported, forKey: .clientIdPrefixesSupported)
        try container.encodeIfPresent(requestObjectSigningAlgValuesSupported, forKey: .requestObjectSigningAlgValuesSupported)
        try container.encodeIfPresent(authorizationEncryptionAlgValuesSupported, forKey: .authorizationEncryptionAlgValuesSupported)
        try container.encodeIfPresent(authorizationEncryptionEncValuesSupported, forKey: .authorizationEncryptionEncValuesSupported)
        try container.encode(responseTypesSupported, forKey: .responseTypesSupported)
    }
    
    public init(
        vpFormatsSupported: [VPFormatType: VPFormatSupported] = WalletMetadataDefaults.vpFormatsSupported,
        clientIdPrefixesSupported: [ClientIdPrefix] = WalletMetadataDefaults.clientIdPrefixesSupported,
        requestObjectSigningAlgValuesSupported: [RequestSigningAlgorithm]? = WalletMetadataDefaults.requestObjectSigningAlgValuesSupported,
        authorizationEncryptionAlgValuesSupported: [KeyManagementAlgorithm]? = WalletMetadataDefaults.authorizationEncryptionAlgValuesSupported,
        authorizationEncryptionEncValuesSupported: [ContentEncryptionAlgorithm]? = WalletMetadataDefaults.authorizationEncryptionEncValuesSupported,
        responseTypesSupported: [ResponseType] = WalletMetadataDefaults.responseTypesSupported
    ) {
        self.vpFormatsSupported = vpFormatsSupported
        self.clientIdPrefixesSupported = clientIdPrefixesSupported
        self.requestObjectSigningAlgValuesSupported = requestObjectSigningAlgValuesSupported
        self.authorizationEncryptionAlgValuesSupported = authorizationEncryptionAlgValuesSupported
        self.authorizationEncryptionEncValuesSupported = authorizationEncryptionEncValuesSupported
        self.responseTypesSupported = responseTypesSupported
    }
    
    internal func encode(specVersion: SpecVersion) throws -> String {
        switch specVersion {
        case .v1:
            return try encodeAsJSON(self, fieldName: "wallet_metadata", className: Self.className)
        case .draft23:
            var walletMetadataDict: [String: Any] = [:]
            
            let vpFormats: [String: [String: [String]]] = self.vpFormatsSupported.reduce(into: [:]) { result, vpFormatSupported in
                let credentialFormat = vpFormatSupported.key.rawValue
                if let algValues = vpFormatSupported.value.toAlgValuesSupported() {
                    result[credentialFormat] = ["alg_values_supported": algValues]
                } else {
                    result[credentialFormat] = [:]
                }
            }
            walletMetadataDict["presentation_definition_uri_supported"] = true
            walletMetadataDict["vp_formats_supported"] = vpFormats
            walletMetadataDict["client_id_schemes_supported"] = self.clientIdPrefixesSupported.map { ClientIdPrefix.toClientIdScheme($0) }
            if let requestAlgs = self.requestObjectSigningAlgValuesSupported {
                walletMetadataDict["request_object_signing_alg_values_supported"] = requestAlgs.map { $0.rawValue }
            }
            if let encAlgs = self.authorizationEncryptionAlgValuesSupported {
                walletMetadataDict["authorization_encryption_alg_values_supported"] = encAlgs.map { $0.rawValue }
            }
            if let encValues = self.authorizationEncryptionEncValuesSupported {
                walletMetadataDict["authorization_encryption_enc_values_supported"] = encValues.map { $0.rawValue }
            }
            walletMetadataDict["response_types_supported"] = self.responseTypesSupported.map { $0.rawValue }
            
            let jsonData = try JSONSerialization.data(withJSONObject: walletMetadataDict)
            return String(data: jsonData, encoding: .utf8) ?? ""
        }
    }
}

private func cast<T>(_ value: Any, to type: T.Type) throws -> T {
    guard let casted = value as? T else {
        throw UnsupportedTypeDecoding(message: "Failed to cast value to \(T.self)", className: WalletMetadata.className)
    }
    return casted
}

private func encodeAsJSON<T: Encodable>(_ value: T, fieldName: String, className: String) throws -> String {
    return try encode(value, fieldName: fieldName, className: className)
}

