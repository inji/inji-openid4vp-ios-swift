import Foundation

public struct WalletMetadata: Codable {
    let presentationDefinitionURISupported: Bool
    let vpFormatsSupported: [VPFormatType: VPFormatSupported]
    let clientIdSchemesSupported: [ClientIdScheme]
    var requestObjectSigningAlgValuesSupported: [RequestSigningAlgorithm]?
    let authorizationEncryptionAlgValuesSupported: [KeyManagementAlgorithm]?
    let authorizationEncryptionEncValuesSupported: [ContentEncryptionAlgorithm]?
    let responseTypesSupported: [ResponseType]
    static let className = String(describing: WalletMetadata.self)
    
    enum CodingKeys: String, CodingKey {
        case presentationDefinitionURISupported = "presentation_definition_uri_supported"
        case vpFormatsSupported = "vp_formats_supported"
        case clientIdSchemesSupported = "client_id_schemes_supported"
        case requestObjectSigningAlgValuesSupported = "request_object_signing_alg_values_supported"
        case authorizationEncryptionAlgValuesSupported = "authorization_encryption_alg_values_supported"
        case authorizationEncryptionEncValuesSupported = "authorization_encryption_enc_values_supported"
        case responseTypesSupported = "response_types_supported"
    }
    
    @available(*, deprecated, message: "Use the initializer with explicit parameters instead.")
    public init(
        presentationDefinitionURISupported: Bool?,
        vpFormatsSupported: [String: VPFormatSupported],
        clientIdSchemesSupported: [String]?,
        requestObjectSigningAlgValuesSupported: [String]? = nil,
        authorizationEncryptionAlgValuesSupported: [String]? = nil,
        authorizationEncryptionEncValuesSupported: [String]? = nil
    ) throws {
        self.presentationDefinitionURISupported = presentationDefinitionURISupported ?? true
        self.vpFormatsSupported = try parseVPFormatsSupported(vpFormatsSupported)
        self.clientIdSchemesSupported = try parseClientIdSchemesSupported(clientIdSchemesSupported)
        self.requestObjectSigningAlgValuesSupported = try parseRequestObjectSigningAlgValuesSupported(requestObjectSigningAlgValuesSupported)
        self.authorizationEncryptionAlgValuesSupported = try parseAuthorizationEncryptionAlgValuesSupported(authorizationEncryptionAlgValuesSupported)
        self.authorizationEncryptionEncValuesSupported = try parseAuthorizationEncryptionEncValuesSupported(authorizationEncryptionEncValuesSupported)
        self.responseTypesSupported = WalletMetadataDefaults.responseTypesSupported
        
        try validateVPFormatsSupported(self.vpFormatsSupported)
    }
    
    public init(
        presentationDefinitionURISupported: Bool = WalletMetadataDefaults.presentationDefinitionURISupported,
        vpFormatsSupported: [VPFormatType: VPFormatSupported] = WalletMetadataDefaults.vpFormatsSupportedSpecVersionDraft23,
        clientIdSchemesSupported: [ClientIdScheme] = WalletMetadataDefaults.clientIdSchemesSupported,
        requestObjectSigningAlgValuesSupported: [RequestSigningAlgorithm]? = WalletMetadataDefaults.requestObjectSigningAlgValuesSupported,
        authorizationEncryptionAlgValuesSupported: [KeyManagementAlgorithm]? = WalletMetadataDefaults.authorizationEncryptionAlgValuesSupported,
        authorizationEncryptionEncValuesSupported: [ContentEncryptionAlgorithm]? = WalletMetadataDefaults.authorizationEncryptionEncValuesSupported,
        responseTypesSupported: [ResponseType] = WalletMetadataDefaults.responseTypesSupported
    ) throws {
        self.presentationDefinitionURISupported = presentationDefinitionURISupported
        self.vpFormatsSupported = vpFormatsSupported
        self.clientIdSchemesSupported = clientIdSchemesSupported
        self.requestObjectSigningAlgValuesSupported = requestObjectSigningAlgValuesSupported
        self.authorizationEncryptionAlgValuesSupported = authorizationEncryptionAlgValuesSupported
        self.authorizationEncryptionEncValuesSupported = authorizationEncryptionEncValuesSupported
        self.responseTypesSupported = responseTypesSupported
        
        try validateVPFormatsSupported(vpFormatsSupported)
    }
}

public struct VPFormatSupported: Codable {
    let algValuesSupported: [String]?
    
    enum CodingKeys: String, CodingKey {
        case algValuesSupported = "alg_values_supported"
    }
    
    public init(algValuesSupported: [String]? = nil) {
        self.algValuesSupported = algValuesSupported
    }
}
