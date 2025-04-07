import Foundation

public struct WalletMetadata: Codable {
    let presentationDefinitionURISupported: Bool
    let vpFormatsSupported: [String: VPFormatSupported]
    let clientIdSchemesSupported: [String]
    var requestObjectSigningAlgValuesSupported: [String]?
    let authorizationEncryptionAlgValuesSupported: [String]?
    let authorizationEncryptionEncValuesSupported: [String]?
    
    enum CodingKeys: String, CodingKey {
        case presentationDefinitionURISupported = "presentation_definition_uri_supported"
        case vpFormatsSupported = "vp_formats_supported"
        case clientIdSchemesSupported = "client_id_schemes_supported"
        case requestObjectSigningAlgValuesSupported = "request_object_signing_alg_values_supported"
        case authorizationEncryptionAlgValuesSupported = "authorization_encryption_alg_values_supported"
        case authorizationEncryptionEncValuesSupported = "authorization_encryption_enc_values_supported"
    }
    
    public init(
        presentationDefinitionURISupported: Bool = true,
        vpFormatsSupported: [String: VPFormatSupported],
        clientIdSchemesSupported: [String] = [ClientIdScheme.preRegistered.rawValue],
        requestObjectSigningAlgValuesSupported: [String]? = nil,
        authorizationEncryptionAlgValuesSupported: [String]? = nil,
        authorizationEncryptionEncValuesSupported: [String]? = nil
    ) {
        self.presentationDefinitionURISupported = presentationDefinitionURISupported
        self.vpFormatsSupported = vpFormatsSupported
        self.clientIdSchemesSupported = clientIdSchemesSupported
        self.requestObjectSigningAlgValuesSupported = requestObjectSigningAlgValuesSupported
        self.authorizationEncryptionAlgValuesSupported = authorizationEncryptionAlgValuesSupported
        self.authorizationEncryptionEncValuesSupported = authorizationEncryptionEncValuesSupported
    }
}

public struct VPFormatSupported: Codable {
    let algValuesSupported: [String]?

    enum CodingKeys: String, CodingKey {
        case algValuesSupported = "alg_values_supported"
    }

    public init(algValuesSupported: [String]?) {
        self.algValuesSupported = algValuesSupported
    }
}
