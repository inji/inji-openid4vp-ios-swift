import Foundation

public struct WalletMetadata: Codable {
    let presentationDefinitionURISupported: Bool
    let vpFormatsSupported: [FormatType: VPFormatSupported]
    let clientIdSchemesSupported: [ClientIdScheme]
    var requestObjectSigningAlgValuesSupported: [RequestSigningAlgorithm]?
    let authorizationEncryptionAlgValuesSupported: [KeyManagementAlgorithm]?
    let authorizationEncryptionEncValuesSupported: [ContentEncryptionAlgorithm]?
    static let className = String(describing: WalletMetadata.self)

    enum CodingKeys: String, CodingKey {
        case presentationDefinitionURISupported = "presentation_definition_uri_supported"
        case vpFormatsSupported = "vp_formats_supported"
        case clientIdSchemesSupported = "client_id_schemes_supported"
        case requestObjectSigningAlgValuesSupported = "request_object_signing_alg_values_supported"
        case authorizationEncryptionAlgValuesSupported = "authorization_encryption_alg_values_supported"
        case authorizationEncryptionEncValuesSupported = "authorization_encryption_enc_values_supported"
    }

    public init(
        presentationDefinitionURISupported: Bool?,
        vpFormatsSupported: [FormatType: VPFormatSupported],
        clientIdSchemesSupported: [ClientIdScheme]?,
        requestObjectSigningAlgValuesSupported: [RequestSigningAlgorithm]? = nil,
        authorizationEncryptionAlgValuesSupported: [KeyManagementAlgorithm]? = nil,
        authorizationEncryptionEncValuesSupported: [ContentEncryptionAlgorithm]? = nil
    ) throws {
        self.presentationDefinitionURISupported = presentationDefinitionURISupported ?? true
        self.vpFormatsSupported = vpFormatsSupported
        self.clientIdSchemesSupported = clientIdSchemesSupported ?? [ClientIdScheme.preRegistered]
        self.requestObjectSigningAlgValuesSupported = requestObjectSigningAlgValuesSupported
        self.authorizationEncryptionAlgValuesSupported = authorizationEncryptionAlgValuesSupported
        self.authorizationEncryptionEncValuesSupported = authorizationEncryptionEncValuesSupported

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

private func validateVPFormatsSupported(_ vpFormatsSupported: [FormatType: VPFormatSupported]) throws {
    if vpFormatsSupported.isEmpty {
        throw InvalidData(
            message: "vp_formats_supported should at least have one supported vp_format",
            className: WalletMetadata.className
        )
    }
}

