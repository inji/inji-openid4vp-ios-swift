import Foundation

@usableFromInline
struct WalletMetadataDefaults: Codable {
    @usableFromInline static let presentationDefinitionURISupported: Bool = true
    @usableFromInline static let vpFormatsSupported: [VPFormatType: VPFormatSupported] = [
        .ldp_vc: VPFormatSupported(algValuesSupported: []),
        .ldp_vp: VPFormatSupported(algValuesSupported: []),
        .mso_mdoc: VPFormatSupported(algValuesSupported: []),
    ]
    @usableFromInline static let clientIdSchemesSupported: [ClientIdScheme] = [.preRegistered, .redirectUri, .did]
    @usableFromInline static let requestObjectSigningAlgValuesSupported: [RequestSigningAlgorithm] = [.edDsa]
    @usableFromInline static let authorizationEncryptionAlgValuesSupported: [KeyManagementAlgorithm] = [.ecdhEs]
    @usableFromInline static let authorizationEncryptionEncValuesSupported: [ContentEncryptionAlgorithm] = [.A256GCM]
}

public struct WalletMetadata: Codable {
    let presentationDefinitionURISupported: Bool
    let vpFormatsSupported: [VPFormatType: VPFormatSupported]
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
        vpFormatsSupported: [VPFormatType: VPFormatSupported],
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
    
    public init(
        presentationDefinitionURISupported: Bool = WalletMetadataDefaults.presentationDefinitionURISupported,
        vpFormatsSupported: [VPFormatType: VPFormatSupported] = WalletMetadataDefaults.vpFormatsSupported,
        clientIdSchemesSupported: [ClientIdScheme] = WalletMetadataDefaults.clientIdSchemesSupported,
        requestObjectSigningAlgValuesSupported: [RequestSigningAlgorithm] = WalletMetadataDefaults.requestObjectSigningAlgValuesSupported,
        authorizationEncryptionAlgValuesSupported: [KeyManagementAlgorithm] = WalletMetadataDefaults.authorizationEncryptionAlgValuesSupported,
        authorizationEncryptionEncValuesSupported: [ContentEncryptionAlgorithm] = WalletMetadataDefaults.authorizationEncryptionEncValuesSupported
    ) throws {
        self.presentationDefinitionURISupported = presentationDefinitionURISupported
        self.vpFormatsSupported = vpFormatsSupported
        self.clientIdSchemesSupported = clientIdSchemesSupported
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

private func validateVPFormatsSupported(_ vpFormatsSupported: [VPFormatType: VPFormatSupported]) throws {
    if vpFormatsSupported.isEmpty {
        throw InvalidData(
            message: "vp_formats_supported should at least have one supported vp_format",
            className: WalletMetadata.className
        )
    }
}

