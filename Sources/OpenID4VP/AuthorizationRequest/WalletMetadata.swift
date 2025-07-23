import Foundation

@usableFromInline
internal struct WalletMetadataDefaults: Codable {
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
    @usableFromInline static let responseTypesSupported: [ResponseType] = [.vp_token]
}

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
            self.vpFormatsSupported = parseVPFormatsSupported(vpFormatsSupported)
            self.clientIdSchemesSupported = parseClientIdSchemesSupported(clientIdSchemesSupported)
            self.requestObjectSigningAlgValuesSupported = parseRequestObjectSigningAlgValuesSupported(requestObjectSigningAlgValuesSupported)
            self.authorizationEncryptionAlgValuesSupported = parseAuthorizationEncryptionAlgValuesSupported(authorizationEncryptionAlgValuesSupported)
            self.authorizationEncryptionEncValuesSupported = parseAuthorizationEncryptionEncValuesSupported(authorizationEncryptionEncValuesSupported)
            self.responseTypesSupported = WalletMetadataDefaults.responseTypesSupported
            
            try validateVPFormatsSupported(self.vpFormatsSupported)
        }
    
    public init(
        presentationDefinitionURISupported: Bool = WalletMetadataDefaults.presentationDefinitionURISupported,
        vpFormatsSupported: [VPFormatType: VPFormatSupported] = WalletMetadataDefaults.vpFormatsSupported,
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

private func parseClientIdSchemesSupported(_ clientIdSchemesSupported: [String]?) -> [ClientIdScheme] {
    guard let schemes = clientIdSchemesSupported else {
        return [.preRegistered]
    }
    return schemes.compactMap { ClientIdScheme(rawValue: $0) }
}

private func parseVPFormatsSupported(_ vpFormatsSupported: [String: VPFormatSupported]) -> [VPFormatType: VPFormatSupported] {
    return vpFormatsSupported.reduce(into: [VPFormatType: VPFormatSupported]()) { result, entry in
        if let type = VPFormatType(rawValue: entry.key) {
            result[type] = entry.value
        }
    }
}

private func parseRequestObjectSigningAlgValuesSupported(_ requestObjectSigningAlgValuesSupported: [String]?) -> [RequestSigningAlgorithm]? {
    guard let algs = requestObjectSigningAlgValuesSupported else {
        return nil
    }
    return algs.compactMap { RequestSigningAlgorithm(rawValue: $0) }
}

private func parseAuthorizationEncryptionAlgValuesSupported(_ authorizationEncryptionAlgValuesSupported: [String]?) -> [KeyManagementAlgorithm]? {
    guard let algs = authorizationEncryptionAlgValuesSupported else {
        return nil
    }
    return algs.compactMap { KeyManagementAlgorithm(rawValue: $0) }
}

private func parseAuthorizationEncryptionEncValuesSupported(_ authorizationEncryptionEncValuesSupported: [String]?) -> [ContentEncryptionAlgorithm]? {
    guard let encs = authorizationEncryptionEncValuesSupported else {
        return nil
    }
    return encs.compactMap { ContentEncryptionAlgorithm(rawValue: $0) }
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

