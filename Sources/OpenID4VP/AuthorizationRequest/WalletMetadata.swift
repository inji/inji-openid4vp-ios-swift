import Foundation

public struct WalletMetadata: Codable {
    let presentationDefinitionURISupported: Bool
    let vpFormatsSupported: [String: VPFormatSupported]
    let clientIdSchemesSupported: [String]
    var requestObjectSigningAlgValuesSupported: [String]?
    let authorizationEncryptionAlgValuesSupported: [String]?
    let authorizationEncryptionEncValuesSupported: [String]?
    let className = String(describing: WalletMetadata.self)
    
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
    ) throws {
        self.presentationDefinitionURISupported = presentationDefinitionURISupported
        self.vpFormatsSupported = vpFormatsSupported
        self.clientIdSchemesSupported = clientIdSchemesSupported
        self.requestObjectSigningAlgValuesSupported = requestObjectSigningAlgValuesSupported
        self.authorizationEncryptionAlgValuesSupported = authorizationEncryptionAlgValuesSupported
        self.authorizationEncryptionEncValuesSupported = authorizationEncryptionEncValuesSupported
        
        try validateVpFormatsSupported(vpFormatsSupported)
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

private func validateVpFormatsSupported(_ vpFormatsSupported: [String: VPFormatSupported]) throws {
    guard !vpFormatsSupported.isEmpty else {
        throw Logger.handleException(
            exceptionType: "InvalidData",
            message: "vp_formats_supported should at least have one supported vp_format",
            className: className
        )
    }

    if vpFormatsSupported.keys.contains(where: { $0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }) {
        throw Logger.handleException(
            exceptionType: "InvalidData",
            message: "vp_formats_supported cannot have empty keys.",
            className: className
        )
    }
}

