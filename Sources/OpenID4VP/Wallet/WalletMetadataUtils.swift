internal func parseClientIdPrefixesSupported(_ clientIdPrefixesSupported: [String]?) throws -> [ClientIdPrefix] {
    guard let schemes = clientIdPrefixesSupported else {
        return [.preRegistered]
    }
    return try schemes.compactMap { try parseEnum(valueName: "ClientIdPrefix", $0, as: ClientIdPrefix.self) }
}

internal func parseVPFormatsSupported(_ vpFormatsSupported: [String: VPFormatSupported]) throws -> [VPFormatType: VPFormatSupported] {
    if vpFormatsSupported.keys.contains(where: { $0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }) {
        throw InvalidData(
            message: "vp_formats_supported cannot have empty keys.",
            className: WalletMetadata.className
        )
    }
    
    
    return try vpFormatsSupported.reduce(into: [VPFormatType: VPFormatSupported]()) { result, entry in
        let parsedVPFormatType = try parseEnum(valueName: "VPFormatType", entry.key, as: VPFormatType.self)
        result[parsedVPFormatType] = entry.value
    }
}


internal func parseRequestObjectSigningAlgValuesSupported(_ requestObjectSigningAlgValuesSupported: [String]?) throws -> [RequestSigningAlgorithm]? {
    guard let algs = requestObjectSigningAlgValuesSupported else {
        return nil
    }
    return try algs.compactMap { try parseEnum(valueName: "RequestSigningAlgorithm", $0, as: RequestSigningAlgorithm.self) }
}

internal func parseAuthorizationEncryptionAlgValuesSupported(_ authorizationEncryptionAlgValuesSupported: [String]?) throws -> [KeyManagementAlgorithm]? {
    guard let algs = authorizationEncryptionAlgValuesSupported else {
        return nil
    }
    return try algs.compactMap { try parseEnum(valueName: "KeyManagementAlgorithm", $0, as: KeyManagementAlgorithm.self) }
}

internal func parseAuthorizationEncryptionEncValuesSupported(_ authorizationEncryptionEncValuesSupported: [String]?) throws -> [ContentEncryptionAlgorithm]? {
    guard let encs = authorizationEncryptionEncValuesSupported else {
        return nil
    }
    return try encs.compactMap { try parseEnum(valueName: "ContentEncryptionAlgorithm", $0, as: ContentEncryptionAlgorithm.self) }
}

internal func validateVPFormatsSupported(_ vpFormatsSupported: [VPFormatType: VPFormatSupported]) throws {
    if vpFormatsSupported.isEmpty {
        throw InvalidData(
            message: "vp_formats_supported should at least have one supported vp_format",
            className: WalletMetadata.className
        )
    }
}

internal func parseClientIdSchemesSupported(_ clientIdSchemesSupported: [String]?) throws -> [ClientIdScheme] {
    guard let schemes = clientIdSchemesSupported else {
        return [.preRegistered]
    }
    return try schemes.compactMap { try parseEnum(valueName: "ClientIdScheme", $0, as: ClientIdScheme.self) }
}

internal func parseEnum<E: RawRepresentable>(valueName: String, _ value: E.RawValue, as type: E.Type) throws -> E {
    guard let enumCase = E(rawValue: value) else {
        throw InvalidData(
            message: "Invalid \(valueName) value: \(value). Its is not supported by the library.",
            className: WalletMetadata.className
        )
    }
    
    return enumCase
}

@usableFromInline
internal struct WalletMetadataDefaults: Codable {
    @usableFromInline static let presentationDefinitionURISupported: Bool = true

    @usableFromInline static let vpFormatsSupported: [VPFormatType: VPFormatSupported] = [
        .ldp_vc: LdpVcFormatSupported(),
        .mso_mdoc: MsoMdocVcFormatSupported(),
        .dc_sd_jwt: SdJwtVcFormatSupported()
    ]
    
    @usableFromInline static let clientIdSchemesSupported: [ClientIdScheme] = [.preRegistered, .redirectUri, .did]
    @usableFromInline static let clientIdPrefixesSupported: [ClientIdPrefix] = [.preRegistered, .redirectUri, .did]
    
    @usableFromInline static let requestObjectSigningAlgValuesSupported: [RequestSigningAlgorithm] = [.edDsa]
    
    @usableFromInline static let authorizationEncryptionAlgValuesSupported: [KeyManagementAlgorithm] = [.ecdhEs]
    
    @usableFromInline static let authorizationEncryptionEncValuesSupported: [ContentEncryptionAlgorithm] = [.A256GCM]
 
    @usableFromInline static let responseTypesSupported: [ResponseType] = [.vp_token]
}
