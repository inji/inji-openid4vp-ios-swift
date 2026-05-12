struct MetadataConstants {
    // Wallet Metadata
    static let proofTypeValues = "proof_type_values"
    
    /// Client ID
    static let clientIdPrefixesSupported = "client_id_prefixes_supported"
    static let clientIdSchemesSupported = "client_id_schemes_supported"
    
    /// Request Object Signing
    static let requestObjectSigningAlgValuesSupported = "request_object_signing_alg_values_supported"
    
    /// Authorization Encryption
    static let authorizationEncryptionAlgValuesSupported = "authorization_encryption_alg_values_supported"
    static let authorizationEncryptionEncValuesSupported = "authorization_encryption_enc_values_supported"
    
    /// Response
    static let responseTypesSupported = "response_types_supported"
    
    /// Presentation Definition
    static let presentationDefinitionUriSupported = "presentation_definition_uri_supported"
    
    /// Request URI
    static let supportedRequestUriMethods = "supported_request_uri_methods"
    
    /// Top-level wrapper key
    static let walletMetadata = "wallet_metadata"
    
    
    // Verifier Metadata
    
    /// Verifier details
    static let clientName = "client_name"
    static let logoUri = "logo_uri"
    
    /// Encrypted response - Spec V1
    static let encryptedResponseEncValuesSupported = "encrypted_response_enc_values_supported"
    /// Encrypted response - Spec draft 23
    static let authorizationEncryptedResponseAlg = "authorization_encrypted_response_alg"
    static let authorizationEncryptedResponseEnc = "authorization_encrypted_response_enc"
    
    /// VP formats
    static let vpFormats = "vp_formats"
    
    // Common Metadata constants
    
    /// VP Formats
    static let vpFormatsSupported = "vp_formats_supported"
    static let algValuesSupported = "alg_values_supported"
    
    /// Top-level wrapper key
    static let clientMetadata = "client_metadata"
}
