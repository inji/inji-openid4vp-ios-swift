import Foundation

public struct WalletMetadata: Decodable {
    
    var presentationDefinitionURISupported: Bool? = true
    var vpFormatsSupported: [String: VPFormatSupported]
    var clientIDSchemesSupported: [String]? = [ClientIdScheme.preRegistered.rawValue]
    var requestObjectSigningAlgValuesSupported: [String]? = nil
    var authorizationEncryptionAlgValuesSupported: [String]? = nil
    var authorizationEncryptionEncValuesSupported: [String]? = nil
    static let className = String(describing: WalletMetadata.self)
    
    enum CodingKeys: String, CodingKey {
        case presentation_definition_uri_supported
        case vp_formats_supported
        case client_id_schemes_supported
        case request_object_signing_alg_values_supported
        case authorization_encryption_alg_values_supported
        case authorization_encryption_enc_values_supported
       
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
          
        self.presentationDefinitionURISupported = try container.decodeRequired(
            Bool.self,
            forKey: .presentation_definition_uri_supported,
            fieldPath: ["wallet_metadata", "presentation_definition_uri_supported"],
            className: WalletMetadata.className,
            isMandatory: false
        )!
        
        self.vpFormatsSupported = try container.decodeRequired(
            [String: VPFormatSupported].self,
            forKey: .vp_formats_supported,
            fieldPath: ["wallet_metadata", "vp_formats_supported"],
            className: WalletMetadata.className,
            isMandatory: true)!
        
        self.clientIDSchemesSupported = try container.decodeRequired(
            [String].self,
            forKey: .client_id_schemes_supported,
            fieldPath: [" wallet_metadata", "client_id_schemes_supported"],
            className: WalletMetadata.className,
            isMandatory: false
        )!
        
        self.requestObjectSigningAlgValuesSupported = try container.decodeRequired(
            [String].self,
            forKey: .request_object_signing_alg_values_supported,
            fieldPath: [" wallet_metadata", "request_object_signing_alg_values_supported"],
            className: WalletMetadata.className,
            isMandatory: false
        )!
        
        self.authorizationEncryptionAlgValuesSupported = try container.decodeRequired(
            [String].self,
            forKey: .authorization_encryption_alg_values_supported,
            fieldPath: [" wallet_metadata", "authorization_encryption_alg_values_supported"],
            className: WalletMetadata.className,
            isMandatory: false
        )!
        
        self.authorizationEncryptionEncValuesSupported = try container.decodeRequired(
            [String].self,
            forKey: .authorization_encryption_enc_values_supported,
            fieldPath: [" wallet_metadata", "authorization_encryption_enc_values_supported"],
            className: WalletMetadata.className,
            isMandatory: false
        )!
        
        

    }
}

public struct VPFormatSupported: Decodable {
    
    var algValuesSupported: [String]?
    
    enum CodingKeys: String, CodingKey {
            case alg_values_supported
        }
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        self.algValuesSupported = try container.decodeRequired(
            [String].self,
            forKey: .alg_values_supported,
            fieldPath: ["filter", "type"],
            className: "test",
            isMandatory: false
        )!
    }
}

