import Foundation

public struct ClientMetadata: Codable {
    let clientName: String?
    let logoUri:String?
    let authorizationEncryptedResponseAlg: String?
    let authorizationEncryptedResponseEnc: String?
    let vpFormats: [String: [String: [String]]]
    let jwks: JWKS?
    static let className = String(describing: ClientMetadata.self)
    
    enum CodingKeys: String, CodingKey {
        case clientName = "client_name"
        case logoUri = "logo_uri"
        case authorizationEncryptedResponseAlg = "authorization_encrypted_response_alg"
        case authorizationEncryptedResponseEnc = "authorization_encrypted_response_enc"
        case vpFormats = "vp_formats"
        case jwks
    }
    
    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        
        self .clientName = try container.decodeRequired(
            String.self,
            forKey: .clientName,
            fieldPath: ["client_metadata", "client_name"],
            className: ClientMetadata.className,
            isMandatory: false
        )
        
        self .logoUri = try container.decodeRequired(
            String.self,
            forKey: .logoUri,
            fieldPath: ["client_metadata", "logo_uri"],
            className: ClientMetadata.className,
            isMandatory: false
        )
        
        self .authorizationEncryptedResponseAlg = try container.decodeRequired(
            String.self,
            forKey: .authorizationEncryptedResponseAlg,
            fieldPath: ["client_metadata", "authorization_encrypted_response_alg"],
            className: ClientMetadata.className,
            isMandatory: false
        )
        
        self .authorizationEncryptedResponseEnc = try container.decodeRequired(
            String.self,
            forKey: .authorizationEncryptedResponseEnc,
            fieldPath: ["client_metadata", "authorization_encrypted_response_enc"],
            className: ClientMetadata.className,
            isMandatory: false
        )
        
        self .vpFormats = try container.decodeRequired(
            [String: [String: [String]]].self,
            forKey: .vpFormats,
            fieldPath: ["client_metadata", "vp_formats"],
            className: ClientMetadata.className,
            isMandatory: true
        )!
        
        self .jwks = try container.decodeRequired(
            JWKS.self,
            forKey: .jwks,
            fieldPath: ["client_metadata", "jwks"],
            className: ClientMetadata.className,
            isMandatory: false
        )
        try validate(self)
    }
    
    static func deserializeAndValidate(clientMetadata: Any) throws -> ClientMetadata {
        if let encodedData = clientMetadata as? Data {
            return try toClientMetadata(encodedData)
        } else if let data = clientMetadata as? String {
            guard let encodedData = data.data(using: .utf8) else {
                throw UTF8EncodingFailed( fieldPath: ["client_metadata"], className: ClientMetadata.className)
            }
            return try toClientMetadata(encodedData)
        } else {
            throw InvalidInput(fieldPath: ["client_metadata"], className: ClientMetadata.className)
        }
    }
    
    fileprivate static func toClientMetadata(_ encodedData: Data)throws -> ClientMetadata {
            return try encodedData.toInstance(as: ClientMetadata.self)
    }
    
    private func validate(_ decodedClientMetadata: ClientMetadata) throws{
        
        try validateField(decodedClientMetadata.clientName, ["client_metadata", "client_name"], ClientMetadata.className)
        try validateField(decodedClientMetadata.logoUri, ["client_metadata", "logo_uri"], ClientMetadata.className)
        try validateField(decodedClientMetadata.authorizationEncryptedResponseAlg, ["client_metadata", "authorization_encrypted_response_alg"], ClientMetadata.className)
        try validateField(decodedClientMetadata.authorizationEncryptedResponseEnc, ["client_metadata", "authorization_encrypted_response_enc"], ClientMetadata.className)
        try validateField(decodedClientMetadata.vpFormats, ["client_metadata", "vp_formats"], ClientMetadata.className)
        
        if decodedClientMetadata.jwks != nil {
            try decodedClientMetadata.jwks!.validate()
        }
    }
}
