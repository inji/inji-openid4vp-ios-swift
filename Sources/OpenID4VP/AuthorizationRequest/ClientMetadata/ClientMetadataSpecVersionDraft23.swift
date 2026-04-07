import Foundation
import JSONWebKey

public struct ClientMetadataSpecVersionDraft23: Codable {
    let clientName: String?
    let logoUri:String?
    let authorizationEncryptedResponseAlg: String?
    let authorizationEncryptedResponseEnc: String?
    let vpFormats: [String: [String: [String]]]
    let jwks: JWKSet?
    static let className = String(describing: ClientMetadataSpecVersionDraft23.self)
    
    enum CodingKeys: String, CodingKey {
        case clientName = "client_name"
        case logoUri = "logo_uri"
        case authorizationEncryptedResponseAlg = "authorization_encrypted_response_alg"
        case authorizationEncryptedResponseEnc = "authorization_encrypted_response_enc"
        case vpFormats = "vp_formats"
        case jwks
    }
    
    public init(from decoder: any Decoder) throws {
        do {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            
            self .clientName = try container.decodeRequired(
                String.self,
                forKey: .clientName,
                fieldPath: ["client_metadata", "client_name"],
                className: ClientMetadataSpecVersionDraft23.className,
                isMandatory: false
            )
            
            self .logoUri = try container.decodeRequired(
                String.self,
                forKey: .logoUri,
                fieldPath: ["client_metadata", "logo_uri"],
                className: ClientMetadataSpecVersionDraft23.className,
                isMandatory: false
            )
            
            self .authorizationEncryptedResponseAlg = try container.decodeRequired(
                String.self,
                forKey: .authorizationEncryptedResponseAlg,
                fieldPath: ["client_metadata", "authorization_encrypted_response_alg"],
                className: ClientMetadataSpecVersionDraft23.className,
                isMandatory: false
            )
            
            self .authorizationEncryptedResponseEnc = try container.decodeRequired(
                String.self,
                forKey: .authorizationEncryptedResponseEnc,
                fieldPath: ["client_metadata", "authorization_encrypted_response_enc"],
                className: ClientMetadataSpecVersionDraft23.className,
                isMandatory: false
            )
            
            self .vpFormats = try container.decodeRequired(
                [String: [String: [String]]].self,
                forKey: .vpFormats,
                fieldPath: ["client_metadata", "vp_formats"],
                className: ClientMetadataSpecVersionDraft23.className,
                isMandatory: true
            )!
            
            self .jwks = try container.decodeRequired(
                JWKSet.self,
                forKey: .jwks,
                fieldPath: ["client_metadata", "jwks"],
                className: ClientMetadataSpecVersionDraft23.className,
                isMandatory: false
            )
            try validate(self)
        } catch {
            throw wrapError(error, customError: { message in InvalidData(message: "Error during client metadata decoding - \(message)", className: ClientMetadataSpecVersionDraft23.className) })
        }
    }
    
    public static func deserializeAndValidate(clientMetadata: Any) throws -> ClientMetadataSpecVersionDraft23 {
        if let encodedData = clientMetadata as? Data {
            return try toClientMetadata(encodedData)
        } else if let data = clientMetadata as? String {
            guard let encodedData = data.data(using: .utf8) else {
                throw UTF8EncodingFailed( fieldPath: ["client_metadata"], className: ClientMetadataSpecVersionDraft23.className)
            }
            return try toClientMetadata(encodedData)
        } else {
            throw InvalidInput(fieldPath: ["client_metadata"], className: ClientMetadataSpecVersionDraft23.className)
        }
    }
    
    fileprivate static func toClientMetadata(_ encodedData: Data)throws -> ClientMetadataSpecVersionDraft23 {
        return try encodedData.toInstance(as: ClientMetadataSpecVersionDraft23.self)
    }
    
    private func validate(_ decodedClientMetadata: ClientMetadataSpecVersionDraft23) throws{
        
        try validateField(decodedClientMetadata.clientName, ["client_metadata", "client_name"], ClientMetadataSpecVersionDraft23.className)
        try validateField(decodedClientMetadata.logoUri, ["client_metadata", "logo_uri"], ClientMetadataSpecVersionDraft23.className)
        try validateField(decodedClientMetadata.authorizationEncryptedResponseAlg, ["client_metadata", "authorization_encrypted_response_alg"], ClientMetadataSpecVersionDraft23.className)
        try validateField(decodedClientMetadata.authorizationEncryptedResponseEnc, ["client_metadata", "authorization_encrypted_response_enc"], ClientMetadataSpecVersionDraft23.className)
        try validateField(decodedClientMetadata.vpFormats, ["client_metadata", "vp_formats"], ClientMetadataSpecVersionDraft23.className)
    }
}
