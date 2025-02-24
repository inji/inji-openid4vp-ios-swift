import Foundation

public struct ClientMetadata: Codable, Equatable {
    let client_name: String?
    let logo_uri:String?
    let authorization_encrypted_response_alg: String?
    let authorization_encrypted_response_enc: String?
    let vp_formats: [String: [String: [String]]]
    static let className = String(describing: ClientMetadata.self)
    
    enum CodingKeys: String, CodingKey {
        case client_name
        case logo_uri
        case authorization_encrypted_response_alg
        case authorization_encrypted_response_enc
        case vp_formats
    }
    
    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        
        self.client_name = try container.decodeRequired(
            String.self,
            forKey: .client_name,
            fieldPath: ["client_metadata", "client_name"],
            className: ClientMetadata.className,
            isMandatory: false
        )
        
        self.logo_uri = try container.decodeRequired(
            String.self,
            forKey: .logo_uri,
            fieldPath: ["client_metadata", "logo_uri"],
            className: ClientMetadata.className,
            isMandatory: false
        )
        
        self .authorization_encrypted_response_alg = try container.decodeRequired(
            String.self,
            forKey: .authorization_encrypted_response_alg,
            fieldPath: ["client_metadata", "authorization_encrypted_response_alg"],
            className: ClientMetadata.className,
            isMandatory: false
        )
        
        self .authorization_encrypted_response_enc = try container.decodeRequired(
            String.self,
            forKey: .authorization_encrypted_response_enc,
            fieldPath: ["client_metadata", "authorization_encrypted_response_enc"],
            className: ClientMetadata.className,
            isMandatory: false
        )
        
        self .vp_formats = try container.decodeRequired(
            [String: [String: [String]]].self,
            forKey: .vp_formats,
            fieldPath: ["client_metadata", "vp_formats"],
            className: ClientMetadata.className,
            isMandatory: true
        )!
        try validate(self)
    }
    
    static func deserializeAndValidate(clientMetadata: Any) throws -> ClientMetadata {
        if let encodedData = clientMetadata as? Data {
            return try toClientMetadata(encodedData)
        } else if let data = clientMetadata as? String {
            guard let encodedData = data.data(using: .utf8) else {
                throw Logger.handleException(exceptionType: "UTF8Encoding", fieldPath: ["client_metadata"], className: ClientMetadata.className)
            }
            return try toClientMetadata(encodedData)
        } else {
            throw Logger.handleException(exceptionType: "InvalidInput", message: "parsing of client_metadata failed", fieldPath: ["client_metadata"], className: ClientMetadata.className)
        }
    }
    
    fileprivate static func toClientMetadata(_ encodedData: Data)throws -> ClientMetadata {
        do {
            return try encodedData.toInstance(as: ClientMetadata.self)
        } catch {
            throw Logger.handleException(exceptionType: "InvalidInput", fieldPath: ["client_metadata"], className: ClientMetadata.className)
        }
    }
    
    private func validate(_ decodedClientMetadata: ClientMetadata) throws{
        if decodedClientMetadata.client_name != nil {
            guard isNeitherNullNorEmpty(field: decodedClientMetadata.client_name!) else {
                throw Logger.handleException(exceptionType: "InvalidInput", fieldPath: ["client_metadata","client_name"], className: ClientMetadata.className)
            }
        }
        
        if decodedClientMetadata.logo_uri != nil {
            guard isNeitherNullNorEmpty(field: decodedClientMetadata.logo_uri!) else {
                throw Logger.handleException(exceptionType: "InvalidInput", fieldPath: ["client_metadata","logo_uri"], className: ClientMetadata.className)
            }
        }
        
        if decodedClientMetadata.authorization_encrypted_response_alg != nil {
            guard isNeitherNullNorEmpty(field: decodedClientMetadata.authorization_encrypted_response_alg!) else {
                throw Logger.handleException(exceptionType: "InvalidInput", fieldPath: ["client_metadata", "authorization_encrypted_response_alg"], className: ClientMetadata.className)
            }
        }
        
        if decodedClientMetadata.authorization_encrypted_response_enc != nil {
            guard isNeitherNullNorEmpty(field: decodedClientMetadata.authorization_encrypted_response_enc!) else {
                throw Logger.handleException(exceptionType: "InvalidInput", fieldPath: ["client_metadata", "authorization_encrypted_response_enc"], className: ClientMetadata.className)
            }
        }
        
        if decodedClientMetadata.vp_formats.isEmpty {
            throw Logger.handleException(exceptionType: "InvalidInput", fieldPath: ["client_metadata", "vp_formats"], className: ClientMetadata.className)
        }
        
        for (key, value) in decodedClientMetadata.vp_formats {
            if value.isEmpty {
                throw Logger.handleException(exceptionType: "InvalidInput", fieldPath: ["client_metadata", "vp_formats", key], className: ClientMetadata.className)
            }
            for (subKey, subValue) in value {
                if subValue.isEmpty {
                    throw Logger.handleException(exceptionType: "InvalidInput", fieldPath: ["client_metadata", "vp_formats", key, subKey], className: ClientMetadata.className)
                }
            }
        }
    }
    
    public static func == (lhs: ClientMetadata, rhs: ClientMetadata) -> Bool {
        return lhs.client_name == rhs.client_name && lhs.logo_uri == rhs.logo_uri &&
        lhs.authorization_encrypted_response_alg == rhs.authorization_encrypted_response_alg && lhs.authorization_encrypted_response_enc == rhs.authorization_encrypted_response_enc &&
        lhs.vp_formats == rhs.vp_formats
    }
}
