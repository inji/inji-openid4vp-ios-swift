import Foundation

public struct ClientMetadata: Codable {
    let client_name: String?
    let logo_uri: String?
    static let className = String(describing: PresentationDefinitionValidator.self)
    
    enum CodingKeys: String, CodingKey {
        case client_name
        case logo_uri
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
            forKey: .client_name,
            fieldPath: ["client_metadata", "logo_uri"],
            className: ClientMetadata.className,
            isMandatory: false
        )
    }
    
    static func decodeAndValidateClientMetadata(clientMetadata: String) throws -> ClientMetadata {
        
        guard let encodedData = clientMetadata.data(using: .utf8) else {
            throw Logger.handleException(exceptionType: "UTF8Encoding", fieldPath: ["client_metadata"], className: ClientMetadata.className)
        }
        
        let decodedClientMetadata: ClientMetadata
        do {
            decodedClientMetadata = try JSONDecoder().decode(ClientMetadata.self, from: encodedData)
        } catch {
            throw error
        }
        
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
        return decodedClientMetadata
        }
}
