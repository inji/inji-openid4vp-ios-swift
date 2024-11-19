import Foundation

public struct ClientMetadata: Codable {
    let name: String
    let logo_url: String?
    static let className = String(describing: PresentationDefinitionValidator.self)
    
    enum CodingKeys: String, CodingKey {
        case name
        case logo_url
    }
    
    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        guard let name = try container.decodeIfPresent(String.self, forKey: .name) else {
            throw Logger.handleException(exceptionType: "MissingInput", fieldPath: ["client_metadata","name"], className: ClientMetadata.className)
        }
        self.name = name
        self.logo_url = try container.decodeIfPresent(String.self, forKey: .logo_url)
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
        
        guard isNeitherNullNorEmpty(field: decodedClientMetadata.name) else {
            throw Logger.handleException(exceptionType: "InvalidInput", fieldPath: ["client_metadata","name"], className: ClientMetadata.className)
        }
        
        if(decodedClientMetadata.logo_url != nil){
            guard isNeitherNullNorEmpty(field: decodedClientMetadata.logo_url!) else {
                throw Logger.handleException(exceptionType: "InvalidInput", fieldPath: ["client_metadata","logo_url"], className: ClientMetadata.className)
            }
        }
        return decodedClientMetadata
    }
}
