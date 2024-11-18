import Foundation

public struct ClientMetadata: Codable {
    let name: String
    let logo_url: String?
    
    enum CodingKeys: String, CodingKey {
        case name
        case logo_url
    }
    
    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        guard let name = try container.decodeIfPresent(String.self, forKey: .name) else {
            Logger.error("ClientMetadata : name field should be present.")
            throw AuthorizationRequestException.missingInput(fieldName: "client_metadata : name")
        }
        self.name = name
        self.logo_url = try container.decodeIfPresent(String.self, forKey: .logo_url)
    }
    
    static func decodeAndValidateClientMetadata(clientMetadata: String) throws -> ClientMetadata {
        
        guard let encodedData = clientMetadata.data(using: .utf8) else {
            Logger.error("Failed to convert client_metadata string to UTF-8 data.")
            throw AuthorizationRequestException.utf8Encoding(fieldName: "client_metadata")
        }
        
        let decodedClientMetadata: ClientMetadata
        do {
            decodedClientMetadata = try JSONDecoder().decode(ClientMetadata.self, from: encodedData)
        } catch {
            Logger.error("Json Decoding of ClientMetadata failed due to this error: \(error).")
            throw AuthorizationRequestException.jsonDecodingFailed
        }
        
        guard !decodedClientMetadata.name.isEmpty else {
            Logger.error("ClientMetadata : name field should not be empty")
            throw AuthorizationRequestException.invalidInput(fieldName: "client_metadata : name")
        }
        
        if(decodedClientMetadata.logo_url != nil){
            guard decodedClientMetadata.logo_url!.isEmpty else {
                Logger.error("ClientMetadata : logo_url should not be empty.")
                throw AuthorizationRequestException.invalidInput(fieldName: "client_metadata : logo_url")
            }
        }
        return decodedClientMetadata
    }
}
