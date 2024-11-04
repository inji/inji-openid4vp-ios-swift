import Foundation

public struct ClientMetadata: Codable {
    let name: String
    
    enum CodingKeys: String, CodingKey {
        case name
    }
    
    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.name = try container.decode(String.self, forKey: .name)
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
            Logger.error("ClientMetadata: name should not be empty")
            throw AuthorizationRequestException.invalidInput(fieldName: "client_metadata : name")
        }
        
        return decodedClientMetadata
    }
}
