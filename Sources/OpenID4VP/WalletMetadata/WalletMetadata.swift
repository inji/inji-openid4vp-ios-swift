import Foundation

struct WalletMetadata: Codable {
    
    var presentationDefinitionURISupported: Bool? = true
    var vpFormatsSupported: [String: VPFormatSupported]
    var clientIDSchemesSupported: [ClientIdScheme]? = [ClientIdScheme.preRegistered]
    
    static func validate(from jsonString: String) throws {
        guard let jsonData = jsonString.data(using: .utf8) else {
            throw ValidationError.invalidJSON
        }
        
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .useDefaultKeys
        
        guard let jsonObject = try? JSONSerialization.jsonObject(with: jsonData, options: []),
              let jsonDict = jsonObject as? [String: Any] else {
            throw ValidationError.invalidJSON
        }
        
        let allowedKeys = ["presentation_definition_uri_supported", "vp_formats_supported", "client_id_schemes_supported"]
        
        for key in jsonDict.keys {
            if !allowedKeys.contains(key) {
                throw ValidationError.extraField(key)
            }
        }
        
        let metadata = try decoder.decode(WalletMetadata.self, from: jsonData)
        
        guard !metadata.vpFormatsSupported.isEmpty else {
            throw ValidationError.missingRequiredField("vp_formats_supported")
        }
        
    }
}

struct VPFormatSupported: Codable {
    
    var algValuesSupported: [String]?
}
