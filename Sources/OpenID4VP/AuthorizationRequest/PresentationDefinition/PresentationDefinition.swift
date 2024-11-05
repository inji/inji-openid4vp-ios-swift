import Foundation

public struct PresentationDefinition: Codable {
    let id: String
    let name: String?
    let purpose: String?
    let input_descriptors: [InputDescriptor]
    let format: Format?
    
    enum CodingKeys: String, CodingKey {
        case id
        case name
        case purpose
        case input_descriptors
        case format
    }
    
    public init(from decoder: Decoder) throws {
        
        let container = try decoder.container(keyedBy: CodingKeys.self)
        
        guard let id = try container.decodeIfPresent(String.self, forKey: .id) else {
            Logger.error("PresentationDefinition : Id should be present.")
            throw AuthorizationRequestException.missingInput(fieldName: "id")
        }
        
        guard let inputDescriptors = try container.decodeIfPresent([InputDescriptor].self, forKey: .input_descriptors) else {
            Logger.error("PresentationDefinition : Input Descriptor should be present.")
            throw AuthorizationRequestException.missingInput(fieldName: "input descriptors")
        }
        
        self.id = id
        self.input_descriptors = inputDescriptors
        self.name = try container.decodeIfPresent(String.self, forKey: .name)
        self.purpose = try container.decodeIfPresent(String.self, forKey: .purpose)
        self.format = try container.decodeIfPresent(Format.self, forKey: .format)
        
        try validate()
    }
    
    func validate() throws {
        guard !id.isEmpty else {
            Logger.error("PresentationDefinition : Id should not be empty.")
            throw AuthorizationRequestException.invalidInput(fieldName: "id")
        }
        
        guard !input_descriptors.isEmpty else {
            Logger.error("PresentationDefinition : Input descriptor should not be empty.")
            throw AuthorizationRequestException.invalidInput(fieldName: "input descriptors")
        }
        
        if let format = format {
            try format.validate()
        }
        
        for descriptor in input_descriptors {
            try descriptor.validate()
        }
    }
}
