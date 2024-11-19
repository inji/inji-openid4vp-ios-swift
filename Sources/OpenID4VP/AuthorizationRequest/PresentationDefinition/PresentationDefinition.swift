import Foundation

public struct PresentationDefinition: Codable {
    let id: String
    let name: String?
    let purpose: String?
    let input_descriptors: [InputDescriptor]
    let format: Format?
    static let className = String(describing: PresentationDefinitionValidator.self)
    
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
            throw Logger.handleException(exceptionType: "MissingInput", fieldPath: ["presentation_definition","id"], className: PresentationDefinition.className)
        }
        
        guard let inputDescriptors = try container.decodeIfPresent([InputDescriptor].self, forKey: .input_descriptors) else {
            throw Logger.handleException(exceptionType: "MissingInput", fieldPath: ["presentation_definition","input_descriptors"], className: PresentationDefinition.className)
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
            throw Logger.handleException(exceptionType: "InvalidInput", fieldPath: ["presentation_definition","id"], className: PresentationDefinition.className)
        }
        
        guard !input_descriptors.isEmpty else {
            throw Logger.handleException(exceptionType: "InvalidInput", fieldPath: ["presentation_definition","input_descriptors"], className: PresentationDefinition.className)
        }
        
        if let format = format {
            try format.validate()
        }
        
        for descriptor in input_descriptors {
            try descriptor.validate()
        }
    }
}
