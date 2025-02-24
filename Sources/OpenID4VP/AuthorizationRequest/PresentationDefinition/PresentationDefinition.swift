import Foundation

public struct PresentationDefinition: Codable, Equatable {
    let id: String
    let name: String?
    let purpose: String?
    let input_descriptors: [InputDescriptor]
    let format: Format?
    static let className = String(describing: PresentationDefinition.self)
    
    enum CodingKeys: String, CodingKey {
        case id
        case name
        case purpose
        case input_descriptors
        case format
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
          
        
        self.id = try container.decodeRequired(
            String.self,
            forKey: .id,
            fieldPath: ["presentation_definition", "id"],
            className: PresentationDefinition.className,
            isMandatory: true
        )!
        
        self.input_descriptors = try container.decodeRequired(
            [InputDescriptor].self,
            forKey: .input_descriptors,
            fieldPath: ["presentation_definition", "input_descriptors"],
            className: PresentationDefinition.className,
            isMandatory: true
        )!
        
        self.name = try container.decodeRequired(
            String.self,
            forKey: .name,
            fieldPath: ["presentation_definition", "name"],
            className: PresentationDefinition.className,
            isMandatory: false)

        self.purpose = try container.decodeRequired(
            String.self,
            forKey: .purpose,
            fieldPath: ["presentation_definition", "purpose"],
            className: PresentationDefinition.className,
            isMandatory: false)
        
        self.format = try container.decodeRequired(
            Format.self,
            forKey: .format,
            fieldPath: ["presentation_definition", "format"],
            className: PresentationDefinition.className,
            isMandatory: false)
        
        try validate()
    }
    
    func validate() throws {
        guard isNeitherNullNorEmpty(field: id) else {
            throw Logger.handleException(exceptionType: "InvalidInput", fieldPath: ["presentation_definition","id"], className: PresentationDefinition.className)
        }
        
        guard !input_descriptors.isEmpty else {
            throw Logger.handleException(exceptionType: "InvalidInput", fieldPath: ["presentation_definition","input_descriptors"], className: PresentationDefinition.className)
        }
        
       if let name = name {
           guard isNeitherNullNorEmpty(field: name) else {
               throw Logger.handleException(exceptionType: "InvalidInput", fieldPath: ["presentation_definition","name"], className: PresentationDefinition.className)
           }
        }
        
        if let purpose = purpose {
            guard isNeitherNullNorEmpty(field: purpose) else {
                throw Logger.handleException(exceptionType: "InvalidInput", fieldPath: ["presentation_definition","purpose"], className: PresentationDefinition.className)
            }
        }
        
        try format?.validate()
        
        for descriptor in input_descriptors {
            try descriptor.validate()
        }
    }
    
    public static func == (lhs: PresentationDefinition, rhs: PresentationDefinition) -> Bool {
        return lhs.id == rhs.id && lhs.name == rhs.name &&
        lhs.purpose == rhs.purpose && lhs.input_descriptors == rhs.input_descriptors &&
        lhs.format == rhs.format
    }
}
