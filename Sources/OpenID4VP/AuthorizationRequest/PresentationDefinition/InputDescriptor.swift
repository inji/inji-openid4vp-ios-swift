import Foundation

struct InputDescriptor: Codable, Equatable {
    let id: String
    let name: String?
    let purpose: String?
    let constraints: Constraints
    let format: Format?
    static let className = String(describing: PresentationDefinition.self)
    
    enum CodingKeys: String, CodingKey {
        case id
        case name
        case purpose
        case constraints
        case format
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        
        self.id = try container.decodeRequired(
            String.self,
            forKey: .id,
            fieldPath: ["input_descriptor", "id"],
            className: InputDescriptor.className,
            isMandatory: true
        )!
        
        self.constraints = try container.decodeRequired(
            Constraints.self,
            forKey: .constraints,
            fieldPath: ["input_descriptor", "constraints"],
            className: InputDescriptor.className,
            isMandatory: true
        )!
        
        self.name = try container.decodeRequired(
            String.self,
            forKey: .name,
            fieldPath: ["input_descriptor", "name"],
            className: InputDescriptor.className,
            isMandatory: false)
        
        self.purpose = try container.decodeRequired(
            String.self,
            forKey: .purpose,
            fieldPath: ["input_descriptor", "purpose"],
            className: InputDescriptor.className,
            isMandatory: false)
        
        self.format = try container.decodeRequired(
            Format.self,
            forKey: .format,
            fieldPath: ["input_descriptor", "format"],
            className: InputDescriptor.className,
            isMandatory: false)
        
        try validate()
    }
    
    func validate() throws {
        guard isNeitherNullNorEmpty(field: id) else {
            throw Logger.handleException(exceptionType: "InvalidInput", fieldPath: ["input_descriptor","id"], className: InputDescriptor.className)
        }
        
        if let name = name {
            guard isNeitherNullNorEmpty(field: name) else {
                throw Logger.handleException(exceptionType: "InvalidInput", fieldPath: ["input_descriptor","name"], className: InputDescriptor.className)
            }
        }
        
        if let purpose = purpose {
            guard isNeitherNullNorEmpty(field: purpose) else {
                throw Logger.handleException(exceptionType: "InvalidInput", fieldPath: ["input_descriptor","purpose"], className: InputDescriptor.className)
            }
        }
    
        try constraints.validate()
        
        try format?.validate()
    }
    
    static func == (lhs: InputDescriptor, rhs: InputDescriptor) -> Bool {
        return lhs.id == rhs.id && lhs.name == rhs.name &&
        lhs.purpose == rhs.purpose && lhs.constraints == rhs.constraints &&
        lhs.format == rhs.format
    }
}
