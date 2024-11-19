import Foundation

struct InputDescriptor: Codable {
    let id: String
    let name: String?
    let purpose: String?
    let constraints: Constraints
    let format: Format?
    static let className = String(describing: PresentationDefinitionValidator.self)
    
    enum CodingKeys: String, CodingKey {
        case id
        case name
        case purpose
        case constraints
        case format
    }
    
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        
        guard let id = try container.decodeIfPresent(String.self, forKey: .id) else {
            throw Logger.handleException(exceptionType: "MissingInput", fieldPath: ["input_descriptor","id"], className: InputDescriptor.className)
        }
        
        guard let constraints = try container.decodeIfPresent(Constraints.self, forKey: .constraints) else {
            throw Logger.handleException(exceptionType: "MissingInput", fieldPath: ["input_descriptor","constraints"], className: InputDescriptor.className)
        }
        
        self.id = id
        self.constraints = constraints
        self.name = try container.decodeIfPresent(String.self, forKey: .name)
        self.purpose = try container.decodeIfPresent(String.self, forKey: .purpose)
        self.format = try container.decodeIfPresent(Format.self, forKey: .format)
        
    }
    
    func validate() throws {
        guard !id.isEmpty else {
            throw Logger.handleException(exceptionType: "InvalidInput", fieldPath: ["input_descriptor","id"], className: InputDescriptor.className)
        }
        
        try format?.validate()
        try constraints.validate()
    }
}
