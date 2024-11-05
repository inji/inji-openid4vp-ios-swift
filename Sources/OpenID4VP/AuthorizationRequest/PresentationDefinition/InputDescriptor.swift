import Foundation

struct InputDescriptor: Codable {
    let id: String
    let name: String?
    let purpose: String?
    let constraints: Constraints
    let format: Format?
    
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
            Logger.error("Input Descriptor : Id should be present.")
            throw AuthorizationRequestException.missingInput(fieldName: "id")
        }
        
        guard let constraints = try container.decodeIfPresent(Constraints.self, forKey: .constraints) else {
            Logger.error("Input Descriptor : Constraints should be present.")
            throw AuthorizationRequestException.missingInput(fieldName: "constraints")
        }
        
        self.id = id
        self.constraints = constraints
        self.name = try container.decodeIfPresent(String.self, forKey: .name)
        self.purpose = try container.decodeIfPresent(String.self, forKey: .purpose)
        self.format = try container.decodeIfPresent(Format.self, forKey: .format)
        
    }
    
    func validate() throws {
        guard !id.isEmpty else {
            Logger.error("Input Descriptor : Id should not be empty.")
            throw AuthorizationRequestException.invalidInput(fieldName: "id")
        }
        
        try format?.validate()
        try constraints.validate()
    }
}
