import Foundation

struct Fields: Codable {
    let path: [String]
    let id: String?
    let name: String?
    let purpose: String?
    let filter: Filter?
    let optional: Bool?
    
    enum CodingKeys: String, CodingKey {
        case path
        case id
        case name
        case purpose
        case filter
        case optional
    }
    
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        
        guard let path = try container.decodeIfPresent([String].self, forKey: .path) else {
            Logger.error("Field : path should be present.")
            throw AuthorizationRequestException.missingInput(fieldName: "path")
        }
        
        self.path = path
        self.id = try container.decodeIfPresent(String.self, forKey: .id)
        self.name = try container.decodeIfPresent(String.self, forKey: .name)
        self.purpose = try container.decodeIfPresent(String.self, forKey: .purpose)
        self.filter = try container.decodeIfPresent(Filter.self, forKey: .filter)
        self.optional = try container.decodeIfPresent(Bool.self, forKey: .optional)
        
        try validate()
    }
    
    func validate() throws {
        guard !path.isEmpty else {
            Logger.error("Field : path should not be empty.")
            throw AuthorizationRequestException.invalidInput(fieldName: "path")
        }
        
        let pathPrefixArray = ["$.","$["]
        if !path.allSatisfy({ p in pathPrefixArray.contains(where: { p.hasPrefix($0) }) }) {
            Logger.error("Field : path is invalid.")
            throw AuthorizationRequestException.invalidPresentationDefinition
        }

        if let filter = filter {
            try filter.validate()
        }
    }
}
