import Foundation

struct Fields: Codable {
    let path: [String]
    let id: String?
    let name: String?
    let purpose: String?
    let filter: Filter?
    let optional: Bool?
    static let className = String(describing: PresentationDefinitionValidator.self)
    
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
            throw Logger.handleException(exceptionType: "MissingInput", fieldPath: ["fields","path"], className: Fields.className)
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
            throw Logger.handleException(exceptionType: "InvalidInput", fieldPath: ["fields","path"], className: Fields.className)
        }
        
        let pathPrefixArray = ["$.","$["]
        if !path.allSatisfy({ p in pathPrefixArray.contains(where: { p.hasPrefix($0) }) }) {
            throw Logger.handleException(exceptionType: "InvalidInputPattern", fieldPath: ["fields","path"], className: Fields.className)
        }

        if let filter = filter {
            try filter.validate()
        }
    }
}
