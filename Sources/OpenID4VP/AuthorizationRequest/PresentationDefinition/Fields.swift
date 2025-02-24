import Foundation

struct Fields: Codable, Equatable {
    let path: [String]
    let id: String?
    let name: String?
    let purpose: String?
    let filter: Filter?
    let optional: Bool?
    static let className = String(describing: PresentationDefinition.self)
    
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
            
            self.path = try container.decodeRequired(
                [String].self,
                forKey: .path,
                fieldPath: ["fields", "path"],
                className: Fields.className,
                isMandatory: true
            )!
            
            self.id = try container.decodeRequired(
                String.self,
                forKey: .id,
                fieldPath: ["fields", "id"],
                className: Fields.className,
                isMandatory: false)
            
            self.name = try container.decodeRequired(
                String.self,
                forKey: .name,
                fieldPath: ["fields", "name"],
                className: Fields.className,
                isMandatory: false)
            
            self.purpose = try container.decodeRequired(
                String.self,
                forKey: .purpose,
                fieldPath: ["fields", "purpose"],
                className: Fields.className,
                isMandatory: false)
            
            self.filter = try container.decodeRequired(
                Filter.self,
                forKey: .filter,
                fieldPath: ["fields", "filter"],
                className: Fields.className,
                isMandatory: false)
            
            self.optional = try container.decodeRequired(
                Bool.self,
                forKey: .optional,
                fieldPath: ["fields", "optional"],
                className: Fields.className,
                isMandatory: false)
            
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
        
        if let id = id {
            guard isNeitherNullNorEmpty(field: id) else {
                throw Logger.handleException(exceptionType: "InvalidInput", fieldPath: ["fields","purpose"], className: Fields.className)
            }
        }
        
        if let name = name {
            guard isNeitherNullNorEmpty(field: name) else {
                throw Logger.handleException(exceptionType: "InvalidInput", fieldPath: ["fields","name"], className: Fields.className)
            }
        }
        
        if let purpose = purpose {
            guard isNeitherNullNorEmpty(field: purpose) else {
                throw Logger.handleException(exceptionType: "InvalidInput", fieldPath: ["fields","purpose"], className: Fields.className)
            }
        }

        if let filter = filter {
            try filter.validate()
        }
    }
    
    static func == (lhs: Fields, rhs: Fields) -> Bool {
        return lhs.path == rhs.path && lhs.id == rhs.id &&
        lhs.name == rhs.name && lhs.purpose == rhs.purpose &&
        lhs.filter == rhs.filter && lhs.optional == rhs.optional
    }
}
