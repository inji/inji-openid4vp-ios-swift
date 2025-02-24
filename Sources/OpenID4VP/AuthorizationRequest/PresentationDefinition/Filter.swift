import Foundation

struct Filter: Codable, Equatable {
    let type: String
    let pattern: String
    static let className = String(describing: PresentationDefinition.self)
    
    enum CodingKeys: String, CodingKey {
        case type
        case pattern
    }
    
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        self.type = try container.decodeRequired(
            String.self,
            forKey: .type,
            fieldPath: ["filter", "type"],
            className: Filter.className,
            isMandatory: true
        )!
        
        self.pattern = try container.decodeRequired(
            String.self,
            forKey: .pattern,
            fieldPath: ["filter", "pattern"],
            className: Filter.className,
            isMandatory: true
        )!
        
        try validate()
    }
    
    func validate() throws {
        guard isNeitherNullNorEmpty(field: type) else {
            throw Logger.handleException(exceptionType: "InvalidInput", fieldPath: ["filter","type"], className: Filter.className)
        }
        
        guard isNeitherNullNorEmpty(field: pattern) else {
            throw Logger.handleException(exceptionType: "InvalidInput", fieldPath: ["filter","pattern"], className: Filter.className)
        }
    }
    
    static func == (lhs: Filter, rhs: Filter) -> Bool {
        return lhs.type == rhs.type && lhs.pattern == rhs.pattern
    }
}
