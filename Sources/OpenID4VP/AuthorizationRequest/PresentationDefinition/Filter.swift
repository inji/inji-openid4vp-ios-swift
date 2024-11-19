import Foundation

struct Filter: Codable {
    let type: String
    let pattern: String
    static let className = String(describing: PresentationDefinitionValidator.self)
    
    enum CodingKeys: String, CodingKey {
        case type
        case pattern
    }
    
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        
        guard let type = try container.decodeIfPresent(String.self, forKey: .type) else {
            throw Logger.handleException(exceptionType: "MissingInput", fieldPath: ["filter","type"], className: Filter.className)
        }
        
        guard let pattern = try container.decodeIfPresent(String.self, forKey: .pattern) else {
            throw Logger.handleException(exceptionType: "MissingInput", fieldPath: ["filter","pattern"], className: Filter.className)
        }
        
        self.type = type
        self.pattern = pattern
        
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
}
