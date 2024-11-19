import Foundation

struct Constraints: Codable {
    let fields: [Fields]?
    let limitDisclosure: LimitDisclosure?
    static let className = String(describing: Constraints.self)
    
    enum CodingKeys: String, CodingKey {
        case fields
        case limitDisclosure
    }
    
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        
        self.fields = try container.decodeIfPresent([Fields].self, forKey: .fields)
        self.limitDisclosure = try container.decodeIfPresent(LimitDisclosure.self, forKey: .limitDisclosure)
        
        try validate()
    }
    
    func validate() throws {
        
        if let fields = fields {
            for field in fields {
                try field.validate()
            }
        }
        
        if let limitDisclosure = limitDisclosure {
            guard isNeitherNullNorEmpty(field: limitDisclosure.rawValue) else {
                throw Logger.handleException(exceptionType: "InvalidInput", fieldPath: ["constraints","limit_disclosure"], className: Constraints.className)
            }
            
            guard limitDisclosure == .required || limitDisclosure == .preferred else {
                throw Logger.handleException(exceptionType: "InvalidLimitDisclosure", fieldPath: ["constraints","limit_disclosure"], className: Constraints.className)
            }
        }
    }
}
