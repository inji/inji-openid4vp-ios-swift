import Foundation

struct Constraints: Codable, Equatable {
    let fields: [Fields]?
    let limitDisclosure: LimitDisclosure?
    static let className = String(describing: Constraints.self)
    
    enum CodingKeys: String, CodingKey {
        case fields
        case limitDisclosure
    }
    
    init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            
            self.fields = try container.decodeRequired(
                [Fields].self,
                forKey: .fields,
                fieldPath: ["constraints", "fields"],
                className: Constraints.className,
                isMandatory: false
            )
            
            self.limitDisclosure = try container.decodeRequired(
                LimitDisclosure.self,
                forKey: .limitDisclosure,
                fieldPath: ["constraints", "limitDisclosure"],
                className: Constraints.className,
                isMandatory: false
            )
            
            try validate()
        }
    
    func validate() throws {
        
        if let fields = fields, !fields.isEmpty {
            try fields.forEach { try $0.validate() }
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
    
    static func == (lhs: Constraints, rhs: Constraints) -> Bool {
        return lhs.fields == rhs.fields && lhs.limitDisclosure == rhs.limitDisclosure
    }
}
