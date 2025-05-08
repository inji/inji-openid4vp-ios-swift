import Foundation

struct Constraints: Codable {
    let fields: [Fields]?
    let limitDisclosure: LimitDisclosure?
    let className = String(describing: Constraints.self)
    
    enum CodingKeys: String, CodingKey {
        case fields
        case limitDisclosure = "limit_disclosure"
    }
    
    init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            
            self.fields = try container.decodeRequired(
                [Fields].self,
                forKey: .fields,
                fieldPath: ["constraints", "fields"],
                className: className,
                isMandatory: false
            )
            
            guard let limitDisclosure = try? container.decodeRequired(
                LimitDisclosure.self,
                forKey: .limitDisclosure,
                fieldPath: ["constraints", "limitDisclosure"],
                className: className,
                isMandatory: false
            ) else {
                throw Logger.handleException(exceptionType: "InvalidLimitDisclosure", fieldPath: ["constraints","limit_disclosure"], className: className)
            }
            self.limitDisclosure = limitDisclosure
            
            try validate()
        }
    
    func validate() throws {
        
        if let fields = fields, !fields.isEmpty {
            try fields.forEach { try $0.validate() }
        }
        
        if let limitDisclosure = limitDisclosure {
            guard isNeitherNullNorEmpty(field: limitDisclosure.rawValue) else {
                throw Logger.handleException(exceptionType: "InvalidInput", fieldPath: ["constraints","limit_disclosure"], className: className)
            }
        }
    }
}
