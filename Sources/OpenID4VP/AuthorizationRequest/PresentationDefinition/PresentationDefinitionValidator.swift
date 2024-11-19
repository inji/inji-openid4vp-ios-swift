import Foundation

struct PresentationDefinitionValidator {
    static let className = String(describing: PresentationDefinitionValidator.self)
    
    static func validate(presentatioDefinition: String) throws -> PresentationDefinition {
        
        guard let jsonData = presentatioDefinition.data(using: .utf8) else {
            throw Logger.handleException(exceptionType: "UTF8Encoding", fieldPath: ["presentation_definition"], className: PresentationDefinitionValidator.className)
        }
        
        do {
            return try JSONDecoder().decode(PresentationDefinition.self, from: jsonData)
        } catch {
            throw error
        }
    }
}
