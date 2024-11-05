import Foundation

struct PresentationDefinitionValidator {
    
    static func validate(presentatioDefinition: String) throws -> PresentationDefinition {
        
        Logger.getLogTag(className: String(describing: self))
        
        guard let jsonData = presentatioDefinition.data(using: .utf8) else {
            Logger.error("Failed to convert presentation_definition string to UTF-8 data.")
            throw AuthorizationRequestException.utf8Encoding(fieldName: "presentation_definition")
        }
        
        do {
          return try JSONDecoder().decode(PresentationDefinition.self, from: jsonData)
        } catch {
            throw AuthorizationRequestException.invalidPresentationDefinition
        }
    }
}
