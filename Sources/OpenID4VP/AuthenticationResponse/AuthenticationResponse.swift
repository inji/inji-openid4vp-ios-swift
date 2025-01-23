import Foundation

public struct AuthenticationResponse {
    static let className = String(describing: AuthenticationResponse.self)
    
    static func validateAuthorizationRequestPartially(_ authorizationRequest: AuthorizationRequest, updateAuthorizationRequest: (PresentationDefinition, ClientMetadata?) -> Void) throws {
        var clientMetadata: ClientMetadata?
        
        let presentationDefinition: PresentationDefinition = try PresentationDefinitionValidator.validate(presentatioDefinition: authorizationRequest.presentationDefinition as! String)
        
        if let clientMeta = authorizationRequest.clientMetadata {
            clientMetadata = try ClientMetadata.decodeAndValidateClientMetadata(clientMetadata: clientMeta as! String)
        }
        
        updateAuthorizationRequest(presentationDefinition, clientMetadata)
    }
}
