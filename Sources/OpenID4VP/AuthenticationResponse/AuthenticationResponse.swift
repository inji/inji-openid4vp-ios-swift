import Foundation

public struct AuthenticationResponse {
    
    static func validateAuthorizationRequestPartially(_ authorizationRequest: AuthorizationRequest,_ trustedVerifierJSON: [Verifier], updateAuthorizationRequest: (PresentationDefinition, ClientMetadata?) -> Void) throws {
        
        Logger.getLogTag(className: String(describing: self))
        
        var clientMetadata: ClientMetadata?
        
        try validateVerifier(verifierList: trustedVerifierJSON, clientId: authorizationRequest.clientId, responseUri: authorizationRequest.responseUri)
        
        let presentationDefinition: PresentationDefinition = try PresentationDefinitionValidator.validate(presentatioDefinition: authorizationRequest.presentationDefinition as! String)
        
        if let clientMeta = authorizationRequest.clientMetadata {
            clientMetadata = try ClientMetadata.decodeAndValidateClientMetadata(clientMetadata: clientMeta as! String)
        }
        
        updateAuthorizationRequest(presentationDefinition, clientMetadata)
    }
    
    private static func validateVerifier(verifierList: [Verifier], clientId receivedClientId: String, responseUri receivedResponseUri: String) throws {
        
        guard verifierList.contains(where: { $0.clientId == receivedClientId && $0.responseUris.contains(receivedResponseUri) }) else {
            
            Logger.error("Client ID \(receivedClientId) not found in verifier list: \(verifierList)")
            throw VerifierVerificationException.invalidVerifierClientID(message: "VP sharing failed: Verifier authentication was unsuccessful")
        }
    }
}
