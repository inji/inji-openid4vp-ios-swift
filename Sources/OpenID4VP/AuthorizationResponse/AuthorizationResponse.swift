import Foundation
import JSONWebEncryption

struct AuthorizationResponse{
    static var vpTokenForSigning: VpTokenForSigning?
    static var verifiableCredentials: [String: [String]]?
    static let className = String(describing: AuthorizationResponse.self)
    
    static func constructVpForSigning(_ verifiableCredentials: [String: [String]]) throws -> String {
        self.verifiableCredentials = verifiableCredentials
        
        var credentialsArray: [String] = []
        for (_, values) in verifiableCredentials {
            for vc in values {
                credentialsArray.append(vc)
            }
        }
        
        self.vpTokenForSigning = VpTokenForSigning(verifiableCredential: credentialsArray,id: UUIDGenerator.generateUUID(), holder: "")
        
        return try encode(self.vpTokenForSigning, fieldName: "vp_token_for_signing")
    }
    
    static func shareVp(vpResponseMetadata: VPResponseMetadata, authorizationRequest: AuthorizationRequest, responseUri: String, networkManager: NetworkManaging) async throws -> String? {
        
        try vpResponseMetadata.validate()
        let proof = Proof.construct(from: vpResponseMetadata, challenge: authorizationRequest.nonce)
        
        let presentationSubmission = PresentationSubmission(definition_id: authorizationRequest.clientId, descriptor_map: createDescriptorMap(verifiableCredentials: verifiableCredentials!))
        let vpToken = VPToken.construct(signingVPToken: vpTokenForSigning!, proof: proof)
        
        return try await ResponseModeBasedHandlerFactory.get(responseMode: authorizationRequest.responseMode).sendAuthorizationResponse(vpToken: vpToken, authorizationRequest: authorizationRequest, presentationSubmission: presentationSubmission, state: authorizationRequest.state, url: responseUri, networkManager: networkManager)
    }

}
