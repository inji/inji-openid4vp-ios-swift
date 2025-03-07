import Foundation
import JSONWebEncryption

struct AuthorizationResponse{
    static var vpTokenForSigning: VpTokenForSigning?
    static var verifiableCredentials: [String: [String]]?
    static let className = String(describing: AuthorizationResponse.self)
    
    static func constructVpForSigning(_ verifiableCredentials: [String: [String]]) throws -> String {
        
        guard !verifiableCredentials.isEmpty else {
                throw Logger.handleException(exceptionType: "CredentialsMapIsEmpty", fieldPath: ["credentials_map"], className: AuthorizationResponse.className)
            }

            for (key, values) in verifiableCredentials {
                guard !values.isEmpty else {
                    throw Logger.handleException(exceptionType: "CredentialsMapValueIsEmpty", fieldPath: ["credentials_map", key], className: AuthorizationResponse.className)
                }
            }
        
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
        
        let requestBody = try createAuthorizationResponseBody(vpToken: vpToken, authorizationRequest: authorizationRequest, presentationSubmission: presentationSubmission, state: authorizationRequest.state)
        
        let response = try await networkManager.sendHTTPRequest(url: responseUri, method: HTTP_METHOD.POST, bodyParams: requestBody, headers: ["Content-Type" : ContentTypes.applicationFormUrlEncoded])
        
        return response.responseBody
    }

}
