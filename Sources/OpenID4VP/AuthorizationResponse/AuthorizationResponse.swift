import Foundation

struct AuthorizationResponse{
    static var vpTokenForSigning: VpTokenForSigning?
    static var descriptorMap: [DescriptorMap]?
    static let className = String(describing: AuthorizationResponse.self)
    
    static func constructVpForSigning(_ credentialsMap: [String: [String]]) throws -> String {
        var credentialsArray: [String] = []
        var descriptorsMap: [DescriptorMap] = []
        var path: Int = 0
        
        for (key,values) in credentialsMap {
            for vc in values {
                credentialsArray.append(vc)
                descriptorsMap.append(DescriptorMap(id: key, format: .ldp_vc, path: "$.verifiableCredential[\(path)]"))
                path += 1
            }
        }
        
        self.descriptorMap = descriptorsMap
        self.vpTokenForSigning = VpTokenForSigning(verifiableCredential: credentialsArray, holder: "")
        
        do {
           return try encodeToJsonString(self.vpTokenForSigning)!
        } catch let error{
            throw Logger.handleException(exceptionType: "JsonEncodingFailed", message: error.localizedDescription, fieldPath: ["vp_token_for_signing"], className: AuthorizationResponse.className)
        }
    }
    
    static func shareVp(vpResponseMetadata: VPResponseMetadata, nonce: String, state: String?, responseUri: String, presentationDefinitionId: String, networkManager: NetworkManaging) async throws -> String? {
        
        try vpResponseMetadata.validate()
        
        let proof = Proof.constructProof(from: vpResponseMetadata, challenge: nonce)
        
        let presentationSubmission = PresentationSubmission(definition_id: presentationDefinitionId, descriptor_map: self.descriptorMap!)
        
        let vpToken = VpToken.constructVpToken(signingVPToken: vpTokenForSigning!, proof: proof)
        
        return try await constructHttpRequestBody(vpToken: vpToken, presentationSubmission: presentationSubmission, responseUri: responseUri, state: state, networkManager: networkManager)
    }
    
    private static func constructHttpRequestBody(vpToken: VpToken, presentationSubmission: PresentationSubmission, responseUri: String, state: String?, networkManager: NetworkManaging = NetworkManager.shared) async throws -> String? {
        let encodedVPTokenData: String, encodedPresentationSubmissionData: String
        do {
            encodedVPTokenData = try encodeToJsonString(vpToken)!
        } catch let error {
            throw Logger.handleException(exceptionType: "JsonEncodingFailed", message: error.localizedDescription, fieldPath: ["vp_token"], className: AuthorizationResponse.className)
        }

        do {
            encodedPresentationSubmissionData = try encodeToJsonString(presentationSubmission)!
        } catch let error {
            throw Logger.handleException(exceptionType: "JsonEncodingFailed", message: error.localizedDescription, fieldPath: ["presentation_submission"], className: AuthorizationResponse.className)
        }
        
        var bodyComponents = [URLQueryItem]()
        bodyComponents.append(URLQueryItem(name: "vp_token", value: encodeQueryValue(encodedVPTokenData)))
        bodyComponents.append(URLQueryItem(name: "presentation_submission", value: encodeQueryValue(encodedPresentationSubmissionData)))
        if state != nil{
            bodyComponents.append(URLQueryItem(name: "state", value: encodeQueryValue(state!)))
        }

        var urlComponents = URLComponents()
        urlComponents.queryItems = bodyComponents

        let requestBody = urlComponents.query
        
        guard let url = URL(string: responseUri) else {
            throw Logger.handleException(exceptionType: "UrlCreationFailed", fieldPath: ["response_uri"], className: AuthorizationResponse.className)
        }

        let response = try await networkManager.sendHTTPRequest(url: url, method: HTTP_METHOD.POST, bodyParams: requestBody ?? "", headers: ["Content-Type" : "application/x-www-form-urlencoded"])
        return response.responseBody
    }

}
