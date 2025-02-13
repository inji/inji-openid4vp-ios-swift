import Foundation

struct RequestBody: Encodable {
    let vp_token: VpToken
    let presentation_submission: PresentationSubmission
}

struct AuthorizationResponse{
    static var vpTokenForSigning: VpTokenForSigning?
    static var descriptorMap: [DescriptorMap]?
    static let className = String(describing: AuthorizationResponse.self)
    
    static func constructVpForSigning(_ credentialsMap: [String: [String]]) throws -> String {
        
        guard !credentialsMap.isEmpty else {
                throw Logger.handleException(exceptionType: "credentialsMapIsEmpty", fieldPath: ["credentials_map"], className: AuthorizationResponse.className)
            }
            
            for (key, values) in credentialsMap {
                guard !values.isEmpty else {
                    throw Logger.handleException(exceptionType: "credentialsMapValueIsEmpty", fieldPath: ["credentials_map", key], className: AuthorizationResponse.className)
                }
            }
        
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
    
    static func shareVp(vpResponseMetadata: VPResponseMetadata, authorizationRequest: AuthorizationRequest, networkManager: NetworkManaging) async throws -> String? {
        
        try vpResponseMetadata.validate()
        
        let proof = Proof.constructProof(from: vpResponseMetadata, challenge: authorizationRequest.nonce)
        
        let presentationSubmission = PresentationSubmission(definition_id: authorizationRequest.clientId, descriptor_map: self.descriptorMap!)
        
        let vpToken = VpToken.constructVpToken(signingVPToken: vpTokenForSigning!, proof: proof)
        
        if authorizationRequest.responseMode == ResponseMode.directPostJwt.rawValue {
            return try await constructJWEAndSendHttpRequest(vpToken: vpToken, authorizationRequest: authorizationRequest, presentationSubmission: presentationSubmission, networkManager: networkManager)
        }
        return try await constructAndSendHttpRequest(vpToken: vpToken, presentationSubmission: presentationSubmission, responseUri: authorizationRequest.responseUri ?? "", state: authorizationRequest.state, networkManager: networkManager)
    }
    
    private static func constructJWEAndSendHttpRequest(
        vpToken: VpToken,
        authorizationRequest: AuthorizationRequest,
        presentationSubmission: PresentationSubmission,
        networkManager: NetworkManaging = NetworkManager.shared
    ) async throws -> String? {
        
        guard let clientMetadata = authorizationRequest.clientMetadata as? ClientMetadata, let jwkFromMetadata = clientMetadata.jwks!.keys.first else {
            throw Logger.handleException(exceptionType: "JWKSExtractionFailed", className: AuthorizationResponse.className)
        }
        
        guard let alg = clientMetadata.authorization_encrypted_response_alg,
              let enc = clientMetadata.authorization_encrypted_response_enc else {
            throw Logger.handleException(exceptionType: "EncryptionConfigExtractionFailed", className: AuthorizationResponse.className)
        }
        
        guard let responseUri = authorizationRequest.responseUri,
              let url = URL(string: responseUri) else {
            throw Logger.handleException(exceptionType: "urlCreationFailed", className: AuthorizationResponse.className)
        }
        
        let requestBody = RequestBody(vp_token: vpToken, presentation_submission: presentationSubmission)
        
        let jwk = JWK(
            kty: jwkFromMetadata.kty,
            use: jwkFromMetadata.use,
            crv: jwkFromMetadata.crv,
            x: jwkFromMetadata.x,
            alg: jwkFromMetadata.alg,
            kid: jwkFromMetadata.kid
        )
        
        let config = JWEEncryptionConfig(alg: alg, enc: enc)
        
        let service = JWEEncryptionService(config: config, jwk: jwk)
        
        guard let encryptedPayload = try? service.encryptPayload(encodeToJsonString(requestBody)!) else {
            throw Logger.handleException(exceptionType: "JWEEncryptionFailed", className: AuthorizationResponse.className)
        }
    
        let queryItems = [URLQueryItem(name: "response", value: encodeQueryValue(encryptedPayload))]
        
        var urlComponents = URLComponents()
        urlComponents.queryItems = queryItems
        
        let response = urlComponents.query
        
        return try await networkManager.sendHTTPRequest(
            url: url,
            method: HTTP_METHOD.POST,
            bodyParams: response,
            headers: ["Content-Type": "application/x-www-form-urlencoded"]
        )
    }

private static func constructAndSendHttpRequest(vpToken: VpToken, presentationSubmission: PresentationSubmission, responseUri: String, state: String, networkManager: NetworkManaging = NetworkManager.shared) async throws -> String? {
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
    bodyComponents.append(URLQueryItem(name: "state", value: encodeQueryValue(state)))
    
    var urlComponents = URLComponents()
    urlComponents.queryItems = bodyComponents
    
    let requestBody = urlComponents.query
    
    guard let url = URL(string: responseUri) else {
        throw Logger.handleException(exceptionType: "UrlCreationFailed", fieldPath: ["response_uri"], className: AuthorizationResponse.className)
    }
    
    return try await networkManager.sendHTTPRequest(url: url, method: HTTP_METHOD.POST, bodyParams: requestBody ?? "", headers: ["Content-Type" : "application/x-www-form-urlencoded"])
}

}
