//
//  File.swift
//  
//
//  Created by Kiruthika Jeyashankar on 11/03/25.
//

import Foundation


struct DirectPostJwtResponseModeHandler : ResponseModeBasedHandler {
    func validate(clientMetadata: ClientMetadata?) throws {
        guard let clientMetadataObject = clientMetadata else {
            throw Logger.handleException(
                exceptionType: "InvalidData",
                message: "client_metadata must be present for given response mode",
                className: className
            )
        }
        guard let alg = clientMetadataObject.authorization_encrypted_response_alg else {
            throw Logger.handleException(
                exceptionType: "MissingInput",
                fieldPath: ["client_metadata", "authorization_encrypted_response_alg"],
                className: className
            )
        }

        if (clientMetadataObject.authorization_encrypted_response_enc) == nil {
            throw Logger.handleException(
                exceptionType: "MissingInput",
                fieldPath: ["client_metadata", "authorization_encrypted_response_enc"],
                className: className
            )
        }

        guard let jwks = clientMetadataObject.jwks else {
            throw Logger.handleException(
                exceptionType: "MissingInput",
                fieldPath: ["client_metadata", "jwks"],
                className: className
            )
        }

        if !jwks.keys.contains(where: { $0.alg == alg }) {
            throw Logger.handleException(
                exceptionType: "InvalidData",
                message: "No jwk matching the specified algorithm found",
                fieldPath: ["jwks", "keys"],
                className: className
            )
        }
    }
    
    func sendAuthorizationResponse(vpToken: VPToken, authorizationRequest: AuthorizationRequest, presentationSubmission: PresentationSubmission, state: String?, url responseUri: String, networkManager: NetworkManaging) async throws -> String {
        let bodyParams = try constructBodyParams(vpToken: vpToken, presentationSubmission: presentationSubmission, state: state, shouldEncode: false)
        let clientMetadata = (authorizationRequest.clientMetadata)!
        let verifierPublicKey = try getJwk(clientMetadata.jwks!, clientMetadata.authorization_encrypted_response_alg!)
        
        let encryptedBody = try JWEHandler(keyEncryptionAlgorithm: clientMetadata.authorization_encrypted_response_alg!, contentEncryptionAlgorithm: clientMetadata.authorization_encrypted_response_enc!, publicKey: verifierPublicKey).createResponse(payload: bodyParams)
        
        let requestBody = ["response": encryptedBody]
        let response = try await networkManager.sendHTTPRequest(url: responseUri, method: HTTP_METHOD.POST, bodyParams: requestBody, headers: ["Content-Type" : ContentTypes.applicationFormUrlEncoded])
        
        return response.responseBody
    }
    
    private func getJwk(_ jwks: JWKS, _ alg: String) throws -> JWK {
        return jwks.keys.first(where: { $0.alg == alg })!
    }
}
