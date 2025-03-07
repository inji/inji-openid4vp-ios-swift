import Foundation

let className = String(describing: ClientMetadata.self)

func parseAndValidateClientMetadata(authorizationRequest: [String: Any]) throws -> [String: Any] {
    var mutableParams = authorizationRequest
    if let clientMetadataObject = authorizationRequest["client_metadata"] as? NSDictionary{
        let data = try JSONSerialization.data(withJSONObject: clientMetadataObject, options: [])
        let clientMetadata = try ClientMetadata.deserializeAndValidate(clientMetadata: data)
        mutableParams["client_metadata"] = clientMetadata
    } else if let clientMetaString = authorizationRequest["client_metadata"] as? String {
        let clientMetadata = try ClientMetadata.deserializeAndValidate(clientMetadata: clientMetaString)
        mutableParams["client_metadata"] = clientMetadata
    }
    
    try validateClientMetadataBasedOnResponseMode(clientMetadata: mutableParams["client_metadata"] as! ClientMetadata, authorizationRequestParameters: &mutableParams)
    
    return mutableParams
}

private func validateClientMetadataBasedOnResponseMode(
    clientMetadata: ClientMetadata,
    authorizationRequestParameters: inout [String: Any]
) throws {
    
    guard let responseMode = authorizationRequestParameters["response_mode"] as? String else {
        return
    }

    if responseMode == ResponseMode.directPostJwt.rawValue {
        guard let alg = clientMetadata.authorization_encrypted_response_alg else {
            throw Logger.handleException(
                exceptionType: "MissingEncryptionParameters",
                message: "Missing required encryption algorithm",
                className: className
            )
        }

        guard let enc = clientMetadata.authorization_encrypted_response_enc else {
            throw Logger.handleException(
                exceptionType: "MissingEncryptionParameters",
                message: "Missing required encryption encoding",
                className: className
            )
        }

        guard let jwks = clientMetadata.jwks else {
            throw Logger.handleException(
                exceptionType: "MissingEncryptionKey",
                message: "No JWKs found in client_metadata",
                fieldPath: ["jwks"],
                className: className
            )
        }

        if !jwks.keys.contains(where: { $0.alg == alg }) {
            throw Logger.handleException(
                exceptionType: "MissingEncryptionKey",
                message: "No JWK matching the specified algorithm found: \(alg)",
                fieldPath: ["jwks", "keys"],
                className: className
            )
        }
    }
}
