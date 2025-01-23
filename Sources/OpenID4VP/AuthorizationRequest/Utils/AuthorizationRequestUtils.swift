import Foundation
import CryptoKit

func isJWT(_ encodedString: String) -> Bool{
    return encodedString.contains(".") ? true : false
}

func createAuthorizationRequest(from params: [String: String]) -> AuthorizationRequest {
    return AuthorizationRequest(
        clientId: params["client_id"]!,
        clientIdScheme: params["client_id_scheme"]!,
        presentationDefinition: params["presentation_definition"]!,
        responseType: params["response_type"]!,
        responseMode: params["response_mode"],
        nonce: params["nonce"]!,
        state: params["state"]!,
        redirectUri: params["redirect_uri"],
        responseUri: params["response_uri"],
        clientMetadata: params["client_metadata"]
    )
}

func validateVerifier(verifierList: [Verifier], authorizationRequest: AuthorizationRequest) throws {
    
    let clientIdScheme = authorizationRequest.clientIdScheme
    let clientId = authorizationRequest.clientId
    let redirectUri = authorizationRequest.redirectUri
    
    if clientIdScheme == ClientIdScheme.preRegistered.rawValue {
        
        guard !verifierList.isEmpty else {
                throw Logger.handleException(exceptionType: "EmptyVerifierList", className: AuthorizationRequest.className)
            }
        
        guard verifierList.contains(where: { $0.clientId == clientId && $0.responseUris.contains(authorizationRequest.responseUri!) }) else {
                    throw Logger.handleException(exceptionType: "InvalidVerifierClientID", className: AuthorizationRequest.className)
                }
    }
    
    if clientIdScheme == ClientIdScheme.redirectUri.rawValue {
        if (redirectUri != nil) {
            guard redirectUri == clientId else {
                throw Logger.handleException(exceptionType: "InvalidVerifierRedirectUri", className: AuthorizationRequest.className)
            }
        }
    }
}

func decodeAuthorizationRequest(_ encodedAuthorizationRequest: String) -> String? {
    return Data(base64Encoded: encodedAuthorizationRequest)
        .flatMap { String(data: $0, encoding: .utf8) }
}

func urlEncodedRequest(_ decodedRequest: String) -> URL? {
    return decodedRequest.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)
        .flatMap { URL(string: $0) }
}

func getQueryItems(_ encodedUrl: URL) -> [URLQueryItem]? {
    return URLComponents(url: encodedUrl, resolvingAgainstBaseURL: false)?.queryItems
}

extension KeyedDecodingContainer {
    func decodeRequired<T>(
        _ type: T.Type,
        forKey key: K,
        fieldPath: [String],
        className: String,
        isMandatory: Bool
    ) throws -> T? where T: Decodable {
        if isMandatory {
            guard contains(key) else {
                throw Logger.handleException(
                    exceptionType: "MissingInput",
                    fieldPath: fieldPath,
                    className: className
                )
            }
        }
        if contains(key) {
            let rawValue = try decodeIfPresent(T?.self, forKey: key)
            if rawValue == nil {
                throw Logger.handleException(
                    exceptionType: "InvalidInput",
                    fieldPath: fieldPath,
                    className: InputDescriptor.className
                )
            }
            return rawValue!
        }
        return nil
    }
}
