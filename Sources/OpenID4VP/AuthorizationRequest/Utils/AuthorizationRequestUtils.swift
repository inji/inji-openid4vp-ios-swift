import Foundation
import CryptoKit

func validateAttribute(
    _ attribute: String,
    values: [String: Any]
) throws {
    guard let value = values[attribute] else {
        throw Logger.handleException(
            exceptionType: "MissingInput",
            fieldPath: [attribute],
            className: AuthorizationRequest.className
        )
    }
    
    if let stringValue = value as? String {
        if stringValue.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ||
            stringValue.lowercased() == "nil" ||
            stringValue.lowercased() == "null" {
            throw Logger.handleException(
                exceptionType: "InvalidInput",
                fieldPath: [attribute],
                className: AuthorizationRequest.className
            )
        }
    }
}

func validateAuthorizationRequestObjectAndParameters(params: [String: String], requestUriParams: [String: Any]) throws {
    
    
    guard params["client_id"] == requestUriParams["client_id"] as? String else {
        throw Logger.handleException(exceptionType: "MismatchingClientIDInRequest", className: AuthorizationRequest.className)
    }
    
    // If client_id_scheme is present in the authorization request, it should be present in the request_uri response as well and should be same we are assuming it follows Draft 21 specification
    if params[AuthorizationRequestFieldConstants.clientIdScheme.rawValue] != nil {
        guard params["client_id_scheme"] == requestUriParams["client_id_scheme"] as? String else {
            throw Logger.handleException(exceptionType: "MismatchingClientIdSchemeInRequest", className: AuthorizationRequest.className)
        }
    }
}

extension Dictionary where Key == String, Value == String {
    func values(forKeys keys: [String]) -> [String]? {
        let values = keys.compactMap { self[$0] }
        return values.count == keys.count ? values : nil
    }
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
                    className: className
                )
            }
            return rawValue!
        }
        return nil
    }
}


func getAuthorizationRequestHandler(authorizationRequestParameters: [String:Any],
                                    trustedVerifiers : [Verifier],
                                    walletMetadata: WalletMetadata?,
                                    shouldValidateClient: Bool,
                                    setResponseUri: @escaping (String) -> Void,
                                    networkManager: NetworkManaging
                                    ) throws -> ClientIdSchemeBasedAuthorizationRequestHandler {
    let clientIdScheme = try extractClientIdScheme(authorizationRequestParams: authorizationRequestParameters)
    
    switch clientIdScheme {
    case ClientIdScheme.preRegistered.rawValue:
        return PreRegisteredSchemeAuthorizationRequestHandler(trustedVerifiers: trustedVerifiers,
                                                              authorizationRequestParameters: authorizationRequestParameters,
                                                              walletMetadata: walletMetadata,
                                                              shouldValidateClient: shouldValidateClient,
                                                              setResponseUri: setResponseUri,
                                                              networkManager: networkManager)
    case ClientIdScheme.did.rawValue:
        return DidSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters,
                                                    walletMetadata: walletMetadata,
                                                    setResponseUri: setResponseUri,
                                                    networkManager: networkManager)
    case ClientIdScheme.redirectUri.rawValue:
        return RedirectUriSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters,
                                                            walletMetadata: walletMetadata,
                                                            setResponseUri: setResponseUri,
                                                            networkManager: networkManager)
    default:
        throw Logger.handleException(exceptionType: "InvalidData",message: "Client id scheme in request is not supported" ,className: AuthorizationRequest.className)
    }
}

func extractQueryParameters(_ input: String) throws -> [String: String] {
    guard input.firstIndex(of: "?") != nil else {
        throw Logger.handleException(exceptionType: "InvalidQueryParams", message: "Query parameters are missing in the Authorization request", className: AuthorizationRequest.className)
    }
    let urlComponents = URLComponents(string: input)
    var decodedParams = [String: String]()
    
    if let queryItems = urlComponents?.queryItems {
        for item in queryItems {
            if let decodedValue = item.value?.removingPercentEncoding {
                decodedParams[item.name] = decodedValue
            }
        }
    }
    
    return decodedParams
}

func validateField<T>(_ field: T?, _ fieldPath: [String], _ className: String) throws {
    guard let field = field else { return }
    
    switch field {
    case let stringValue as String:
        guard isNeitherNullNorEmpty(field: stringValue) else {
            throw Logger.handleException(exceptionType: "InvalidInput", fieldPath: fieldPath, className: className)
        }
    case let dictValue as [String: Any]:
        guard !dictValue.isEmpty else {
            throw Logger.handleException(exceptionType: "InvalidInput", fieldPath: fieldPath, className: className)
        }
        try dictValue.forEach { key, value in
            try validateField(value, fieldPath + [key], className)
        }
    case let arrayValue as [Any]:
        guard !arrayValue.isEmpty else {
            throw Logger.handleException(exceptionType: "InvalidInput", fieldPath: fieldPath, className: className)
        }
        for (index, value) in arrayValue.enumerated() {
            try validateField(value, fieldPath + ["\(index)"], className)
        }
    default:
        break
    }
}

func extractClientIdScheme(authorizationRequestParams: [String:Any]) throws -> String {
    if let scheme = authorizationRequestParams[AuthorizationRequestFieldConstants.clientIdScheme.rawValue] as? String {
        try validateField(scheme, [AuthorizationRequestFieldConstants.clientIdScheme.rawValue], AuthorizationRequest.className)
        return scheme
    }
      
    try validateAttribute(AuthorizationRequestFieldConstants.clientId.rawValue, values: authorizationRequestParams)
    let clientId = authorizationRequestParams[AuthorizationRequestFieldConstants.clientId.rawValue] as? String ?? ""
    
    let components = clientId.split(separator: ":", maxSplits: 1)
        
    if components.count > 1 {
         return String(components[0])
    } else {
        // Fallback client_id_scheme pre-registered; pre-registered clients MUST NOT contain a : character in their Client Identifier
        return ClientIdScheme.preRegistered.rawValue
    }
}

public func extractClientIdPartOnly(_ clientIdWithClientIdSchemeAttached: String) -> String {
    let components = clientIdWithClientIdSchemeAttached.split(separator: ":", maxSplits: 1)
    if components.count > 1 {
        let clientIdScheme = String(components[0])
        // DID client ID scheme will have the client id itself with did prefix, example - did:example:123#1. So there will not be additional prefix stating client_id_scheme
        if(clientIdScheme == ClientIdScheme.did.rawValue){
            return clientIdWithClientIdSchemeAttached
        }
        return String(components[1])
    } else {
        // client_id_scheme is optional (Fallback client_id_scheme - pre-registered) i.e., a : character is not present in the Client Identifier
        return clientIdWithClientIdSchemeAttached
    }
}
