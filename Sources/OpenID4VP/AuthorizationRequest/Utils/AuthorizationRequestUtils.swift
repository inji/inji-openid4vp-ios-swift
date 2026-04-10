import Foundation
import CryptoKit

func validateAttribute(
    _ attribute: String,
    values: [String: Any]
) throws {
    guard let value = values[attribute] else {
        throw MissingInput(
            fieldPath: [attribute],
            className: AuthorizationRequest.className
        )
    }
    
    if let stringValue = value as? String {
        if stringValue.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ||
            stringValue.lowercased() == "nil" ||
            stringValue.lowercased() == "null" {
            throw InvalidInput(
                fieldPath: [attribute],
                className: AuthorizationRequest.className
            )
        }
    }
}

func validateAuthorizationRequestObjectAndParameters(params: [String: Any], requestObject: [String: Any]) throws {
    guard params[AuthorizationRequestFieldConstants.clientId.rawValue] as? String == requestObject[AuthorizationRequestFieldConstants.clientId.rawValue] as? String else {
        throw MismatchingClientIDInRequest(className: AuthorizationRequest.className)
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
                throw MissingInput(
                    fieldPath: fieldPath,
                    className: className
                )
            }
        }
        if contains(key) {
            let rawValue = try decodeIfPresent(T?.self, forKey: key)
            if rawValue == nil {
                throw InvalidInput(
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
                                    walletNonce: String,
                                    networkManager: NetworkManaging
) throws -> ClientIdPrefixBasedAuthorizationRequestHandler {
    try validateAttribute(AuthorizationRequestFieldConstants.clientId.rawValue, values: authorizationRequestParameters)
    let clientId = authorizationRequestParameters[AuthorizationRequestFieldConstants.clientId.rawValue] as? String ?? ""
    
    let clientIdPrefix = try extractClientIdPrefix(authorizationRequestParams: authorizationRequestParameters)
    let specVersion = findSpecVersion(clientId: clientId, clientIdPrefix: clientIdPrefix, authorizationRequestParameters: authorizationRequestParameters, trustedVerifiers: trustedVerifiers)
    
    switch clientIdPrefix {
    case ClientIdPrefix.preRegistered.rawValue:
        return PreRegisteredSchemeAuthorizationRequestHandler(clientId: clientId,
                                                              specVersion: specVersion,
                                                              trustedVerifiers: trustedVerifiers,
                                                              authorizationRequestParameters: authorizationRequestParameters,
                                                              walletMetadata: walletMetadata,
                                                              shouldValidateClient: shouldValidateClient,
                                                              setResponseUri: setResponseUri,
                                                              walletNonce: walletNonce,
                                                              networkManager: networkManager)
    case ClientIdScheme.did.rawValue, ClientIdPrefix.decentralizedIdentifier.rawValue:
        return DecentralizedIdentifierPrefixAuthorizationRequestHandler(clientId: clientId,
                                                    specVersion: specVersion,
                                                    authorizationRequestParameters: authorizationRequestParameters,
                                                    walletMetadata: walletMetadata,
                                                    setResponseUri: setResponseUri,
                                                    walletNonce: walletNonce,
                                                    networkManager: networkManager)
    case ClientIdPrefix.redirectUri.rawValue:
        return RedirectUriPrefixAuthorizationRequestHandler(clientId: clientId,
                                                            specVersion: specVersion,
                                                            authorizationRequestParameters: authorizationRequestParameters,
                                                            walletMetadata: walletMetadata,
                                                            setResponseUri: setResponseUri,
                                                            walletNonce: walletNonce,
                                                            networkManager: networkManager)
    default:
        throw InvalidData(message: "Given client_id_prefix is not supported" ,className: AuthorizationRequest.className)
    }
}

func extractQueryParameters(_ input: String) throws -> [String: String] {
    guard input.firstIndex(of: "?") != nil else {
        throw InvalidQueryParams( message: "Exception occurred when extracting the query params from Authorization Request :", className: AuthorizationRequest.className)
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
            throw InvalidInput(fieldPath: fieldPath, className: className)
        }
    case let dictValue as [String: Any]:
        guard !dictValue.isEmpty else {
            throw InvalidInput(fieldPath: fieldPath, className: className)
        }
        try dictValue.forEach { key, value in
            try validateField(value, fieldPath + [key], className)
        }
    case let arrayValue as [Any]:
        guard !arrayValue.isEmpty else {
            throw InvalidInput(fieldPath: fieldPath, className: className)
        }
        for (index, value) in arrayValue.enumerated() {
            try validateField(value, fieldPath + ["\(index)"], className)
        }
    default:
        break
    }
}

func extractClientIdPrefix(authorizationRequestParams: [String:Any]) throws -> String {      
    try validateAttribute(AuthorizationRequestFieldConstants.clientId.rawValue, values: authorizationRequestParams)
    let clientId = authorizationRequestParams[AuthorizationRequestFieldConstants.clientId.rawValue] as? String ?? ""
    
    let components = clientId.split(separator: ":", maxSplits: 1)
        
    if components.count > 1 {
         return String(components[0])
    } else {
        // Fallback client_id_prefix pre-registered; pre-registered clients MUST NOT contain a : character in their Client Identifier
        return ClientIdScheme.preRegistered.rawValue
    }
}

public func extractClientIdPartOnly(_ clientIdWithClientIdPrefixAttached: String) -> String {
    let components = clientIdWithClientIdPrefixAttached.split(separator: ":", maxSplits: 1)
    if components.count > 1 {
        let clientIdPrefix = String(components[0])
        // DID client_id_prefix will have the client id itself with did prefix, example - did:example:123#1. So there will not be additional prefix stating client_id_prefix for Spec version Draft 23
        if(clientIdPrefix == ClientIdScheme.did.rawValue){
            return clientIdWithClientIdPrefixAttached
        }
        return String(components[1])
    } else {
        // client_id_prefix is optional (Fallback client_id_prefix - pre-registered) i.e., a : character is not present in the Client Identifier
        return clientIdWithClientIdPrefixAttached
    }
}

func validateRequestObjectSigningAlgSupported(_ walletMetadata: WalletMetadata, className: String) throws {
    guard walletMetadata.requestObjectSigningAlgValuesSupported != nil else {
        throw InvalidData(
            message: "request_object_signing_alg_values_supported is not present in wallet metadata.",
            className: className
        )
    }
}

func validateResponseTypeSupported(_ responseType: String) throws {
    guard ResponseType(rawValue: responseType) != nil else {
        throw InvalidData(
            message: "response type - \(responseType) is not supported",
            className: AuthorizationRequest.className
        )
    }
}

internal func findSpecVersionUsingRequestParameters(_ authorizationRequestParameters: [String : Any]) -> SpecVersion {
    // In case of By value mode of Request - understand the spec version based on presence of `dcql_query`
    if authorizationRequestParameters[AuthorizationRequestFieldConstants.dcqlQuery.rawValue] != nil {
        return .v1
    }
    return .draft23
}

internal func findSpecVersion(clientId: String, clientIdPrefix: String, authorizationRequestParameters: [String: Any], trustedVerifiers: [Verifier]) -> SpecVersion {
    // In case of By reference mode of Request - get the client ID and understand the spec version
    if(authorizationRequestParameters[AuthorizationRequestFieldConstants.requestUri.rawValue] != nil) {
        if clientIdPrefix == ClientIdScheme.did.rawValue {
            return .draft23
        } else if clientIdPrefix == ClientIdPrefix.decentralizedIdentifier.rawValue {
            return .v1
        } else if clientIdPrefix == ClientIdPrefix.preRegistered.rawValue {
            let trustedVerifier = trustedVerifiers.first { $0.clientId == clientId }
            if let trustedVerifier = trustedVerifier {
                return trustedVerifier.specVersion
            }
            return .v1
        }
    }
    
    return findSpecVersionUsingRequestParameters(authorizationRequestParameters)
}
