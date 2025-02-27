import Foundation
import CryptoKit

func parseAndValidatePresentationDefinition(
    authorizationRequest: [String: Any],
    networkManager: NetworkManaging
) async throws -> [String: Any] {
    
    let hasPresentationDefinition = authorizationRequest.keys.contains("presentation_definition")
    let hasPresentationDefinitionUri = authorizationRequest.keys.contains("presentation_definition_uri")
    var finalPresentationDefinition: PresentationDefinition
    
    guard hasPresentationDefinition != hasPresentationDefinitionUri else {
        throw Logger.handleException(
            exceptionType: "InvalidQueryParams",
            message: "Either presentation_definition or presentation_definition_uri request param can be provided but not both",
            className: AuthorizationRequest.className
        )
    }
    
    
    if hasPresentationDefinition, let value = authorizationRequest["presentation_definition"] {
        if let presentationDefinitionString = value as? String {
            //Presentation Definition is of type String when auth request obtained by value
            guard let valueStr = getStringValue(presentationDefinitionString), isNeitherNullNorEmpty(field: valueStr), valueStr != "null" else {
                throw Logger.handleException(
                    exceptionType: "InvalidInput",
                    fieldPath: ["presentation_definition"],
                    className: AuthorizationRequest.className
                )
            }

            finalPresentationDefinition = try convertToInstance(valueStr, as: PresentationDefinition.self, fieldPath: [AuthorizationRequestFieldConstants.presentationDefinition.rawValue], className: PresentationDefinition.className)
        } else if let presentationDefinitionJson = value as? [String: Any] {
            //Presentation Definition is of type Dictionary when auth request obtained by reference
            do {
                finalPresentationDefinition = try convertToInstance(presentationDefinitionJson, as: PresentationDefinition.self)
            } catch {
                throw Logger.handleException(
                    exceptionType: "InvalidData",
                    message: "presentation_defintion data is not valid",
                    className: AuthorizationRequest.className
                )
            }
        } else {
            throw Logger.handleException(
                exceptionType: "InvalidData",
                message: "presentation_defintion data is not valid",
                className: AuthorizationRequest.className
            )
        }
    } else if hasPresentationDefinitionUri, let presentationDefintionUri = authorizationRequest[AuthorizationRequestFieldConstants.presentationDefinitionUri.rawValue] {
        guard let valueStr = getStringValue(presentationDefintionUri), isNeitherNullNorEmpty(field: valueStr), valueStr != "null" else {
            throw Logger.handleException(
                exceptionType: "InvalidInput",
                fieldPath: [AuthorizationRequestFieldConstants.presentationDefinitionUri.rawValue],
                className: AuthorizationRequest.className
            )
        }
        guard isValidUri(presentationDefintionUri as! String)
        else {
            throw Logger.handleException(
                exceptionType: "InvalidData",
                message: "presentation_defintion_uri data is not valid",
                className: AuthorizationRequest.className
            )
        }
        
        guard let url = URL(string: valueStr) else {
            throw Logger.handleException(
                exceptionType: "UrlCreationFailed",
                fieldPath: ["presentation_definition_uri"],
                className: AuthorizationRequest.className
            )
        }
        
        let response = try await networkManager.sendHTTPRequest(
            url: url, method: .GET, bodyParams: nil, headers: nil
        )
        guard let data = response.responseBody.data(using: .utf8) else {
            throw Logger.handleException(
                exceptionType: "InvalidData",
                message: "presentation_defintion_uri data is not valid",
                className: AuthorizationRequest.className
            )
        }
        
        finalPresentationDefinition = try data.toInstance(as: PresentationDefinition.self)
        
    } else {
        throw Logger.handleException(
            exceptionType: "InvalidQueryParams",
            message: "Either presentation_definition or presentation_definition_uri request param must be present",
            className: AuthorizationRequest.className
        )
    }
    
    var mutableParams = authorizationRequest
    mutableParams[AuthorizationRequestFieldConstants.presentationDefinition.rawValue] = finalPresentationDefinition
    
    return mutableParams
}

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
    return mutableParams
}

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
    
    guard params["client_id_scheme"] == requestUriParams["client_id_scheme"] as? String else {
        throw Logger.handleException(exceptionType: "MismatchingClientIdSchemeInRequest", className: AuthorizationRequest.className)
    }
}

func urlEncodedRequest(_ decodedRequest: String) -> String? {
    return decodedRequest.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)
}

func getQueryItems(_ encodedUrl: URL) -> [URLQueryItem]? {
    return URLComponents(url: encodedUrl, resolvingAgainstBaseURL: false)?.queryItems
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
                    className: InputDescriptor.className
                )
            }
            return rawValue!
        }
        return nil
    }
}


func getAuthorizationRequestHandler(trustedVerifiers : [Verifier], authorizationRequestParameters: [String:Any], shouldValidateClient: Bool, networkManager: NetworkManaging,setResponseUri: @escaping (String) -> Void) throws -> ClientIdSchemeBasedAuthorizationRequestHandler {
    let clientIdScheme = getStringValue(authorizationRequestParameters[AuthorizationRequestFieldConstants.clientIdScheme.rawValue]) ?? ClientIdScheme.preRegistered.rawValue
    
    switch clientIdScheme {
    case ClientIdScheme.preRegistered.rawValue:
        return PreRegisteredSchemeAuthorizationRequestHandler(trustedVerifiers: trustedVerifiers, authorizationRequestParameters: authorizationRequestParameters, networkManager: networkManager, shouldValidateClient: shouldValidateClient, setResponseUri: setResponseUri)
    case ClientIdScheme.did.rawValue:
        return DidSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters, networkManager: networkManager, setResponseUri: setResponseUri)
    case ClientIdScheme.redirectUri.rawValue:
        return RedirectUriSchemeAuthorizationRequestHandler(authorizationRequestParameters: authorizationRequestParameters, networkManager: networkManager, setResponseUri: setResponseUri)
    default:
        throw Logger.handleException(exceptionType: "InvalidClientIdScheme",message: "Client id scheme in request is not supported" ,className: AuthorizationRequest.className)
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
