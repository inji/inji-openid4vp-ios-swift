import Foundation

extension Dictionary where Key == String, Value == String {
    func values(forKeys keys: [String]) -> [String]? {
        let values = keys.compactMap { self[$0] }
        return values.count == keys.count ? values : nil
    }
}

public struct AuthorizationRequest: Encodable {
    let clientId: String
    var presentationDefinition: Any
    let responseType: String
    let responseMode: String
    let nonce: String
    let state: String
    let responseUri: String
    var clientMetadata: Any?
    
    enum CodingKeys: String, CodingKey {
        case client_id
        case presentation_definition
        case response_type
        case response_mode
        case nonce
        case state
        case response_uri
        case client_metadata
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(clientId, forKey: .client_id)
        if let presentationDefString = presentationDefinition as? String {
            try container.encode(presentationDefString, forKey: .presentation_definition)
        } else if let presentationDefObject = presentationDefinition as? PresentationDefinition {
            try container.encode(presentationDefObject, forKey: .presentation_definition)
        }
        try container.encode(responseType, forKey: .response_type)
        try container.encode(responseMode, forKey: .response_mode)
        try container.encode(nonce, forKey: .nonce)
        try container.encode(state, forKey: .state)
        try container.encode(responseUri, forKey: .response_uri)
        if let clientMetadataString = clientMetadata as? String {
            try container.encode(clientMetadataString, forKey: .client_metadata)
        } else if let clientMetadataObject = clientMetadata as? ClientMetadata {
            try container.encode(clientMetadataObject, forKey: .client_metadata)
        }
    }
    
    static func validateAndGetAuthorizationRequest(encodedAuthorizationRequest: String, setResponseUri: (String) -> Void) throws -> AuthorizationRequest {
        
        Logger.getLogTag(className: String(describing: self))
        
        let requestParts = encodedAuthorizationRequest.components(separatedBy: "?")
           guard requestParts.count > 1 else {
               Logger.error("Invalid AuthorizationRequest format. No query string found.")
               throw AuthorizationRequestException.decodingException
           }
           
        let baseUrl = requestParts[0]
        let encodedQuery = requestParts[1]
        
        guard let decodedQuery = decodeAuthorizationRequest(encodedQuery) else {
            Logger.error("Decoding of the AuthorizationRequest failed.")
            throw AuthorizationRequestException.decodingException
        }
        
        let decodedRequest = "\(baseUrl)?\(decodedQuery)"
        
        return try parseAuthorizationRequest(decodedAuthorizationRequest: decodedRequest, setResponseUri: setResponseUri)
        
    }
    
    private static func parseAuthorizationRequest(decodedAuthorizationRequest: String, setResponseUri: (String) -> Void) throws -> AuthorizationRequest {
        
        guard let encodedRequestUrl = urlEncodedRequest(decodedAuthorizationRequest) else {
            Logger.error("URLEncoding of the AuthorizationRequest failed while parsing.")
            throw AuthorizationRequestException.urlCreationFailed
        }
        
        guard let queryItems = getQueryItems(encodedRequestUrl) else {
            Logger.error("Query items retrieval from AuthorizationRequest failed.")
            throw AuthorizationRequestException.queryItemsRetrievalFailed
        }
        
        let params = try extractQueryParams(from: queryItems)
        
        try validateQueryParams(params,setResponseUri)
        
        return AuthorizationRequest(
            clientId: params["client_id"]!,
            presentationDefinition: params["presentation_definition"]!,
            responseType: params["response_type"]!,
            responseMode: params["response_mode"]!,
            nonce: params["nonce"]!,
            state: params["state"]!,
            responseUri: params["response_uri"]!,
            clientMetadata: params["client_metadata"]
        )
    }
    
    private static func extractQueryParams(from queryItems: [URLQueryItem]) throws -> [String: String] {
        var extractedValues: [String: String] = [:]
        
        for queryItem in queryItems {
            guard let value = queryItem.value, !value.isEmpty else {
                Logger.error("Query parameter value should not be empty: \(queryItem)")
                throw AuthorizationRequestException.parameterValuesAreEmpty
            }
            extractedValues[queryItem.name] = value
        }
        
        return extractedValues
    }
    
    
    private static func validateQueryParams(_ values: [String: String], _ setResponseUri: (String) -> Void) throws {
        
        //Keep response_uri as first param in this list because if any other required param is not present then we need this response_uri to send error to the verifier
        var requiredKeys = [
            "response_uri",
            "presentation_definition",
            "client_id",
            "response_type",
            "response_mode",
            "nonce",
            "state",
        ]
        
        for key in requiredKeys {
            if values[key] == nil  {
                Logger.error("AuthorizationRequest parameter \(key) should not be null.")
                throw AuthorizationRequestException.missingInput(fieldName: key)
            }
            if key == "response_uri" {
                setResponseUri(values["response_uri"]!)
            }
            if values[key] == "" || values[key] == "null" {
                Logger.error("AuthorizationRequest parameter \(key) should not be null.")
                throw AuthorizationRequestException.invalidInput(fieldName: key)
            }
        }
        
        if values["client_metadata"] != nil {
            requiredKeys.append("client_metadata")
        }
    }
}
