import Foundation
@testable import OpenID4VP

func createVerifiers(from verifierList: [[String: Any]]) -> [Verifier] {
    var verifiers: [Verifier] = []
    
    for verifierData in verifierList {
        if let clientId = verifierData["client_id"] as? String,
           let responseUris = verifierData["response_uris"] as? [String] {
            let verifier = Verifier(clientId: clientId, responseUris: responseUris)
            verifiers.append(verifier)
        }
    }
    
    return verifiers
}

func createEncodedAuthorizationRequest(
    requestParams: [String: Any],
    verifierSentAuthRequestByReference: Bool = false,
    clientIdScheme: ClientIdScheme,
    applicableFields: [String]? = nil
) -> String {
    
    let authorizationRequestParam = createAuthorizationRequest(requestParams: requestParams, verifierSentAuthRequestByReference: verifierSentAuthRequestByReference, clientIdScheme: clientIdScheme, applicableFields: applicableFields)
    
    let queryString = authorizationRequestParam.map { "\($0.key)=\($0.value)" }.joined(separator: "&")
    
    
    var finalQueryString = queryString
    if verifierSentAuthRequestByReference == true {
        finalQueryString += "&request_uri=https://mock-verifier.com/verifier/get-auth-request-obj"
    }
    
    let base64Encoded = Data(finalQueryString.utf8).base64EncodedString()
    
    return "OPENID4VP://authorize?\(base64Encoded)"
}

func createAuthorizationRequest(requestParams: [String: Any],
                                verifierSentAuthRequestByReference: Bool,
                                clientIdScheme: ClientIdScheme,
                                applicableFields: [String]?) -> [String:String]{
    var queryParams = requestParams
    
    func addAsJSONParam(_ paramName: String) {
        if let data = queryParams[paramName],
           let jsonData = try? JSONSerialization.data(withJSONObject: data, options: []),
           let jsonString = String(data: jsonData, encoding: .utf8) {
            queryParams[paramName] = jsonString
        }
        
    }
    // Convert presentation_definition & client_metadata to JSON string if provided
    addAsJSONParam("presentation_definition")
    addAsJSONParam("client_metadata")
    var authorizationRequestParam = [String: String]()
    
    
    let listOfApplicableFieldsOfClientIdScheme = (applicableFields==nil) ? authRequestClientIdSchemeMap[clientIdScheme]!: applicableFields
    for fieldName in listOfApplicableFieldsOfClientIdScheme! {
        if let value = queryParams[fieldName] {
            authorizationRequestParam[fieldName] = (value as! String)
        }
    }
    return authorizationRequestParam
}

func addingPercentEncoding(_ value: String) -> String {
    return value.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? value
}

func mergeMaps<K, V>(_ maps: [K: V]...) -> [K: V] {
    return maps.reduce(into: [:]) { result, map in
        result.merge(map) { (_, new) in new }
    }
}
