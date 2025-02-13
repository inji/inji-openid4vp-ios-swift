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
    requestParams: [String: String],
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

func createAuthorizationRequest(requestParams: [String: String],
                                verifierSentAuthRequestByReference: Bool = false,
                                clientIdScheme: ClientIdScheme,
                                applicableFields: [String]?) -> [String:String]{
    var queryParams = requestParams
    
    var authorizationRequestParam = [String: String]()
    
    
    let listOfApplicableFieldsOfClientIdScheme = (applicableFields==nil) ? authRequestClientIdSchemeMap[clientIdScheme]!: applicableFields
    for fieldName in listOfApplicableFieldsOfClientIdScheme! {
        if (queryParams.contains{ $0.key == fieldName }){
            authorizationRequestParam[fieldName] = (queryParams[fieldName])
        }
    }
    return authorizationRequestParam
}

func createAuthorizationRequestObject(
    clientIdScheme: ClientIdScheme,
    authorizationRequestParams: [String: String],
    jwtHeaderData: [String: Any]? = nil,
    applicableFields: [String]? = nil,
    addValidSignature: Bool = true
) -> String {
    let requestObject = createAuthorizationRequest(requestParams: authorizationRequestParams,  clientIdScheme: .did, applicableFields: applicableFields)
    switch clientIdScheme {
    case .did:
        return JWTUtil.create(header: jwtHeaderData, payload: requestObject, addValidSignature: addValidSignature)
        
    default:
        return (try! JSONSerialization.data(withJSONObject: requestObject).base64EncodedString())
    }
}


func convertToJson(_ data: [String: Any]) -> String {
    let jsonData = try? JSONSerialization.data(withJSONObject: data, options: [])
    let jsonString = String(data: jsonData!, encoding: .utf8)
    return jsonString!
}

func addingPercentEncoding(_ value: String) -> String {
    return value.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? value
}

func mergeMaps<K, V>(_ maps: [K: V]...) -> [K: V] {
    return maps.reduce(into: [:]) { result, map in
        result.merge(map) { (_, new) in new }
    }
}
