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
    requestParams: [String: String?],
    verifierSentAuthRequestByReference: Bool? = false,
    clientIdScheme: ClientIdScheme,
    applicableFields: [String]? = nil
) -> String {
    let paramList: [String]
    if verifierSentAuthRequestByReference == true {
        paramList = authRequestParamsByReference
    } else {
        paramList = applicableFields ?? authRequestClientIdSchemeMap[clientIdScheme]!
    }
    
    let authorizationRequestParam = createAuthorizationRequest(paramList: paramList, requestParams: requestParams)
    let queryString = authorizationRequestParam.map { "\($0.key)=\($0.value ?? "")" }.joined(separator: "&")
    let encodedData = queryString.data(using: .utf8)!
    let base64String = encodedData.base64EncodedString()
    
    return "OPENID4VP://authorize?\(base64String)"
}

func createAuthorizationRequest(
    paramList: [String],
    requestParams: [String: String?]
) -> [String: String?] {
    var authorizationRequestParam: [String: String?] = [:]
    for param in paramList {
        if let value = requestParams[param] {
            authorizationRequestParam[param] = value
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
    
    let paramList = applicableFields ?? authRequestClientIdSchemeMap[clientIdScheme]!
    let authRequestParam = createAuthorizationRequest(paramList: paramList, requestParams: authorizationRequestParams)
    
    switch clientIdScheme {
    case .did:
        return JWTUtil.create(header: jwtHeaderData, payload: authRequestParam, addValidSignature: addValidSignature)
    default:
        return (try! JSONSerialization.data(withJSONObject: authRequestParam).base64EncodedString())
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
