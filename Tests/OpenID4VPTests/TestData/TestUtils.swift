import Foundation
@testable import OpenID4VP
import XCTest

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

func createUrlEncodedAuthorizationRequest(
    requestParams: [String: Any?],
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
    let queryString = encodeToQueryParameters(authorizationRequestParam)
    
    return "OPENID4VP://authorize?\(queryString)"
}

private func encodeToQueryParameters(_ parameters: [String: Any?]) -> String {
    let queryString = parameters.compactMap { (key, value) -> String? in
        guard let encodedKey = key.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) else { return nil }
        
        let encodedValue: String
        if let stringValue = value as? String {
            encodedValue = stringValue
        } else if let jsonData = try? JSONSerialization.data(withJSONObject: value as Any, options: []),
                  //       stringify client_metdata and presentation defintiion
                  let jsonString = String(data: jsonData, encoding: .utf8) {
            encodedValue = jsonString
        } else {
            return nil // Skip values that can't be converted
        }
        
        guard let finalEncodedValue = encodedValue.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) else { return nil }
        return "\(encodedKey)=\(finalEncodedValue)"
    }.joined(separator: "&")
    
    return queryString
}

func createAuthorizationRequest(
    paramList: [String],
    requestParams: [String: Any?]
) -> [String: Any?] {
    var authorizationRequestParam: [String: Any?] = [:]
    for param in paramList {
        if let value = requestParams[param], value != nil {
            authorizationRequestParam[param] = value
        }
    }
    return authorizationRequestParam
}

func createAuthorizationRequestObject(
    clientIdScheme: ClientIdScheme,
    authorizationRequestParams: [String: Any],
    jwsHeaderData: [String: Any]? = nil,
    applicableFields: [String]? = nil,
    addValidSignature: Bool = true
) -> String {
    
    let parametersList = applicableFields ?? authRequestClientIdSchemeMap[clientIdScheme]!
    let authorizaitonRequestParameters = createAuthorizationRequest(paramList: parametersList, requestParams: authorizationRequestParams)
    
    switch clientIdScheme {
    case .did:
        return JWSUtil.create(header: jwsHeaderData, payload: authorizaitonRequestParameters as [String : Any], addValidSignature: addValidSignature)
    default:
        return convertToJsonString(authorizaitonRequestParameters as [String : Any])
    }
}


func convertToJsonString(_ data: [String: Any]) -> String {
    let jsonData = try? JSONSerialization.data(withJSONObject: data, options: [])
    let jsonString = String(data: jsonData!, encoding: .utf8)
    return jsonString!
}

func convertToDictionary<T: Encodable>(object: T) -> [String: Any]? {
    guard let data = try? JSONEncoder().encode(object) else {
        return nil
    }
    return try? JSONSerialization.jsonObject(with: data, options: []) as? [String: Any]
}

func addingPercentEncoding(_ value: String) -> String {
    return value.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? value
}

func mergeMaps<K, V>(_ maps: [K: V]...) -> [K: V] {
    return maps.reduce(into: [:]) { result, map in
        result.merge(map) { (_, new) in new }
    }
}


// Assert equality of errors
public func == (lhs: Error, rhs: Error) -> Bool {
    guard type(of: lhs) == type(of: rhs) else { return false }
    let error1 = lhs as NSError
    let error2 = rhs as NSError
    return error1.domain == error2.domain && error1.code == error2.code && "\(lhs)" == "\(rhs)"
}

extension Equatable where Self : Error {
    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs as Error == rhs as Error
    }
}

func decodeQueryValue(_ value: String) -> String {
    return value.removingPercentEncoding ?? value
}

func createInstance<T: Decodable>(_ json: [String: Any], as type: T.Type) -> T {
    let jsonData = try? JSONSerialization.data(withJSONObject: json, options: [])
    let decoder = JSONDecoder()
    return (try? decoder.decode(T.self, from: jsonData!))!
}

func createNetworkResponse(_ body: String, httpUrlResponse: HTTPURLResponse? = nil) -> (body: String, httpUrlResponse: HTTPURLResponse) {
    let url = URL(string: "https://mock-verifier.com/verifier/get-auth-request-obj")!
    let defaultHttpUrlResponse = HTTPURLResponse(url: url, statusCode: 200, httpVersion: "", headerFields: [Header.contentType.rawValue: "application/json"])!
    let modifiedResponse: HTTPURLResponse = httpUrlResponse ?? defaultHttpUrlResponse
    
    return (body: body, httpUrlResponse: modifiedResponse)
}

public func getMockAuthorizationRequest(responseMode: ResponseMode = .directPost, responseType: String? = nil) -> AuthorizationRequest {
    let responseType = responseType ?? ResponseType.vp_token.rawValue
    return AuthorizationRequest(
        clientId: "client_id",
        presentationDefinition: mockPresentationDefinitionObject,
        responseType: responseType,
        responseMode: ResponseMode.directPost.rawValue,
        nonce: "nonce",
        state: "state",
        redirectUri: "1234",
        responseUri: "https://mock-verifier.com",
        clientMetadata: mockClientMetadataObject
    )
}

func createWalletMetadata(
    presentationDefinitionURISupported: Bool = true,
    vpFormatsSupported: [String: VPFormatSupported] = ["ldp_vc": VPFormatSupported(algValuesSupported: ["ES256", "EdDSA"])],
    clientIdSchemesSupported: [String] = ["pre-registered"],
    requestObjectSigningAlgValuesSupported: [String]? = nil,
    authorizationEncryptionAlgValuesSupported: [String]? = nil,
    authorizationEncryptionEncValuesSupported: [String]? = nil
) -> WalletMetadata {
    return WalletMetadata(
        presentationDefinitionURISupported: presentationDefinitionURISupported,
        vpFormatsSupported: vpFormatsSupported,
        clientIdSchemesSupported: clientIdSchemesSupported,
        requestObjectSigningAlgValuesSupported: requestObjectSigningAlgValuesSupported,
        authorizationEncryptionAlgValuesSupported: authorizationEncryptionAlgValuesSupported,
        authorizationEncryptionEncValuesSupported: authorizationEncryptionEncValuesSupported
    )
}
