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
    jwtHeaderData: [String: Any]? = nil,
    applicableFields: [String]? = nil,
    addValidSignature: Bool = true
) -> String {
    
    let parametersList = applicableFields ?? authRequestClientIdSchemeMap[clientIdScheme]!
    let authorizaitonRequestParameters = createAuthorizationRequest(paramList: parametersList, requestParams: authorizationRequestParams)
    
    switch clientIdScheme {
    case .did:
        return JWTUtil.create(header: jwtHeaderData, payload: authorizaitonRequestParameters as [String : Any], addValidSignature: addValidSignature)
    default:
        return convertToJsonString(authorizaitonRequestParameters as [String : Any])
    }
}


func convertToJsonString(_ data: [String: Any]) -> String {
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

//Assert two dictionaries
func assertDictionariesEqual(expected: [String: Any], actual: [String: Any], file: StaticString = #file, line: UInt = #line) {
    
    func isEqual(_ lhs: Any, _ rhs: Any) -> Bool {
        switch (lhs, rhs) {
        case let (lhs as String, rhs as String): return lhs == rhs
        case let (lhs as Int, rhs as Int): return lhs == rhs
        case let (lhs as Double, rhs as Double): return lhs == rhs
        case let (lhs as Bool, rhs as Bool): return lhs == rhs
        case let (lhs as [String: Any], rhs as [String: Any]): return dictionariesEqual(lhs, rhs)
        case let (lhs as [Any], rhs as [Any]): return arraysEqual(lhs, rhs)
        case let (lhs as ClientMetadata, rhs as ClientMetadata): return lhs == rhs
        case let (lhs as PresentationDefinition, rhs as PresentationDefinition): return lhs == rhs
        default: return false
        }
    }

    func dictionariesEqual(_ lhs: [String: Any], _ rhs: [String: Any]) -> Bool {
        guard lhs.count == rhs.count else { return false }
        return lhs.allSatisfy { key, value in
            guard let rhsValue = rhs[key] else { return false }
            return isEqual(value, rhsValue)
        }
    }

    func arraysEqual(_ lhs: [Any], _ rhs: [Any]) -> Bool {
        guard lhs.count == rhs.count else { return false }
        return zip(lhs, rhs).allSatisfy { isEqual($0, $1) }
    }

    XCTAssertEqual(expected.count, actual.count, "Dictionary sizes are different", file: file, line: line)

    for (key, expectedValue) in expected {
        guard let actualValue = actual[key] else {
            XCTFail("Missing key '\(key)' in actual dictionary", file: file, line: line)
            continue
        }
        
        XCTAssertTrue(isEqual(expectedValue, actualValue), "Mismatch for key '\(key)'. Expected: \(expectedValue), but got: \(actualValue)", file: file, line: line)
    }
}

/// Function to compare two JSON strings after normalizing them
private func compareJsonStrings(_ jsonString1: String, _ jsonString2: String) -> Bool {
    guard let jsonData1 = jsonString1.data(using: .utf8),
          let jsonData2 = jsonString2.data(using: .utf8),
          let jsonObject1 = try? JSONSerialization.jsonObject(with: jsonData1, options: []),
          let jsonObject2 = try? JSONSerialization.jsonObject(with: jsonData2, options: [])
    else {
        return false
    }
    
    return NSDictionary(dictionary: jsonObject1 as! [String: Any])
        .isEqual(to: jsonObject2 as! [String: Any])
}

/// Check if a string is a valid JSON
private func isValidJson(_ string: String) -> Bool {
    guard let jsonData = string.data(using: .utf8) else { return false }
    return (try? JSONSerialization.jsonObject(with: jsonData, options: [])) != nil
}

func createInstance<T: Decodable>(_ json: [String: Any], as type: T.Type) -> T {
    let jsonData = try? JSONSerialization.data(withJSONObject: json, options: [])
    let decoder = JSONDecoder()
    return (try? decoder.decode(T.self, from: jsonData!))!
}

func createNetworkResponse(_ body: String, httpUrlResponse: HTTPURLResponse? = nil) -> (body: String, httpUrlResponse: HTTPURLResponse) {
    let url = URL(string: "https://mock-verifier.com/verifier/get-auth-request-obj")!
    let defaultHttpUrlResponse = HTTPURLResponse(url: url, statusCode: 200, httpVersion: "", headerFields: ["Content-Type": "application/json"])!
    let modifiedResponse: HTTPURLResponse = httpUrlResponse ?? defaultHttpUrlResponse
    
    return (body: body, httpUrlResponse: modifiedResponse)
}
