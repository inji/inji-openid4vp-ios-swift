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
    let queryString = encodeToQueryParameters(authorizationRequestParam)
    
    return "OPENID4VP://authorize?\(queryString)"
}

private func encodeToQueryParameters(_ parameters: [String: String?]) -> String {
    let queryString = parameters.compactMap { (key, value) -> String? in
        guard let value = value else { return nil } // Ignore nil values
        let encodedKey = key.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? ""
        let encodedValue = value.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? ""
        return "\(encodedKey)=\(encodedValue)"
    }.joined(separator: "&")
    
    return queryString
}

func createAuthorizationRequest(
    paramList: [String],
    requestParams: [String: String?]
) -> [String: String?] {
    var authorizationRequestParam: [String: String?] = [:]
    for param in paramList {
        if let value = requestParams[param], value != nil {
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

// Assert two dictionary values with values of JSON string or usual data types
func assertDictionaryValues(actual: [String: Any], expected: [String: Any?]) {
    for (key, expectedValue) in expected {
        guard let actualValue = actual[key] else {
            XCTFail("Missing key: \(key)")
            continue
        }
        
        if let expectedValue = expectedValue {
            if isValidJson(expectedValue as! String), let actualString = actualValue as? String, isValidJson(actualString) {
                XCTAssertTrue(compareJsonStrings(expectedValue as! String, actualString), "Mismatch in JSON for key: \(key)")
            } else {
                XCTAssertEqual(actualValue as? String, expectedValue as! String, "Mismatch for key: \(key)")
            }
        } else {
            XCTAssertNil(actualValue as? String, "Expected nil for key: \(key), but got \(actualValue)")
        }
    }
    
    // Ensure there are no extra keys in actual
    let extraKeys = Set(actual.keys).subtracting(expected.keys)
    XCTAssertTrue(extraKeys.isEmpty, "Unexpected extra keys in actual: \(extraKeys)")
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
