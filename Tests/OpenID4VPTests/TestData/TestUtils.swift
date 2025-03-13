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
func assertDictionariesEqual(expected: [String: Any], actual: [String: Any]?, file: StaticString = #file, line: UInt = #line, strict: Bool = true) {
    guard let actualDict = actual else {
        XCTFail("Actual is nil", file: file, line: line)
        return
    }
    
    func isEqual(_ lhs: Any?, _ rhs: Any?) -> Bool {
        switch (lhs, rhs) {
        case let (lhs as String, rhs as String): return lhs == rhs
        case let (lhs as Int, rhs as Int): return lhs == rhs
        case let (lhs as Double, rhs as Double): return lhs == rhs
        case let (lhs as Bool, rhs as Bool): return lhs == rhs
        case let (lhs as NSNull, rhs as NSNull):
            return lhs == rhs
        case let (lhs as [String: Any], rhs as [String: Any]): return dictionariesEqual(lhs, rhs)
        case let (lhs as [Any], rhs as [Any]): return arraysEqual(lhs, rhs)
        case let (lhs as any RawRepresentable, rhs as any RawRepresentable):
            return isEqual(lhs.rawValue, rhs.rawValue)
        case let (lhs as Encodable, rhs as Encodable):
            do {
                let encoder = JSONEncoder()
                let jsonData1 = try encoder.encode(lhs)
                let jsonData2 = try encoder.encode(rhs)
                
                let dict1 = try JSONSerialization.jsonObject(with: jsonData1, options: []) as? [String: Any]
                let dict2 = try JSONSerialization.jsonObject(with: jsonData2, options: []) as? [String: Any]
                
                XCTAssertNotNil(dict1, "Failed to convert instance1 to dictionary", file: file, line: line)
                XCTAssertNotNil(dict2, "Failed to convert instance2 to dictionary", file: file, line: line)
                
                assertDictionariesEqual(expected: dict1 ?? [:], actual: dict2, file: file, line: line)
                return true
            } catch {
                print("error - \(error) occurred during conversion")
                return false
            }
        default: return "\(String(describing: lhs))"  == "\(String(describing: rhs))"
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
    
    if strict {
        //TODO: add containsAll check to enhance assertion
        XCTAssertEqual(expected.count, actualDict.count, "Dictionary sizes are different", file: file, line: line)
    }
    
    for (key, expectedValue) in expected {
        guard let actualValue = actualDict[key] else {
            XCTFail("Missing key '\(key)' in actual dictionary", file: file, line: line)
            continue
        }
        
        XCTAssertTrue(isEqual(expectedValue, actualValue), "Mismatch for key '\(key)'. Expected: \(expectedValue), but got: \(actualValue)", file: file, line: line)
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
    let defaultHttpUrlResponse = HTTPURLResponse(url: url, statusCode: 200, httpVersion: "", headerFields: ["Content-Type": "application/json"])!
    let modifiedResponse: HTTPURLResponse = httpUrlResponse ?? defaultHttpUrlResponse
    
    return (body: body, httpUrlResponse: modifiedResponse)
}

public func getMockAuthorizationRequest(responseMode: ResponseMode = .directPost) -> AuthorizationRequest {
    return AuthorizationRequest(
        clientId: "client_id",
        clientIdScheme: "123",
        presentationDefinition: mockPresentationDefinitionObject,
        responseType: "vp_token",
        responseMode: responseMode.rawValue,
        nonce: "nonce",
        state: "state",
        redirectUri: "1234",
        responseUri: "https://mock-verifier.com",
        clientMetadata: mockClientMetadataObject
    )
}

func compareJsonStrings(_ jsonString1: String, _ jsonString2: String, strict: Bool = true, file: StaticString = #file, line: UInt = #line) {
    do {
        guard let data1 = jsonString1.data(using: .utf8),
              let data2 = jsonString2.data(using: .utf8) else {
            XCTFail("Invalid JSON string encoding", file: file, line: line)
            return
        }
        
        let json1 = try JSONSerialization.jsonObject(with: data1, options: []) as? [String: Any]
        let json2 = try JSONSerialization.jsonObject(with: data2, options: []) as? [String: Any]

        XCTAssertNotNil(json1, "Failed to parse first JSON string", file: file, line: line)
        XCTAssertNotNil(json2, "Failed to parse second JSON string", file: file, line: line)

        if let json1 = json1, let json2 = json2 {
            assertDictionariesEqual(expected: json1, actual: json2, file: file, line: line, strict: strict)
        }
    } catch {
        XCTFail("JSON deserialization failed with error: \(error)", file: file, line: line)
    }
}
