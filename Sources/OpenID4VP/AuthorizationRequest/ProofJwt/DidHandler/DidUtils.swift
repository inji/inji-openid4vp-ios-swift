import Foundation

func extractKid(from jwtToken: String) -> String? {
    let parts = jwtToken.split(separator: ".")
    guard parts.count > 1,
          let headerData = Data(base64Encoded: makeBase64Standard(String(parts[0]))),
          let headerJson = try? JSONSerialization.jsonObject(with: headerData, options: []),
          let headerDict = headerJson as? [String: Any],
          let kid = headerDict["kid"] as? String else {
        return nil
    }
    return kid
}

func extractPublicKeyMultibase(for kid: String, from json: String) throws -> String? {
    
    guard let data = json.data(using: .utf8) else {
        throw Logger.handleException(exceptionType: "UTF8Encoding", className: DidHandler.className)
    }
    
    do {
        if let json = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any],
           let didDocument = json["didDocument"] as? [String: Any],
           let verificationMethod = didDocument["verificationMethod"] as? [[String: Any]] {
            
            for method in verificationMethod {
                if let id = method["id"] as? String, id.hasSuffix(kid),
                   let publicKeyMultibase = method["publicKeyMultibase"] as? String {
                    return publicKeyMultibase
                }
            }
        } else {
            throw Logger.handleException(exceptionType: "PublicKeyNotFound", className: DidHandler.className)
        }
    } catch {
        throw Logger.handleException(exceptionType: "PublicKeyExtractionFailed", className: DidHandler.className)
    }
    return nil
}

func extractPayloadJsonFromJwt(jwtToken: String) throws -> [String:String] {
        let components = jwtToken.split(separator: ".")
        let payload = String(components[1])
        let str = makeBase64Standard(payload)
        return try decodeBase64ToJSON(str)
}

func makeBase64Standard(_ base64String: String) -> String {
    var base64 = base64String
        .replacingOccurrences(of: "-", with: "+")
        .replacingOccurrences(of: "_", with: "/")
    
    while base64.count % 4 != 0 {
        base64.append("=")
    }
    return base64
}

func decodeBase64ToJSON(_ base64String: String) throws -> [String: String] {
    guard let decodedData = Data(base64Encoded: base64String) else {
        throw Logger.handleException(exceptionType: "Decoding", message: "JWT payload decoding failed" ,className: DidHandler.className)
    }
    
    do {
        if let jsonObject = try JSONSerialization.jsonObject(with: decodedData, options: []) as? [String: Any] {
            let stringifiedDict = jsonObject.reduce(into: [String: String]()) { dict, pair in
                let (key, value) = pair
                dict[key] = "\(value)"
            }
            return stringifiedDict
        } else {
            throw Logger.handleException(exceptionType: "JsonDecodingFailed", message: "JWT payload decoding to json failed", className: DidHandler.className)
        }
    }
}
