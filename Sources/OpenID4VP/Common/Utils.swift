import Foundation

func makeBase64Standard(_ base64String: String) -> String {
    var base64 = base64String
        .replacingOccurrences(of: "-", with: "+")
        .replacingOccurrences(of: "_", with: "/")
    
    while base64.count % 4 != 0 {
        base64.append("=")
    }
    return base64
}

func extractDataJsonFromJwt(_ jwtToken: String, part: JwtPart) -> [String: Any]? {
    let parts = jwtToken.split(separator: ".")
    guard parts.indices.contains(part.rawValue),
          let data = Data(base64Encoded: makeBase64Standard(String(parts[part.rawValue]))),
          let json = try? JSONSerialization.jsonObject(with: data, options: []),
          let jsonDict = json as? [String: Any] else {
        return nil
    }
    return jsonDict
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

func extractPayloadJsonFromJwt(jwtToken: String) throws -> [String:String] {
        let components = jwtToken.split(separator: ".")
        let payload = String(components[1])
        let str = makeBase64Standard(payload)
        return try decodeBase64ToJSON(str)
}
