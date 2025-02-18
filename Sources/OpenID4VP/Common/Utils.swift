import Foundation

enum JwtPart: Int {
    case header = 0, payload, signature
}

func isJWT(_ authorizationRequest: String) -> Bool {
    return authorizationRequest.split(separator: ".").count == 3
}

func determineHttpMethod(method: String) throws -> HTTP_METHOD {
    if method.contains("get") {
        return HTTP_METHOD.GET
    } else if method.contains("post") {
        return HTTP_METHOD.POST
    } else {
        throw Logger.handleException(exceptionType: "UnsupportedHttpMethod", message: method, className: AuthorizationRequest.className)
    }
}

func extractDataJsonFromJwt(jwtToken: String, jwtPart: JwtPart) throws -> [String:String] {
    let components = jwtToken.split(separator: ".")
    let payload = String(components[jwtPart.rawValue])
    return try decodeBase64ToJSON(makeBase64Standard(payload))
}

func makeBase64Standard(_ base64String: String) -> String {
    var validBase64String = base64String
        .replacingOccurrences(of: "-", with: "+")
        .replacingOccurrences(of: "_", with: "/")
    
    while validBase64String.count % 4 != 0 {
        validBase64String.append("=")
    }
    return validBase64String
}

func decodeBase64ToString(_ encodedAuthorizationRequest: String) -> String? {
    return Data(base64Encoded: encodedAuthorizationRequest)
        .flatMap { String(data: $0, encoding: .utf8) }
}

func decodeBase64ToJSON(_ base64String: String) throws -> [String: String] {
    guard let decodedData = Data(base64Encoded: base64String) else {
        throw Logger.handleException(exceptionType: "Decoding", message: "JWT payload decoding failed" ,className: JWTHandler.className)
    }
    
    do {
        if let jsonObject = try JSONSerialization.jsonObject(with: decodedData, options: []) as? [String: Any] {
            let stringifiedDict = jsonObject.reduce(into: [String: String]()) { dict, pair in
                let (key, value) = pair
                dict[key] = "\(value)"
            }
            return stringifiedDict
        } else {
            throw Logger.handleException(exceptionType: "JsonDecodingFailed", message: "JWT payload decoding to json failed", className: JWTHandler.className)
        }
    }
}

func getStringValue(_ value: Any?) -> String? {
    return value as? String
}

public func isValidUri(_ urlString: String) -> Bool {
    let urlRegex = #"^https:\/\/(?:[\w-]+\.)+[\w-]+(?:\/[\w\-.~!$&'()*+,;=:@%]+)*\/?(?:\?[^#\s]*)?(?:#.*)?$"#
    
    return urlString.range(of: urlRegex, options: .regularExpression) != nil
}
