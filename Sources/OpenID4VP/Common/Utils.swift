import Foundation

enum JwtPart: Int {
    case header = 0, payload, signature
}

func isJWT(_ input: String) -> Bool {
    return input.split(separator: ".").count == 3
}


func determineHttpMethod(method: String) throws -> HTTP_METHOD {
    let methodValue = method.lowercased()
    if methodValue == "get" {
        return HTTP_METHOD.GET
    } else if methodValue == "post" {
        return HTTP_METHOD.POST
    } else {
        throw Logger.handleException(exceptionType: "UnsupportedHttpMethod", message: method, className: AuthorizationRequest.className)
    }
}

func extractDataJsonFromJwt(jwtToken: String, jwtPart: JwtPart) throws -> [String:Any] {
    let components = jwtToken.split(separator: ".")
    let payload = String(components[jwtPart.rawValue])
    return try Base64Decoder.decodeBase64ToJSON(payload)
}

func getStringValue(_ value: Any?) -> String? {
    return value as? String
}

public func isValidUri(_ urlString: String) -> Bool {
    let urlRegex = #"^https:\/\/(?:[\w-]+\.)+[\w-]+(?:\/[\w\-.~!$&'()*+,;=:@%]+)*\/?(?:\?[^#\s]*)?(?:#.*)?$"#
    
    return urlString.range(of: urlRegex, options: .regularExpression) != nil
}

func convertToInstance<T: Decodable>(_ dictionary: [String: Any], as type: T.Type) throws -> T {
    let data = try JSONSerialization.data(withJSONObject: dictionary, options: [])
    return try JSONDecoder().decode(T.self, from: data)
}

func convertToInstance<T: Decodable>(_ input: String, as type: T.Type, fieldPath: [String] = [], className: String = "Utils") throws -> T {
    guard let jsonData = input.data(using: .utf8) else {
        throw Logger.handleException(exceptionType: "UTF8Encoding", fieldPath: fieldPath, className: className)
    }
    
    return try jsonData.toInstance(as: T.self)
}
