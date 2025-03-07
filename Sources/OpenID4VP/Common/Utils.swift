import Foundation

enum JwtPart: Int {
    case header = 0, payload, signature
}

func isJWT(_ input: String) -> Bool {
    return input.split(separator: ".").count == 3
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

func base64URLEscaped(_ base64String: String) -> String {
    return base64String
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
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

extension Encodable {
    func toDictionary() -> [String: Any]? {
        guard let data = try? JSONEncoder().encode(self),
              let json = try? JSONSerialization.jsonObject(with: data, options: []) as? [String: Any] else {
            return nil
        }
        return json
    }
}

func encode<T: Encodable>(_ data: T, fieldName: String) throws -> String {
    do {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .withoutEscapingSlashes
        let jsonData = try encoder.encode(data)
        return String(decoding: jsonData, as: UTF8.self)
    } catch {
        throw Logger.handleException(
            exceptionType: "JsonEncodingFailed",
            message: error.localizedDescription,
            fieldPath: [fieldName],
            className: AuthorizationResponse.className
        )
    }
}

func encodeQueryValue(_ value: String) -> String {
    var allowedCharacterSet = CharacterSet.urlQueryAllowed
    allowedCharacterSet.remove("+")

    if let decodedValue = value.removingPercentEncoding, decodedValue != value {
        return value
    }
    return value.addingPercentEncoding(withAllowedCharacters: allowedCharacterSet) ?? value
}

func validateField(_ field: String?, _ fieldPath: [String]) throws {
    if let field = field {
        guard isNeitherNullNorEmpty(field: field) else {
            throw Logger.handleException(exceptionType: "InvalidInput", fieldPath: fieldPath, className: Fields.className)
        }
    }
}
