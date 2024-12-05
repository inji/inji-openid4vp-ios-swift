import Foundation


func encodeQueryValue(_ value: String) -> String {
    var allowedCharacterSet = CharacterSet.urlQueryAllowed
    allowedCharacterSet.remove("+")
    return value.addingPercentEncoding(withAllowedCharacters: allowedCharacterSet) ?? value
}

func encodeToJsonString<T: Encodable>(_ value: T) throws -> String? {
    let encoder = JSONEncoder()
    encoder.outputFormatting = .withoutEscapingSlashes
    let jsonData = try encoder.encode(value)
    let jsonresponse: String? = String(data: jsonData, encoding: .utf8)
    return jsonresponse
}
