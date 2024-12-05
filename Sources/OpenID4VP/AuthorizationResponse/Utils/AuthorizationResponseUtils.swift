import Foundation

func encodeToJsonString<T: Encodable>(_ value: T) throws -> String? {
    let encoder = JSONEncoder()
    encoder.outputFormatting = .withoutEscapingSlashes
    let jsonData = try encoder.encode(value)
    let jsonresponse: String? = String(data: jsonData, encoding: .utf8)
    print(jsonresponse ?? "")
    return jsonresponse
}
