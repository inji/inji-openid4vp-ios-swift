import Foundation

struct JSON {
    // Create JSON encoder with custom settings - without escaping slashes
    static let encoder = JSONEncoder()
}

extension Encodable {
    func jsonData() throws -> Any {
        JSON.encoder.outputFormatting = [ .withoutEscapingSlashes]
        return try JSONSerialization.jsonObject(with: JSON.encoder.encode(self))
    }
}

func encode<T: Encodable>(_ data: T, fieldName: String, className: String) throws -> String {
    do {
        let encoder = JSON.encoder
        encoder.outputFormatting = .withoutEscapingSlashes
        let jsonData = try encoder.encode(data)
        return String(decoding: jsonData, as: UTF8.self)
    } catch {
        throw Logger.handleException(
            exceptionType: "JsonEncodingFailed",
            message: error.localizedDescription,
            fieldPath: [fieldName],
            className: className
        )
    }
}
