import Foundation

extension Encodable {
    func jsonData() throws -> Any {
        JSON.encoder.outputFormatting = [ .withoutEscapingSlashes]
        return try JSONSerialization.jsonObject(with: JSON.encoder.encode(self))
    }
}

struct JSON {
    static let encoder = JSONEncoder()
}
