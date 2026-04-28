import Foundation

func base64URLEncode(_ input: [String: Any]) throws -> String {
    guard let jsonData = try? JSONSerialization.data(withJSONObject: input, options: []) else {
        throw InvalidData(message: "Failed to serialize JSON", className: "Base64Encoder")
    }
    
    return jsonData.toBase64UrlEncoded()
}
