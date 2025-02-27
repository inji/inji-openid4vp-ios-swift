import Foundation

class Base64Decoder {
    static let className = String(describing: Base64Decoder.self)
    
    static func decodeBase64ToJSON(_ base64String: String) throws -> [String: Any] {
        let standardBase64String = makeBase64Standard(base64String)
        guard let decodedData = Data(base64Encoded: standardBase64String) else {
            throw Logger.handleException(exceptionType: "Decoding", message: "JWT payload decoding failed" ,className: Base64Decoder.className)
        }
        do{
            guard let jsonObject = try JSONSerialization.jsonObject(with: decodedData, options: []) as? [String: Any]  else {
                throw Logger.handleException(
                    exceptionType: "InvalidData",
                    message: "Decoding failed",
                    className: Base64Decoder.className
                )
            }
            return jsonObject
        } catch {
            throw Logger.handleException(exceptionType: "JsonDecodingFailed", message: "JWT Decoding to json failed", className: Base64Decoder.className)
        }
    }
    
    static func makeBase64Standard(_ base64String: String) -> String {
        var validBase64String = base64String
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        
        while validBase64String.count % 4 != 0 {
            validBase64String.append("=")
        }
        return validBase64String
    }
}
