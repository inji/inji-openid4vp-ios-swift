import Foundation

class Base64Encoder {
    
    static func encodeToBase64Url(_ input: Data) -> String {
        let base64String = input.base64EncodedString()
        let base64urlEncoded = base64String
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        
        return base64urlEncoded
    }
    
}
