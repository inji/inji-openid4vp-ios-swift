import Foundation

extension Data {
    init?(base64UrlEncoded: String) {
            var base64 = base64UrlEncoded
                .replacingOccurrences(of: "-", with: "+")
                .replacingOccurrences(of: "_", with: "/")

            let paddingLength = 4 - (base64.count % 4)
            if paddingLength < 4 {
                base64 += String(repeating: "=", count: paddingLength)
            }

            guard let decoded = Data(base64Encoded: base64) else {
                return nil
            }

            self = decoded
        }
    
    func toBase64UrlEncoded() -> String {
        return base64URLEscaped(self.base64EncodedString())
    }
}
