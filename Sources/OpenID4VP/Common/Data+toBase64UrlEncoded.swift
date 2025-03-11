import Foundation

extension Data {
    func toBase64UrlEncoded() -> String {
        return base64URLEscaped(self.base64EncodedString())
    }
}
