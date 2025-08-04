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
    
    init?(hexString: String) {
           let len = hexString.count / 2
           var data = Data(capacity: len)
           var index = hexString.startIndex
           
           for _ in 0..<len {
               let nextIndex = hexString.index(index, offsetBy: 2)
               guard nextIndex <= hexString.endIndex else { return nil }
               let byteString = hexString[index..<nextIndex]
               guard let byte = UInt8(byteString, radix: 16) else { return nil }
               data.append(byte)
               index = nextIndex
           }
           
           self = data
       }
}
