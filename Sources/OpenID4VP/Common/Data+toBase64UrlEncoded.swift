import Foundation

extension Data {
    init?(base64UrlEncoded: String) {
        let base64 = base64UrlEncoded.base64URLToBase64()
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
