import Foundation

func base64URLEncode(_ input: [String: Any]) throws -> String {
    guard let jsonData = try? JSONSerialization.data(withJSONObject: input, options: []) else {
        throw InvalidData(message: "Failed to serialize JSON", className: "Base64Encoder")
    }
    
    return jsonData.toBase64UrlEncoded()
}

import Foundation

struct BaseEncoding {
    
    /// Standard Base-58-BTC alphabet (excludes 0, O, l, I)
    private static let base58BtcAlphabet = Array("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".utf8)
    
    /// Converts a byte array (base-256) to a base-encoded string (e.g., base-58-btc)
    /// - Parameters:
    ///   - bytes: Array of UInt8 representing the data.
    ///   - targetBase: The target base (e.g., 58 for base-58-btc).
    ///   - baseAlphabet: The alphabet used for character mapping.
    /// - Returns: A base-encoded string.
     private static func baseEncode(bytes: [UInt8], targetBase: Int, baseAlphabet: [UInt8]) -> String {
        var begin = 0
        var end = bytes.count
        var zeroes = 0
        var length = 0
        
        // 1. Count leading zero bytes
        while begin != end && bytes[begin] == 0 {
            begin += 1
            zeroes += 1
        }
        
        // 2. Estimate output capacity using log(256) / log(targetBase)
        // For base-58, log(256)/log(58) ≈ 1.3737
        let log256: Double = 8.0
        let logBase: Double = log2(Double(targetBase))
        let sizeRatio = log256 / logBase
        
        let remainingBytes = Double(end - begin)
        let estimatedSize = Int(ceil(remainingBytes * sizeRatio)) + 1
        
        var baseValue = [UInt8](repeating: 0, count: estimatedSize)
        
        // 3. Process the remaining bytes
        for byteIndex in begin..<end {
            let byteVal = bytes[byteIndex]
            var carry = Int(byteVal)
            
            var basePosition = estimatedSize - 1
            var i = 0
            
            while carry != 0 || i < length {
                carry += Int(baseValue[basePosition]) * 256
                baseValue[basePosition] = UInt8(carry % targetBase)
                carry /= targetBase
                
                basePosition -= 1
                i += 1
            }
            length = i
            begin += 1
        }
        
        // 4. Skip the leading zeros of baseValue
        var baseEncodingPosition = estimatedSize - length
        while baseEncodingPosition < estimatedSize && baseValue[baseEncodingPosition] == 0 {
            baseEncodingPosition += 1
        }
        
        // 5. Construct the final output
        var baseEncoding = ""
        
        // Add prefix for leading zero bytes
        for _ in 0..<zeroes {
            if let firstChar = String(bytes: [baseAlphabet[0]], encoding: .utf8) {
                baseEncoding.append(firstChar)
            }
        }
        
        // Append the rest of the values
        while baseEncodingPosition < estimatedSize {
            let charIndex = Int(baseValue[baseEncodingPosition])
            if let mappedChar = String(bytes: [baseAlphabet[charIndex]], encoding: .utf8) {
                baseEncoding.append(mappedChar)
            }
            baseEncodingPosition += 1
        }
        
        return baseEncoding
    }
    
    static func base58BtcEncode(bytes: Data) -> String {
        return baseEncode(bytes: [UInt8](bytes), targetBase: 58, baseAlphabet: base58BtcAlphabet)
    }
}
