import Foundation

extension Data {
    func toBase58BtcEncoded() -> String {
        let alphabet = Array("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
        var bytes = [UInt8](self)

        var leadingZeroCount = 0
        for byte in bytes {
            guard byte == 0 else { break }
            leadingZeroCount += 1
        }

        var digits = [Int]()
        for byte in bytes {
            var carry = Int(byte)
            for j in 0..<digits.count {
                carry += digits[j] * 256
                digits[j] = carry % 58
                carry /= 58
            }
            while carry > 0 {
                digits.append(carry % 58)
                carry /= 58
            }
        }

        var result = String(repeating: "1", count: leadingZeroCount)
        result += digits.reversed().map { String(alphabet[$0]) }.joined()
        return result
    }
}
