import Foundation

extension Data {
    func toBase58BtcEncoded() -> String {
        return BaseEncoding.base58BtcEncode(bytes: self)
    }
}
