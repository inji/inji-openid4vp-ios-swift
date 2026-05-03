import Foundation

public enum SignatureAlgorithm: String, CaseIterable, Codable {
    case ed25519Signature2020 = "Ed25519Signature2020"
    case jsonWebSignature2020 = "JsonWebSignature2020"
    case ed25519Signature2018 = "Ed25519Signature2018"
    case rsaSignature2018 = "RsaSignature2018"
    
    public static func fromValue(_ value: String) -> SignatureAlgorithm? {
        return SignatureAlgorithm(rawValue: value)
    }
}
