import Foundation
import Base58Swift
import CryptoKit

func publicKeyMultibaseToSecKey(_ multibase: String) throws -> SecKey {
    let decoded = try decodeMultibase(multibase)
    let rawKey = stripMulticodecPrefix(from: decoded)
    guard let secKey = createSecKey(from: rawKey) else {
        throw NSError(domain: "KeyCreationError", code: -1, userInfo: nil)
    }
    return secKey
}


private func stripMulticodecPrefix(from data: Data) -> Data {
    // First 2 bytes are the codec
    return data.dropFirst(2)
}

private func createSecKey(from publicKeyData: Data) -> SecKey? {
    let attributes: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
        kSecAttrKeySizeInBits as String: 256,
        kSecReturnPersistentRef as String: false
    ]
    
    return SecKeyCreateWithData(publicKeyData as CFData,
                                attributes as CFDictionary,
                                nil)
}


private func decodeMultibase(_ multibaseKey: String) throws -> Data {
    guard multibaseKey.starts(with: "z") else {  throw JsonDecodingFailed(
        message: "Multibase not starting with base58 prefix",
        className: JWSHandler.className
    ) } // "z" = base58btc
    
    let encoded = String(multibaseKey.dropFirst())
    guard let decoded = Base58.base58Decode(encoded) else {
        throw JsonDecodingFailed(
            message: "DID public key decoding failed",
            className: JWSHandler.className
        )
    }
    return Data(decoded)
}

func parsePublicKey(from publicKeyMultibase: String) throws -> PublicKeyType {
    guard publicKeyMultibase.first == "z" else {
        throw JsonDecodingFailed(
            message: "DID public key decoding failed",
            className: JWSHandler.className
        )
    }
    
    let base58Part = String(publicKeyMultibase.dropFirst())
    guard let decoded = Base58.base58Decode(base58Part) else{
        throw JsonDecodingFailed(
            message: "DID public key decoding failed",
            className: JWSHandler.className
        )
    }
    
    guard decoded.count > 2 else {
        throw JsonDecodingFailed(
            message: "DID public key decoding failed",
            className: JWSHandler.className
        )
    }
    
    let prefix = Array(decoded.prefix(2))
    let keyData = Data(decoded.dropFirst(2))
    
    switch prefix {
    case [0xed, 0x01]:  // Ed25519
        guard keyData.count == 32 else {
            throw JsonDecodingFailed(
                message: "DID public key decoding failed",
                className: JWSHandler.className
            )
        }
        let edKey = try Curve25519.Signing.PublicKey(rawRepresentation: keyData)
        return .ed25519(edKey)
        
    case [0x12, 0x00]:  // P-256 (uncompressed EC public key — often 65 bytes)
        return try createSecKey(from: keyData).map { .secKey($0) } ?? {
            throw JsonDecodingFailed(
                message: "DID public key decoding failed",
                className: JWSHandler.className
            )
        }()
        
    default:
        throw JsonDecodingFailed(
            message: "DID public key decoding failed",
            className: JWSHandler.className
        )
    }
}

//func createSecKeyFromJWK(_ jwk: [String: Any]) throws -> PublicKeyType {
//    guard let kty = jwk["kty"] as? String, kty == "OKP" else {
//        throw PublicKeyResolutionFailed(
//            message: "JWKError.unsupportedKeyType",
//            className: JWSHandler.className
//        )
//    }
//    
//    guard let crv = jwk["crv"] as? String, crv == "Ed25519" else {
//        throw PublicKeyResolutionFailed(
//            message: "JWKError.unsupportedKeyType",
//            className: JWSHandler.className
//        )
//    }
//    
//    guard let x = jwk["x"] as? String else {
//        throw PublicKeyResolutionFailed(
//            message: "JWKError.missingKeyData",
//            className: JWSHandler.className
//        )
//    }
//    
//    guard let keyData = Data(base64Encoded: x) else {
//        throw PublicKeyResolutionFailed(
//            message: "JWKError.invalidBase64",
//            className: JWSHandler.className
//        )
//    }
//    
//    let attributes: [String: Any] = [
//        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom, // placeholder; overridden below
//        kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
//        kSecAttrKeySizeInBits as String: 256,
//        kSecAttrIsPermanent as String: false
//    ]
//    
//    guard let secKey = SecKeyCreateWithData(keyData as CFData,
//                                            attributes as CFDictionary,
//                                            nil) else {
//        throw JsonDecodingFailed(
//            message: "JWKError.secKeyCreationFailed",
//            className: JWSHandler.className
//        )
//    }
//    
//    return .secKey(secKey)
//}
