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
            message: "DID public key decoding failed. Unsupported public key format",
            className: JWSHandler.className
        )
    }
}

func createSecKeyFromJWK(_ jwk: [String: Any]) throws -> PublicKeyType {
    guard let kty = jwk["kty"] as? String, kty == "OKP" else {
        throw PublicKeyResolutionFailed(
            message: "JWKError.unsupportedKeyType",
            className: JWSHandler.className
        )
    }
    
    guard let crv = jwk["crv"] as? String, crv == "Ed25519" else {
        throw PublicKeyResolutionFailed(
            message: "JWKError.unsupportedKeyType",
            className: JWSHandler.className
        )
    }
    
    guard let x = jwk["x"] as? String else {
        throw PublicKeyResolutionFailed(
            message: "JWKError.missingKeyData",
            className: JWSHandler.className
        )
    }
    
    guard let keyData = Data(base64UrlEncoded: x) else {
        throw PublicKeyResolutionFailed(
            message: "JWKError.invalidBase64",
            className: JWSHandler.className
        )
    }
    let edPublicKey = try Curve25519.Signing.PublicKey(rawRepresentation: keyData)
    
    return .ed25519(edPublicKey)
}

func stripPEMHeader(pemString: String) -> Data? {
    let lines = pemString.components(separatedBy: .newlines)
    let base64String = lines
        .filter { !$0.contains("-----") && !$0.isEmpty }
        .joined()
    return Data(base64Encoded: base64String)
}

func publicKeyFromPEM(_ pemString: String) -> SecKey? {
    guard let keyData = stripPEMHeader(pemString: pemString) else { return nil }

    let options: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
        kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
        kSecAttrKeySizeInBits as String: keyData.count * 8,
        kSecReturnPersistentRef as String: true
    ]

    return SecKeyCreateWithData(keyData as CFData, options as CFDictionary, nil)
}

func hexStringToData(_ hex: String) -> Data? {
    var data = Data()
    var temp = ""
    for char in hex {
        temp.append(char)
        if temp.count == 2 {
            if let byte = UInt8(temp, radix: 16) {
                data.append(byte)
                temp = ""
            } else {
                return nil
            }
        }
    }
    return data
}


func publicKeyFromHex(_ hexKey: String) -> PublicKeyType? {
    let hexData = hexStringToData(hexKey)!
    let publicKey = try! Curve25519.Signing.PublicKey(rawRepresentation: hexData)
    return .ed25519(publicKey)
}
