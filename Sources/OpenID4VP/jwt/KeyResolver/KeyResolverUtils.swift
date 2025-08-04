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

func publicKeyFromJWK(_ jwk: [String: Any]) throws -> PublicKeyType {
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

func publicKeyFromPEM(_ pem: String) throws -> PublicKeyType {
    let base64Key = pem
        .replacingOccurrences(of: "-----BEGIN PUBLIC KEY-----", with: "") // PEM header
        .replacingOccurrences(of: "-----END PUBLIC KEY-----", with: "") // PEMM footer
        .replacingOccurrences(of: "\n", with: "") // Extra newlines
        .replacingOccurrences(of: "\r", with: "") // Carriage returns

    guard let derData = Data(base64Encoded: base64Key) else {
        //PEM format will have the key in base64 encoded format
        throw PublicKeyResolutionFailed(
            message: "Invalid PEM format",
            className: JWSHandler.className
        )
    }

    // Strip ASN.1 header to get raw Ed25519 key (32 bytes)
    // Ed25519 DER prefix is always 12 bytes (for SubjectPublicKeyInfo)
    // You may need to adjust this if you’re dealing with a different key format
    let expectedHeader: [UInt8] = [
        0x30, 0x2a,             // SEQUENCE
        0x30, 0x05,             // SEQUENCE (AlgorithmIdentifier)
        0x06, 0x03, 0x2b, 0x65, 0x70, // OID: 1.3.101.112 (Ed25519)
        0x03                    // BIT STRING
    ]

    // Find start of actual key
    var offset = 0
    for i in 0..<derData.count {
        if derData[i...].starts(with: expectedHeader) {
            offset = i + 12
            break
        }
    }

    guard offset > 0, derData.count >= offset + 32 else {
        throw PublicKeyResolutionFailed(
            message: "Invalid Ed25519 public key format",
            className: JWSHandler.className
        )
    }

    let publicKeyBytes = derData[offset..<offset + 32]

    do {
        let edKey = try Curve25519.Signing.PublicKey(rawRepresentation: publicKeyBytes)
        return .ed25519(edKey)
    } catch {
        throw error
    }
}


//func publicKeyFromHex(_ hex: String) throws -> PublicKeyType {
//    guard let rawData = Data(hexString: hex) else {
//        throw PublicKeyResolutionFailed(
//            message: "Invalid hex string",
//            className: JWSHandler.className
//        )
//    }
//    
//    guard rawData.count == 32 else {
//        throw PublicKeyResolutionFailed(
//            message: "Invalid Ed25519 public key length. Expected 32 bytes, got \(rawData.count).",
//            className: JWSHandler.className
//        )
//    }
//    
//    do {
//        let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: rawData)
//        return .ed25519(publicKey)
//    } catch {
//        throw PublicKeyResolutionFailed(
//            message: "Failed to create Ed25519 public key from hex string",
//            className: JWSHandler.className
//        )
//    }
//}
