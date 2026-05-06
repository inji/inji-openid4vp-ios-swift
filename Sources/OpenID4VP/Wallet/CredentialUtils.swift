import Foundation
import CryptoKit
import SwiftCBOR

func extractSdJwtPayload(_ credential: AnyCodable, className: String, decodeDisclosures: Bool = false) throws -> (Credential: String, decodedPayload: [String: Any], fullyResolvedClaims: [String: Any]) {
    let sdJwtCredential = try extractSDJwtString(from: credential, className: className)

    let parts = sdJwtCredential.split(separator: "~", omittingEmptySubsequences: false).map(String.init)

    guard let jwtPart = parts.first, !jwtPart.isEmpty else {
        throw InvalidData(message: "SD-JWT credential is malformed or empty", className: className)
    }

    let payload = try JWSHandler.extractDataJsonFromJws(jws: jwtPart, jwsPart: .payload)

    var disclosureMap: [String: (claimName: String, claimValue: Any)] = [:]
    for disclosure in parts.dropFirst().filter({ !$0.isEmpty }) {
        let padded = disclosure.base64URLToBase64()
        guard let data = Data(base64Encoded: padded),
              let decoded = try? JSONSerialization.jsonObject(with: data) as? [Any],
              decoded.count >= 3,
              let claimName = decoded[1] as? String else {
            continue
        }
        let digest = Data(SHA256.hash(data: Data(disclosure.utf8))).toBase64UrlEncoded()
        disclosureMap[digest] = (claimName, decoded[2])
    }

    let fullyResolvedClaims = resolveSDJWTClaims(payload, disclosureMap: disclosureMap)

    return (sdJwtCredential, payload, fullyResolvedClaims)
}

private func resolveSDJWTClaims(_ object: [String: Any], disclosureMap: [String: (claimName: String, claimValue: Any)]) -> [String: Any] {
    var result: [String: Any] = [:]

    if let sdHashes = object["_sd"] as? [String] {
        for hash in sdHashes {
            if let (claimName, claimValue) = disclosureMap[hash] {
                result[claimName] = (claimValue as? [String: Any]).map { resolveSDJWTClaims($0, disclosureMap: disclosureMap) } ?? claimValue
            }
        }
    }

    for (key, value) in object where key != "_sd" && key != "_sd_alg" {
        result[key] = (value as? [String: Any]).map { resolveSDJWTClaims($0, disclosureMap: disclosureMap) } ?? value
    }

    return result
}

func decodeMdoc(_ credential: AnyCodable, className: String) throws -> (mdocCredential: String, decodedMdoc: CBOR) {
    let mdocCredential = try extractMdocString(from: credential, className: className)
    
    guard let decodedMdoc = try? decodeCBOR(base64EncodedInput: mdocCredential) else {
        throw InvalidData(
            message: "Invalid Verifiable Credential: Error while decoding credential",
            className: className
        )
    }
    
    return (mdocCredential, decodedMdoc)
}

func extractSDJwtString(from credential: AnyCodable, className: String) throws -> String {
    guard let sdJwtCredential = credential.value as? String else {
        throw InvalidData(message: "SD-JWT credential is not a String", className: className)
    }
    return sdJwtCredential
}

func extractMdocString(from credential: AnyCodable, className: String) throws -> String {
    guard let mdocCredential = credential.value as? String else {
        throw InvalidData(
            message: "MDOC credential is not a String",
            className: AuthorizationResponseHandler.className
        )
    }
    
    return mdocCredential
}

func extractMdocDocType(from decodedCredential: CBOR, className: String) throws -> (docType: CBOR, docTypeString: String) {
    guard let docType = getValueFromCBORMap(cborMap: decodedCredential, key: "docType"),
          let docTypeString = extractStringFromCBOR(docType) else {
        
        throw InvalidData(
            message: "docType missing or invalid in credential",
            className: className
        )
    }
    
    return (docType, docTypeString)
}
