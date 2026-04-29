import Foundation
import JSONWebKey
import CryptoKit
import SwiftCBOR

// COSE algorithm identifiers (RFC 8152 / COSE Algorithms)
private let COSE_ALG_ES256: Int = -7
private let COSE_ALG_EDDSA: Int = -8

// COSE curve identifiers (RFC 8152 / COSE Keys)
private let COSE_CRV_P256: Int = 1
private let COSE_CRV_ED25519: Int = 6

// CBOR tag identifiers (RFC 7049 / CBOR Tags)
private let CBOR_TAG_ENCODED_CBOR: Int = 24

enum JWSPart: Int {
    case header = 0, payload, signature
}

func isJWS(_ input: String) -> Bool {
    return input.split(separator: ".").count == 3
}

func base64URLEscaped(_ base64String: String) -> String {
    return base64String
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

func determineHttpMethod(method: String) throws -> HttpMethod {
    let methodValue = method.lowercased()
    if methodValue == "get" {
        return .get
    } else if methodValue == "post" {
        return .post
    } else {
        throw UnsupportedHttpMethod(message: method, className: AuthorizationRequest.className)
    }
}

func getStringValue(_ value: Any?) -> String? {
    return value as? String
}

public func isValidUri(_ urlString: String) -> Bool {
    let urlRegex = #"^https:\/\/(?:[\w-]+\.)+[\w-]+(?:\/[\w\-.~!$&'()*+,;=:@%]+)*\/?(?:\?[^#\s]*)?(?:#.*)?$"#
    
    return urlString.range(of: urlRegex, options: .regularExpression) != nil
}

func convertToInstance<T: Decodable>(_ dictionary: [String: Any], as type: T.Type) throws -> T {
    let data = try JSONSerialization.data(withJSONObject: dictionary, options: [])
    return try JSONDecoder().decode(T.self, from: data)
}

func convertToInstance<T: Decodable>(_ input: String, as type: T.Type, fieldPath: [String] = [], className: String = "Utils") throws -> T {
    guard let jsonData = input.data(using: .utf8) else {
        throw UTF8EncodingFailed( fieldPath: fieldPath, className: className)
    }
    
    return try jsonData.toInstance(as: T.self)
}

func toData(_ input: [String: Any]) throws -> Data {
    var processedInput: [String: Any] = [:]

    for (key, value) in input {
        if let encodableValue = value as? Encodable {
            if let converted = encodableValue.toDictionary() {
                processedInput[key] = converted
            } else {
                processedInput[key] = value
            }
        } else {
            processedInput[key] = value
        }
    }
    guard JSONSerialization.isValidJSONObject(processedInput) else {
        throw JsonEncodingFailed(
            fieldPath: "processedInput",
            errorMessage: "Invalid JSON object",
            className: "utils"
        )
    }
    return try JSONSerialization.data(withJSONObject: processedInput, options: [])
}

func sha256Hash(from data: CBOR) -> [UInt8] {
    let hash: SHA256.Digest = SHA256.hash(data: CBOR.encode(data))
    return ([UInt8])(Data(hash))
}

func wrapError(_ error: Error, customError: (String) -> Error) -> Error {
    if type(of: error) == OpenID4VPException.self {
        return error
    } else {
        return customError(error.localizedDescription)
    }
}


func hashData(_ data: String, hashAlgorithm: String = HashAlgorithm.sha256.rawValue, className: String) throws -> Data {
    guard let inputData = data.data(using: .utf8) else {
        throw UTF8EncodingFailed(fieldPath: "hashInput", className: className)
    }
    
    let algorithm = HashAlgorithm(rawValue: hashAlgorithm)
    
    switch algorithm {
    case .sha256:
        let hash = SHA256.hash(data: inputData)
        return Data(hash)
    case .sha384:
        let hash = SHA384.hash(data: inputData)
        return Data(hash)
    case .sha512:
        let hash = SHA512.hash(data: inputData)
        return Data(hash)
    default:
        throw UnsupportedOperationException(message: "Hash algorithm \(hashAlgorithm) is not supported", className: className)
    }
}

func createNestedPath(id: String, nestedPath: String?, format: FormatType) -> PathNested? {
    guard let nestedPath = nestedPath else { return nil }
    return PathNested(id: id, format: format, path: nestedPath)
}

func createDescriptorMapPath(_ index: Int) -> String {
    return "$[\(index)]"
}

func resolveJwksFromUri(_ uri: String, networkManager: NetworkManaging, className: String) async throws -> JWKSet {
    do {
        let response = try await networkManager.sendHTTPRequest(url: uri, method: .get, bodyParams: nil, headers: nil)
        if(!response.isOK){
            throw InvalidData(
                message: "Error while fetching jwks information, status code: \(response.statusCode) with body: \(response.body)",
                className: className
            )
        }
        let data = try response.body.data(using: .utf8) ?? {
           throw InvalidData(
                message: "unable to convert the jwks response to data",
                className: className
            )
        }()
        return try data.toInstance(as: JWKSet.self)
    } catch {
        throw InvalidData(
            message: "Public key extraction failed - Unable to fetch/parse jwks from \(uri) due to \(error.localizedDescription)",
            className: className,
            code: OpenID4VPErrorCodes.invalidRequestObject
                )
    }
}

internal func validate(_ value: String, fieldPath: String,className: String) throws {
    if !isNeitherNullNorEmpty(field: value) || (value == "null") {
        throw InvalidInput(fieldPath: [fieldPath], className: className)
    }
}

func resolveMdocKeyAndAlg(_ mdocCredential: String) throws -> (keyRef: String, alg: String) {

    
    guard let data = Data(base64UrlEncoded: mdocCredential) else {
        throw InvalidData(
            message: "Invalid base64url mdoc credential",
            className: "OpenID4VPUtils"
        )
    }

    var decoded = try CBORDecoder(input: [UInt8](data)).decodeItem()

    
    guard case let CBOR.map(rootMap)? = decoded,
          let issuerSigned = rootMap[CBOR.utf8String("issuerSigned")],
          case let CBOR.map(issuerSignedMap) = issuerSigned else {
        throw InvalidData(message: "issuerSigned missing", className: "OpenID4VPUtils")
    }

    
    guard let issuerAuth = issuerSignedMap[CBOR.utf8String("issuerAuth")],
          case let CBOR.array(issuerAuthArray) = issuerAuth,
          issuerAuthArray.count > 2,
          case let CBOR.byteString(payloadBytes) = issuerAuthArray[2] else {
        throw InvalidData(message: "issuerAuth payload missing", className: "OpenID4VPUtils")
    }

    
    decoded = try CBORDecoder(input: payloadBytes).decodeItem()

    
    if case let CBOR.tagged(tag, inner)? = decoded, tag.rawValue == CBOR_TAG_ENCODED_CBOR {
        guard case let CBOR.byteString(innerBytes) = inner else {
            throw InvalidData(message: "cbor tag 24 inner not bstr", className: "OpenID4VPUtils")
        }
        decoded = try CBORDecoder(input: innerBytes).decodeItem()
    }

    
    guard case let CBOR.map(msoMap)? = decoded,
          let deviceKeyInfo = msoMap[CBOR.utf8String("deviceKeyInfo")],
          case let CBOR.map(deviceKeyInfoMap) = deviceKeyInfo,
          let deviceKey = deviceKeyInfoMap[CBOR.utf8String("deviceKey")],
          case let CBOR.map(deviceKeyMap) = deviceKey else {
        throw InvalidData(message: "deviceKey missing", className: "OpenID4VPUtils")
    }

    
    let keyBytes = Data(cborEncode(deviceKey))
    let keyRef = keyBytes.toBase64UrlEncoded()

    
    if let algItem = deviceKeyMap[CBOR.unsignedInt(3)]{
        let coseAlg = try readCoseInt(algItem)
        switch coseAlg {
        case COSE_ALG_ES256: return (keyRef, "ES256")
        case COSE_ALG_EDDSA: return (keyRef, "EdDSA")
        default:
            throw InvalidData(message: "Unsupported COSE alg \(coseAlg)", className: "OpenID4VPUtils")
        }
    }

    
    guard let crvItem = deviceKeyMap[CBOR.negativeInt(0)] else {
        throw InvalidData(message: "crv missing for alg inference", className: "OpenID4VPUtils")
    }

    let crv = try readCoseInt(crvItem)
    switch crv {
    case COSE_CRV_P256: return (keyRef, "ES256")
    case COSE_CRV_ED25519: return (keyRef, "EdDSA")
    default:
        throw InvalidData(message: "Unsupported crv \(crv)", className: "OpenID4VPUtils")
    }
}

func readCoseInt(_ cbor: CBOR) throws -> Int {
    switch cbor {
    case .unsignedInt(let v): return Int(v)
    case .negativeInt(let v): return -1 - Int(v)
    default:
        throw InvalidData(message: "Invalid COSE integer type", className: "OpenID4VPUtils")
    }
}



// MARK: - CONSTRUCT SIGNING RESULTS V2

func constructSigningResults(
    unsignedVPTokenResults: [FormatType: (Any?, [UnsignedVPToken])],
    signingResults: [VPTokenSigningResult],
    signatureSuite: String
) throws -> [FormatType: [VPTokenSigningResult]] {
    
    var iterator = signingResults.makeIterator()
    var reconstructed: [FormatType: [VPTokenSigningResult]] = [:]
    
    for format in unsignedVPTokenResults.keys.sorted(by: { $0.rawValue < $1.rawValue }) {
        guard let pair = unsignedVPTokenResults[format] else { continue }
        let unsignedTokens = pair.1
        
        var resultsForFormat: [VPTokenSigningResult] = []
        for _ in unsignedTokens {
            guard let nextResult = iterator.next() else {
                throw InvalidData(message: "Missing signing result for format \(format)", className: "OpenID4VPUtils")
            }
            resultsForFormat.append(nextResult)
        }
        reconstructed[format] = resultsForFormat
    }
    
    if iterator.next() != nil {
        throw InvalidData(message: "Extra signing results provided", className: "OpenID4VPUtils")
    }
    
    return reconstructed
}

func resolveSdJwtKeyAndAlg(_ sdJwtCredential: String) async throws -> (keyRef: String, alg: String) {
    let parts = sdJwtCredential.split(separator: "~")
    guard let sdJwt = parts.first else {
        throw InvalidData(message: "Invalid SD-JWT credential format", className: "OpenID4VPUtils")
    }

    let jwsParts = sdJwt.split(separator: ".")
    guard jwsParts.count >= 2 else {
        throw InvalidData(message: "Invalid SD-JWT JWS format", className: "OpenID4VPUtils")
    }

    guard let payloadData = Data(base64UrlEncoded: String(jwsParts[1])) else {
        throw InvalidData(message: "Invalid SD-JWT payload encoding", className: "OpenID4VPUtils")
    }

    guard let json = try JSONSerialization.jsonObject(with: payloadData) as? [String: Any],
          let cnf = json["cnf"] as? [String: Any],
          let kid = cnf["kid"] as? String else {
        throw InvalidData(message: "cnf.kid missing in SD-JWT", className: "OpenID4VPUtils")
    }

    
    let resolver = DidPublicKeyResolver()
    let publicKey = try await resolver.resolve(
        uri: kid.trimmingCharacters(in: CharacterSet(charactersIn: "=")),
        keyId: nil
    )

    
    let alg: String

    switch publicKey {
    case .ed25519:
        alg = "EdDSA"

    case .secKey:
        alg = "ES256"
    }

    return (kid, alg)
}

func getEncryptionKey(_ jwks: JWKSet, _ supportedEncryptionAlgorithms: [String]) throws -> JWK {
    for alg in supportedEncryptionAlgorithms {
        if let key = jwks.keys.first(where: { $0.algorithm == alg && $0.publicKeyUse == .encryption }) {
            return key
        }
    }
    
    throw InvalidData(message: "No encryption key with alg \(supportedEncryptionAlgorithms) found in JWK Set", className: "OpenID4VPUtils")
}

func matchingDCQLCredentialQuery(_  authorizationRequest: AuthorizationRequest, for credentialQueryId: String, className: String) throws -> CredentialQuery {
    let matchingCredentialQuery = try (authorizationRequest as? AuthorizationDcqlRequest)?.dcqlQuery.credentials.first(where: { $0.id == credentialQueryId }) ?? {
        throw InvalidData(message: "No matching credential query found for credentialQueryId: \(credentialQueryId)", className: className)
    }()
    return matchingCredentialQuery
}


private enum JWSAlgorithm {
    static let eddsa = "EdDSA"
    static let es256 = "ES256"
    static let es384 = "ES384"
    static let es256k = "ES256K"
}

private enum MulticodecPrefix {
    static let ed25519 = "z6M"    // Ed25519
    static let p256 = "zDn"       // P-256
    static let p384 = "z82"       // P-384
    static let secp256k1 = "zQ3"  // secp256k1
}

private enum DIDPrefix {
    static let key = "did:key:"
    static let jwk = "did:jwk:"
}

// MARK: - Utility Function
/// Extracts the JWS 'alg' string based on a Subject ID (DID) without hardcoded magic strings.
/// Reference: https://www.w3.org/TR/vc-data-model-1.1/#identifiers
func getJWSAlgorithm(from uri: String) -> String {
    
    // 1. Handle did:key
    if uri.hasPrefix(DIDPrefix.key) {
        let identifier = uri.replacingOccurrences(of: DIDPrefix.key, with: "")
        
        if identifier.hasPrefix(MulticodecPrefix.ed25519) { return JWSAlgorithm.eddsa }
        if identifier.hasPrefix(MulticodecPrefix.p256)    { return JWSAlgorithm.es256 }
        if identifier.hasPrefix(MulticodecPrefix.p384)    { return JWSAlgorithm.es384 }
        if identifier.hasPrefix(MulticodecPrefix.secp256k1) { return JWSAlgorithm.es256k }
    }
    
    // 2. Handle did:jwk
    if uri.hasPrefix(DIDPrefix.jwk) {
        //TODO: reuse Did key resolver logic here to avoid code duplication
        let base64Part = uri.replacingOccurrences(of: DIDPrefix.jwk, with: "")
        if let jwk = decodeJWK(base64Part) {
            // Priority 1: Use explicit 'alg' field
            if let alg = jwk["alg"] as? String { return alg }
            
            // Priority 2: Map from kty/crv
            let kty = jwk["kty"] as? String ?? ""
            let crv = jwk["crv"] as? String ?? ""
            
            switch (kty, crv) {
            case ("OKP", "Ed25519"): return JWSAlgorithm.eddsa
            case ("EC", "P-256"):    return JWSAlgorithm.es256
            case ("EC", "P-384"):    return JWSAlgorithm.es384
            case ("EC", "secp256k1"): return JWSAlgorithm.es256k
            default: break
            }
        }
    }
    
    // Default fallback to EdDSA as per common mobile wallet profiles
    return JWSAlgorithm.eddsa
}

private func decodeJWK(_ base64URL: String) -> [String: Any]? {
    var base64 = base64URL
        .replacingOccurrences(of: "-", with: "+")
        .replacingOccurrences(of: "_", with: "/")
    
    let remainder = base64.count % 4
    if remainder > 0 {
        base64 = base64.padding(toLength: base64.count + (4 - remainder), withPad: "=", startingAt: 0)
    }
    
    guard let data = Data(base64Encoded: base64) else { return nil }
    return try? JSONSerialization.jsonObject(with: data) as? [String: Any]
}
