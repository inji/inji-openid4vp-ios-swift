import Foundation
import JSONWebKey
import CryptoKit
import SwiftCBOR

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

func flattenUnsignedTokensV2(
        unsignedVPTokenResults: [FormatType: (VPTokenSigningPayload?, UnsignedVPToken)],
        formatMappings: [FormatType: [CredentialInputDescriptorMapping]],
        holderId: String?,
        signatureSuite: String?
    ) async throws -> [UnsignedVPTokenV2] {

        var result: [UnsignedVPTokenV2] = []

        for (format, pair) in unsignedVPTokenResults {
            guard let mappings = formatMappings[format] else {
                throw InvalidData(message: "Missing mapping for \(format)", className: "OpenID4VPUtils")
            }

            switch format {
            case .ldp_vc:
                result += try flattenLdpV2(pair.1, mappings, signatureSuite, holderId: holderId)

            case .mso_mdoc:
                result += try flattenMdocV2(pair.1, mappings)

            case .dc_sd_jwt, .vc_sd_jwt:
                result += try await flattenSdJwtV2(pair.1, mappings, format)
            }
        }

        return result
    }

func resolveMdocKeyAndAlg(_ mdocCredential: String) throws -> (keyRef: String, alg: String) {

    
    var base64 = mdocCredential
        .replacingOccurrences(of: "-", with: "+")
        .replacingOccurrences(of: "_", with: "/")

    let remainder = base64.count % 4
    if remainder > 0 {
        base64 += String(repeating: "=", count: 4 - remainder)
    }

    guard let data = Data(base64Encoded: base64) else {
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

    
    if case let CBOR.tagged(tag, inner)? = decoded, tag.rawValue == 24 {
        guard case let CBOR.byteString(innerBytes) = inner else {
            throw InvalidData(message: "Tag 24 inner not bstr", className: "OpenID4VPUtils")
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
        case -7: return (keyRef, "ES256")
        case -8: return (keyRef, "EdDSA")
        default:
            throw InvalidData(message: "Unsupported COSE alg \(coseAlg)", className: "OpenID4VPUtils")
        }
    }

    
    guard let crvItem = deviceKeyMap[CBOR.negativeInt(0)] else {
        throw InvalidData(message: "crv missing for alg inference", className: "OpenID4VPUtils")
    }

    let crv = try readCoseInt(crvItem)
    switch crv {
    case 1: return (keyRef, "ES256")
    case 6: return (keyRef, "EdDSA")
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



    // MARK: - RECONSTRUCT SIGNING RESULTS V2

     func reconstructSigningResultsV2(
        unsignedVPTokenResults: [FormatType: (VPTokenSigningPayload?, UnsignedVPToken)],
        formatMappings: [FormatType: [CredentialInputDescriptorMapping]],
        signingResults: [VPTokenSigningResultV2],
        signatureSuite: String
    ) throws -> [FormatType: VPTokenSigningResult] {

        var iterator = signingResults.makeIterator()
        var reconstructed: [FormatType: VPTokenSigningResult] = [:]

        for (format, pair) in unsignedVPTokenResults {
            let unsignedToken = pair.1
            guard let mappings = formatMappings[format] else {
                throw InvalidData(message: "Missing mapping for \(format)", className: "OpenID4VPUtils")
            }

            switch format {
            case .ldp_vc:
                reconstructed[format] = try reconstructLdpV2(&iterator, signatureSuite: signatureSuite)

            case .mso_mdoc:
                reconstructed[format] = try reconstructMdocV2(unsignedToken, mappings, &iterator)

            case .dc_sd_jwt, .vc_sd_jwt:
                reconstructed[format] = try reconstructSdJwtV2(unsignedToken, &iterator)
            }
        }

        if iterator.next() != nil {
            throw InvalidData(message: "Extra signing results provided", className: "OpenID4VPUtils")
        }

        return reconstructed
    }

    // MARK: - LDP

private func flattenLdpV2(
        _ unsignedToken: UnsignedVPToken,
        _ mappings: [CredentialInputDescriptorMapping],
        _ signatureSuite: String?,
        holderId: String?
    ) throws -> [UnsignedVPTokenV2] {

        guard let ldp = unsignedToken as? UnsignedLdpVPToken else { fatalError() }

        let holdervalue = try holderId ??
        (mappings.first?.credential.value as? [String: Any]).flatMap { ($0["credentialSubject"] as? [String: Any])?["id"] as? String } ??
        { throw InvalidData(message: "Invalid LDP credential structure", className: "OpenID4VPUtils") }()


        guard let suite = signatureSuite else {
            throw InvalidData(message: "signatureSuite required for LDP", className: "OpenID4VPUtils")
        }

        return [
            UnsignedVPTokenV2(
                format: .ldp_vc,
                holderKeyReference: holdervalue,
                signatureAlgorithm: suite,
                dataToSign: ldp.dataToSign
            )
        ]
    }

    private  func reconstructLdpV2(
        _ iterator: inout IndexingIterator<[VPTokenSigningResultV2]>,
        signatureSuite: String
    ) throws -> VPTokenSigningResult {

        guard let signed = iterator.next() else {
            throw InvalidData(message: "Missing LDP signature", className: "OpenID4VPUtils")
        }

        if(signatureSuite == SignatureAlgorithm.jsonWebSignature2020.rawValue || signatureSuite == SignatureAlgorithm.rsaSignature2018.rawValue ||
           signatureSuite == SignatureAlgorithm.ed25519Signature2018.rawValue){
            return LdpVPTokenSigningResult(
                jws: signed.signedData,
                proofValue: nil,
                signatureAlgorithm: signatureSuite
            )
        }
        return LdpVPTokenSigningResult(
            proofValue: signed.signedData,
            signatureAlgorithm: signatureSuite
        )
    }

    // MARK: - MDOC

    private  func flattenMdocV2(
        _ unsignedToken: UnsignedVPToken,
        _ mappings: [CredentialInputDescriptorMapping]
    ) throws -> [UnsignedVPTokenV2] {

        guard let mdoc = unsignedToken as? UnsignedMdocVPToken else { fatalError() }

        return try mdoc.docTypeToDeviceAuthenticationBytes.map { (docType, bytes) in
            guard let mapping = mappings.first(where: { $0.identifier == docType }) else {
                throw InvalidData(message: "No mapping for docType \(docType)", className: "OpenID4VPUtils")
            }

            let (keyRef, alg) = try resolveMdocKeyAndAlg(mapping.credential.value as! String)

            return UnsignedVPTokenV2(
                format: .mso_mdoc,
                holderKeyReference: keyRef,
                signatureAlgorithm: alg,
                dataToSign: bytes
            )
        }
    }






    private  func reconstructMdocV2(
        _ unsignedToken: UnsignedVPToken,
        _ mappings: [CredentialInputDescriptorMapping],
        _ iterator: inout IndexingIterator<[VPTokenSigningResultV2]>
    ) throws -> VPTokenSigningResult {

        guard let mdoc = unsignedToken as? UnsignedMdocVPToken else { fatalError() }

        var map: [String: DeviceAuthentication] = [:]

        for (docType, _) in mdoc.docTypeToDeviceAuthenticationBytes {
            guard let signed = iterator.next() else {
                throw InvalidData(message: "Missing mdoc signature for \(docType)", className: "OpenID4VPUtils")
            }

            let mapping = mappings.first(where: { $0.identifier == docType })!
            let (_, alg) = try resolveMdocKeyAndAlg(mapping.credential.value as! String)

            map[docType] = DeviceAuthentication(signature: signed.signedData, algorithm: alg)
        }

        return MdocVPTokenSigningResult(docTypeToDeviceAuthentication: map)
    }

    // MARK: - SD-JWT

    private func flattenSdJwtV2(
        _ unsignedToken: UnsignedVPToken,
        _ mappings: [CredentialInputDescriptorMapping],
        _ format: FormatType
    ) async throws -> [UnsignedVPTokenV2] {

        guard let sdjwt = unsignedToken as? UnsignedSdJwtVPToken else { fatalError() }

        let uuidMap = Dictionary(uniqueKeysWithValues: mappings.compactMap { ($0.identifier, $0) })

        var results: [UnsignedVPTokenV2] = []
        results.reserveCapacity(sdjwt.uuidToUnsignedKBT.count)

        for (uuid, kb) in sdjwt.uuidToUnsignedKBT {
            guard let mapping = uuidMap[uuid] else {
                throw InvalidData(message: "No SD-JWT mapping for uuid \(uuid)", className: "OpenID4VPUtils")
            }

            let (kid, alg) = try await resolveSdJwtKeyAndAlg(mapping.credential.value as! String)

            results.append(
                UnsignedVPTokenV2(
                    format: format,
                    holderKeyReference: kid,
                    signatureAlgorithm: alg,
                    dataToSign: kb
                )
            )
        }

        return results
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

    // 🔐 Resolve DID public key
    let resolver = DidPublicKeyResolver()
    let publicKey = try await resolver.resolve(
        uri: kid.trimmingCharacters(in: CharacterSet(charactersIn: "=")),
        keyId: nil
    )

    // 🎯 Algorithm mapping — THIS is the correct parity with Kotlin
    let alg: String

    switch publicKey {
    case .ed25519:
        alg = "EdDSA"

    case .secKey:
        alg = "ES256"

    default:
        throw InvalidData(
            message: "Unsupported key type \(publicKey)",
            className: "OpenID4VPUtils"
        )
    }

    return (kid, alg)
}




    private  func reconstructSdJwtV2(
        _ unsignedToken: UnsignedVPToken,
        _ iterator: inout IndexingIterator<[VPTokenSigningResultV2]>
    ) throws -> VPTokenSigningResult {

        guard let sd = unsignedToken as? UnsignedSdJwtVPToken else { fatalError() }

        var map: [String: String] = [:]

        for (uuid, _) in sd.uuidToUnsignedKBT {
            guard let signed = iterator.next() else {
                throw InvalidData(message: "Missing SD-JWT signature for \(uuid)", className: "OpenID4VPUtils")
            }
            map[uuid] = signed.signedData
        }

        return SdJwtVpTokenSigningResult(uuidToKbJWTSignature: map)
    }





