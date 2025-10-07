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
        let data = try response.body.data(using: .utf8) ?? {
           throw InvalidData(
                message: "unable to convert the jwks response to data",
                className: className,
                code: OpenID4VPErrorCodes.invalidRequestObject
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
