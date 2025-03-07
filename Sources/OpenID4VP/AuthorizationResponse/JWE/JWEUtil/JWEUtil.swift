import Foundation

func getPayloadData(_ bodyParams: [String: Any]) throws -> Data {
    var processedParams: [String: Any] = [:]

    for (key, value) in bodyParams {
        if let encodableValue = value as? Encodable {
            if let converted = encodableValue.toDictionary() {
                processedParams[key] = converted
            } else {
                processedParams[key] = value
            }
        } else {
            processedParams[key] = value
        }
    }
    return try JSONSerialization.data(withJSONObject: processedParams, options: [])
}


func encodeJWEComponents(
        header: [String: Any],
        encryptedKey: String,
        nonce: Data,
        ciphertext: Data,
        tag: Data
    ) throws -> String {
      
        let headerJson = try JSONSerialization.data(withJSONObject: header)
        let encodedHeader = base64URLEscaped(headerJson.base64EncodedString())
        let encodedEncryptedKey = encryptedKey
        let encodedIV = base64URLEscaped(nonce.base64EncodedString())
        let encodedCiphertext = base64URLEscaped(ciphertext.base64EncodedString())
        let encodedAuthTag = base64URLEscaped(tag.base64EncodedString())
        
        return [
            encodedHeader,
            encodedEncryptedKey,
            encodedIV,
            encodedCiphertext,
            encodedAuthTag
        ].joined(separator: ".")
    }
