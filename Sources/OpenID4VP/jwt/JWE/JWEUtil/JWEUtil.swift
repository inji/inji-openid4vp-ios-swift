import Foundation

func toData(_ bodyParams: [String: Any]) throws -> Data {
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
        let encodedHeader = headerJson.toBase64UrlEncoded()
        let encodedEncryptedKey = encryptedKey
        let encodedIV = nonce.toBase64UrlEncoded()
        let encodedCiphertext = ciphertext.toBase64UrlEncoded()
        let encodedAuthTag = tag.toBase64UrlEncoded()
        
        return [
            encodedHeader,
            encodedEncryptedKey,
            encodedIV,
            encodedCiphertext,
            encodedAuthTag
        ].joined(separator: ".")
    }
