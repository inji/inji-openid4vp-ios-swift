import Foundation

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

func validateField(_ value: String, fieldName: String) throws {
    guard !value.isEmpty else {
        throw Logger.handleException(
            exceptionType: "InvalidJwksInput",
            fieldPath: ["jwks", fieldName],
            className: JWK.className
        )
    }
}
