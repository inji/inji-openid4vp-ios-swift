import Foundation
import CryptoKit

public struct JWEHandler {
    let contentEncryptionAlgorithm: String
    let keyEncryptionAlgorithm: String
    let publicKey: JWK
    let producerInfo: String
    let recipientInfo: String
    
    static let className = String(describing: JWEHandler.self)

    func generateEncryptedResponse(payload: [String:Any]) throws -> String {
        var payloadData: Data
        do {
            payloadData = try toData(payload)
        } catch {
            throw Logger.handleException(exceptionType: "PayloadConversionFailed", className: JWEHandler.className)
        }

        //TODO: Perform key agreement based on keyEncryptionAlgorithm
        let encrypter = try EncryptionProvider.getEncrypter(contentEncryptionAlgorithm)
        let keyAgreement = try KeyAgreementFactory.createKeyAgreement(for: publicKey)
        let sharedKey = try keyAgreement.deriveKey(publicKey: publicKey.x)

        let (ciphertext, nonce, tag) = try encrypter.encrypt(payloadData, with: sharedKey)

        var header = keyAgreement.getJWEHeader(alg: publicKey.alg, enc: contentEncryptionAlgorithm, jwk: publicKey, producerInfo: producerInfo, recipientInfo: recipientInfo)
        if let epk = keyAgreement.getEphemeralPublicKey() {
            header["epk"] = epk
        }

        return try encodeJWEComponents(
            header: header,
            encryptedKey: keyAgreement.getEncyptionKey(),
            nonce: nonce,
            ciphertext: ciphertext,
            tag: tag
        )
    }

    private func encodeJWEComponents(
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
}
