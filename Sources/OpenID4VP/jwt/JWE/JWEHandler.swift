import Foundation
import CryptoKit

public struct JWEHandler {
    let contentEncryptionAlgorithm: String
    let keyEncryptionAlgorithm: String
    let publicKey: JWK
    static let className = String(describing: JWEHandler.self)

    init(keyEncryptionAlgorithm: String, contentEncryptionAlgorithm: String, publicKey: JWK) {
        self.keyEncryptionAlgorithm = keyEncryptionAlgorithm
        self.contentEncryptionAlgorithm = contentEncryptionAlgorithm
        self.publicKey = publicKey
    }

    func createResponse(bodyParams: [String:Any]) throws -> String {

        var payloadData: Data
        do {
            payloadData = try getPayloadData(bodyParams)
        } catch {
            throw Logger.handleException(exceptionType: "PayloadConversionFailed", className: JWEHandler.className)
        }

        let encryption = try EncryptionProvider.getEncryption(contentEncryptionAlgorithm)

        let keyAgreement = try KeyAgreementFactory.createKeyAgreement(for: publicKey)

        let sharedKey = try keyAgreement.deriveKey(publicKey: publicKey.x)

        let (ciphertext, nonce, tag) = try encryption.encrypt(payloadData, with: sharedKey)

        var header = keyAgreement.getJWEHeader(alg: publicKey.alg, enc: contentEncryptionAlgorithm, jwk: publicKey)

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

}
