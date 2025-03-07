import Foundation
import CryptoKit

public struct JWEProcessor {
    let clientMetadata: ClientMetadata
    static let className = String(describing: JWEProcessor.self)
    
    func createResponse(bodyParams: [String:Any]) throws -> String {
        
        var payloadData: Data
        do {
            payloadData = try getPayloadData(bodyParams)
        } catch {
            throw Logger.handleException(exceptionType: "PayloadConversionFailed", className: JWEProcessor.className)
        }
        
        let encryption = try EncryptionProvider.getEncryption(clientMetadata.authorization_encrypted_response_enc!)
        
        let jwk = try getJwk(clientMetadata.jwks!, clientMetadata.authorization_encrypted_response_alg!)
        
        let keyAgreement = try KeyAgreementFactory.createKeyAgreement(for: jwk)
        
        let sharedKey = try keyAgreement.deriveKey(publicKey: jwk.x)
        
        let (ciphertext, nonce, tag) = try encryption.encrypt(payloadData, with: sharedKey)
        
        var header = keyAgreement.getJWEHeader(alg: jwk.alg, enc: clientMetadata.authorization_encrypted_response_enc!, jwk: jwk)
        
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
    
    func getJwk(_ jwks: JWKS, _ alg: String) throws -> JWK {
        return jwks.keys.first(where: { $0.alg == alg })!
    }
}
