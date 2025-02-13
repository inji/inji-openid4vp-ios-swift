import Foundation
import CryptoKit

protocol JWEAlgorithm {
    func deriveKey(publicKey: Data) throws -> SymmetricKey
    func getEphemeralPublicKey() -> [String: Any]?
    func getEncryptedKey() -> String
    func getJWEHeader(config: JWEEncryptionConfig, jwk: JWK) -> [String: Any]
}

protocol JWEEncryption {
    func encrypt(_ data: Data, with key: SymmetricKey) throws -> (ciphertext: Data, nonce: Data, tag: Data)
}