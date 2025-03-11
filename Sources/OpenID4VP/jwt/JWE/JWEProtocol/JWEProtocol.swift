import Foundation
import CryptoKit

protocol JWEKeyAgreement {
    func deriveKey(publicKey: String) throws -> SymmetricKey
    func getEphemeralPublicKey() -> [String: Any]?
    func getJWEHeader(alg: String, enc: String, jwk: JWK) -> [String: Any]
    func getEncyptionKey() -> String
}

protocol JWEEncryption {
    func encrypt(_ data: Data, with key: SymmetricKey) throws -> (ciphertext: Data, nonce: Data, tag: Data)
}
