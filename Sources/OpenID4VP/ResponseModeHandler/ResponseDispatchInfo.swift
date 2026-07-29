import Foundation
import JSONWebKey

/**
 * Data class that holds information required for dispatching responses to the verifier.
 */
struct ResponseDispatchInfo {
    public let responseMode: String
    public var nonce: String?
    public var walletNonce: String?
    public let state: String?
    public let clientId: String
    public let responseUrl: String
    public var responseEncryptionSpecification: ResponseEncryptionSpecification?
}

/**
 * Specification for encrypting authorization responses.
 *
 * @property keyEncryptionAlg The algorithm used for key encryption (e.g., "ECDH-ES")
 * @property contentEncryptionAlg The algorithm used for content encryption (e.g., "A256GCM")
 * @property verifierPublicKey The verifier's public key (JWK) used for encryption
 */
struct ResponseEncryptionSpecification {
    public let keyEncryptionAlg: EncryptionAlgorithm
    public let contentEncryptionAlg: EncryptionMethod
    public let verifierPublicKey: JWK
}
