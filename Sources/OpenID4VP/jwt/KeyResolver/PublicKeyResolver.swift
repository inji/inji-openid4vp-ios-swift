import Foundation
import CryptoKit

protocol PublicKeyResolver {
    // TODO: should return publicKey instead of String once multiple signature support is added
    func resolveKey(header: [String: Any])async throws -> PublicKeyType
}

enum PublicKeyType {
    case secKey(SecKey)                        // For EC keys (P-256, etc.)
    case ed25519(Curve25519.Signing.PublicKey) // For Ed25519
}
