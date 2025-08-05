import Foundation
import CryptoKit

enum PublicKeyType {
    case secKey(SecKey)
    case ed25519(Curve25519.Signing.PublicKey)
}
