import Foundation
import JSONWebKey
import CryptoKit
import SwiftCBOR

enum JWSAlgorithm {
    static let eddsa = "EdDSA"
    static let rs256 = "RS256"
    static let es256 = "ES256"
    static let es384 = "ES384"
    static let es256k = "ES256K"
}
