import Foundation
import CryptoKit

protocol PublicKeyResolver {
    func resolveKey(header: [String: Any])async throws -> PublicKeyType
}


